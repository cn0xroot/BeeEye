// Package procmap attributes a flow to the local process that owns it.
//
// SCOPE — this is the important part:
//
// This only works for traffic whose local endpoint is a socket on THIS host.
// A packet from a camera, a door lock or a phone carries no process identity;
// nothing in an Ethernet frame says which program on the far device sent it,
// and no amount of gateway-side analysis can recover that. For those flows the
// strongest identity available is the device itself (MAC → asset record) plus
// what the protocol reveals — which is what the rest of BeeEye is for.
//
// So Lookup returns ok=false for anything not local, and the UI shows that
// honestly rather than guessing.
//
// Mechanism: /proc/net/{tcp,tcp6,udp,udp6} maps a local address:port to a
// socket inode; /proc/<pid>/fd/* maps an inode back to a process. This is what
// `ss -p` and `lsof -i` do.
//
// Known limitation: a short-lived connection can be gone from /proc before it
// is looked up, so attribution is best-effort for connections that live
// milliseconds. A race-free version would record PID at socket creation from an
// eBPF hook on inet_sock_set_state / udp_sendmsg; that is the natural upgrade
// path and would slot in behind this same interface.
package procmap

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Process identifies the owner of a local socket.
type Process struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe,omitempty"`
	User string `json:"user,omitempty"`
}

type socketKey struct {
	proto string // "tcp" | "udp"
	addr  netip.AddrPort
}

// Resolver caches the two scans that make attribution work.
type Resolver struct {
	mu sync.Mutex

	ttl time.Duration

	sockets   map[socketKey]uint64 // local addr:port → inode
	socketsAt time.Time

	inodes   map[uint64]Process // inode → owning process
	inodesAt time.Time

	localAddrs   map[netip.Addr]bool
	localAddrsAt time.Time
}

// New returns a resolver. ttl bounds how stale an answer may be; the scans are
// not free (the inode scan walks every fd of every process), so re-running them
// per packet would be far more expensive than the analysis itself.
func New(ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 2 * time.Second
	}
	return &Resolver{ttl: ttl}
}

// IsLocal reports whether addr belongs to an interface on this host.
func (r *Resolver) IsLocal(addr netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshLocalAddrs()
	return r.localAddrs[addr.Unmap()] || addr.IsLoopback()
}

// Lookup resolves the process owning a local socket. proto is "tcp" or "udp".
//
// ok is false when the socket is not local to this host — which is the normal
// case for gateway traffic, and is a fact about the data, not a failure.
func (r *Resolver) Lookup(proto string, local netip.AddrPort) (Process, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refreshSockets()
	inode, ok := r.sockets[socketKey{proto, normalize(local)}]
	if !ok {
		// A listening socket is recorded against the wildcard address, so a
		// flow to a specific local IP still resolves.
		wildcard := netip.AddrPortFrom(netip.IPv6Unspecified(), local.Port())
		inode, ok = r.sockets[socketKey{proto, wildcard}]
		if !ok {
			return Process{}, false
		}
	}

	r.refreshInodes()
	p, ok := r.inodes[inode]
	return p, ok
}

// LookupFlow picks whichever end of a flow is local and resolves it. It returns
// the process plus which side matched, so the UI can say "this host's curl was
// the client" rather than just naming a process.
func (r *Resolver) LookupFlow(proto string, src, dst netip.AddrPort) (p Process, side string, ok bool) {
	if r.IsLocal(src.Addr()) {
		if p, ok = r.Lookup(proto, src); ok {
			return p, "source", true
		}
	}
	if r.IsLocal(dst.Addr()) {
		if p, ok = r.Lookup(proto, dst); ok {
			return p, "destination", true
		}
	}
	return Process{}, "", false
}

// ---------------------------------------------------------------- refreshers

func (r *Resolver) refreshLocalAddrs() {
	if time.Since(r.localAddrsAt) < 10*time.Second && r.localAddrs != nil {
		return
	}
	addrs := map[netip.Addr]bool{}
	if ifaces, err := netInterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			addrs[a.Unmap()] = true
		}
	}
	r.localAddrs = addrs
	r.localAddrsAt = time.Now()
}

func (r *Resolver) refreshSockets() {
	if time.Since(r.socketsAt) < r.ttl && r.sockets != nil {
		return
	}
	out := map[socketKey]uint64{}
	for _, f := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		parseProcNet(f.path, f.proto, out)
	}
	r.sockets = out
	r.socketsAt = time.Now()
}

func (r *Resolver) refreshInodes() {
	if time.Since(r.inodesAt) < r.ttl && r.inodes != nil {
		return
	}
	r.inodes = scanProcFDs()
	r.inodesAt = time.Now()
}

// ------------------------------------------------------------------ parsing

// parseProcNet reads one /proc/net table into out.
//
// Line shape (whitespace-separated):
//
//	sl  local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
//	0: 0100007F:0035 00000000:0000 0A ...  1000  0  12345
func parseProcNet(path, proto string, out map[socketKey]uint64) {
	f, err := os.Open(path)
	if err != nil {
		return // tcp6/udp6 are absent on an IPv6-less kernel; not an error
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		ap, err := parseHexAddrPort(fields[1])
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		out[socketKey{proto, normalize(ap)}] = inode
	}
}

// parseHexAddrPort decodes the "0100007F:0035" form.
//
// The address is host-byte-order words rendered as hex, which on a
// little-endian machine means "0100007F" is 127.0.0.1 — reading it as
// big-endian gives 1.0.0.127, a wrong answer that looks plausible.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	host, portStr, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("procmap: malformed address %q", s)
	}
	port, err := strconv.ParseUint(portStr, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.AddrPort{}, err
	}

	switch len(raw) {
	case 4:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], binary.BigEndian.Uint32(raw))
		return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(port)), nil
	case 16:
		// IPv6 is four 32-bit words, each byte-swapped independently.
		var b [16]byte
		for i := 0; i < 4; i++ {
			w := binary.BigEndian.Uint32(raw[i*4 : i*4+4])
			binary.LittleEndian.PutUint32(b[i*4:i*4+4], w)
		}
		return netip.AddrPortFrom(netip.AddrFrom16(b), uint16(port)), nil
	}
	return netip.AddrPort{}, fmt.Errorf("procmap: unexpected address width %d", len(raw))
}

// normalize maps IPv4 and its v6-mapped form onto one key, so a dual-stack
// socket found in /proc/net/tcp6 still matches an IPv4 packet.
func normalize(ap netip.AddrPort) netip.AddrPort {
	a := ap.Addr().Unmap()
	if a.Is4() {
		return netip.AddrPortFrom(a, ap.Port())
	}
	return netip.AddrPortFrom(a, ap.Port())
}

// scanProcFDs builds inode → process by walking every process's descriptors.
func scanProcFDs() map[uint64]Process {
	out := map[uint64]Process{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	userCache := map[string]string{}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // the process exited, or we lack permission — both normal
		}

		var proc *Process
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(link[8:], "]"), 10, 64)
			if err != nil {
				continue
			}
			if proc == nil {
				proc = describeProcess(pid, e.Name(), userCache)
			}
			out[inode] = *proc
		}
	}
	return out
}

func describeProcess(pid int, pidStr string, userCache map[string]string) *Process {
	p := &Process{PID: pid}
	if b, err := os.ReadFile(filepath.Join("/proc", pidStr, "comm")); err == nil {
		p.Comm = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(filepath.Join("/proc", pidStr, "exe")); err == nil {
		p.Exe = exe
	}
	if fi, err := os.Stat(filepath.Join("/proc", pidStr)); err == nil {
		if uid := ownerUID(fi); uid != "" {
			if name, ok := userCache[uid]; ok {
				p.User = name
			} else if u, err := user.LookupId(uid); err == nil {
				userCache[uid] = u.Username
				p.User = u.Username
			} else {
				userCache[uid] = uid
				p.User = uid
			}
		}
	}
	return p
}
