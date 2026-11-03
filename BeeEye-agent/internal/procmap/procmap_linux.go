//go:build linux

package procmap

import (
	"io/fs"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

func ownerUID(fi fs.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(uint64(st.Uid), 10)
	}
	return ""
}

// netInterfaceAddrs returns every address configured on this host.
func netInterfaceAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v, ok := netip.AddrFromSlice(ipnet.IP); ok {
				out = append(out, v.Unmap())
			}
		}
	}
	return out, nil
}

// platformSockets reads /proc/net/{tcp,tcp6,udp,udp6}.
func platformSockets() map[socketKey]uint64 {
	out := map[socketKey]uint64{}
	for _, f := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		parseProcNet(f.path, f.proto, out)
	}
	return out
}

// platformOwners maps socket inode → owning process via /proc/<pid>/fd.
func platformOwners(force bool) map[uint64]Process { return scanProcFDs() }
