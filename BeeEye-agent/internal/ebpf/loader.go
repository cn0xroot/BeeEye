//go:build linux

package ebpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// bpfObject is the CO-RE object built from bpf/BeeEye.bpf.c. The Makefile
// compiles it into this package directory so `go build` alone is enough once
// `make bpf` has run; see Makefile target `bpf`.
//
//go:embed BeeEye.bpf.o
var bpfObject []byte

// cfg map slot indices — must match enum BeeEye_cfg_slot in BeeEye_events.h.
const (
	cfgFlowIntervalNS      uint32 = 0
	cfgSensitiveIntervalNS uint32 = 1
	cfgRawFrameMode        uint32 = 2
)

// Loader owns the loaded kernel program, its maps and every TCX attachment.
type Loader struct {
	coll  *ebpf.Collection
	rd    *ringbuf.Reader
	mu    sync.Mutex
	links []link.Link
	ifs   map[int]string // ifindex → interface name (F17)
}

// ErrNotSupported reports a kernel that cannot host the program. Callers are
// expected to degrade to another capture source rather than abort (§3.4).
var ErrNotSupported = errors.New("ebpf: kernel does not support the BeeEye program (needs ≥5.8 with BTF; TCX attach needs ≥6.6)")

// Load verifies and loads the program into the kernel. Nothing is attached to
// any interface yet — call AttachInterface for each configured NIC (§3.4.5).
func Load() (*Loader, error) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("%w: /sys/kernel/btf/vmlinux missing, CO-RE unavailable", ErrNotSupported)
	}
	// Older kernels charge BPF memory against RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("ebpf: parse object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// The verifier log is the only useful diagnostic here, so keep
			// it rather than collapsing it into a one-line message.
			return nil, fmt.Errorf("ebpf: verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("ebpf: load collection: %w", err)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("ebpf: open ringbuf: %w", err)
	}
	return &Loader{coll: coll, rd: rd, ifs: map[int]string{}}, nil
}

// AttachInterface attaches the same bytecode to both directions of one NIC.
// A missing or un-attachable interface is reported to the caller but never
// fatal: per §3.4.5 the agent logs and skips so the other NICs keep capturing.
func (l *Loader) AttachInterface(name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", name, err)
	}
	attachments := []struct {
		prog   string
		attach ebpf.AttachType
	}{
		{"BeeEye_tc_ingress", ebpf.AttachTCXIngress},
		{"BeeEye_tc_egress", ebpf.AttachTCXEgress},
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	added := 0
	for _, a := range attachments {
		prog := l.coll.Programs[a.prog]
		if prog == nil {
			return fmt.Errorf("program %q missing from object", a.prog)
		}
		lk, err := link.AttachTCX(link.TCXOptions{
			Program:   prog,
			Attach:    a.attach,
			Interface: iface.Index,
		})
		if err != nil {
			// Roll back the direction that did succeed, so an interface is
			// never left half-instrumented (that would under-count one way).
			for i := 0; i < added; i++ {
				l.links[len(l.links)-1].Close()
				l.links = l.links[:len(l.links)-1]
			}
			return fmt.Errorf("attach %s to %s: %w", a.prog, name, err)
		}
		l.links = append(l.links, lk)
		added++
	}
	l.ifs[iface.Index] = name
	return nil
}

// IfaceName resolves an event's ifindex back to the configured name (F17).
func (l *Loader) IfaceName(ifindex uint32) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n, ok := l.ifs[int(ifindex)]; ok {
		return n
	}
	return fmt.Sprintf("if%d", ifindex)
}

// SetIntervals pushes the reporting cadence from config.yaml into the kernel
// (§3.4.4). Nothing tunable is compiled into the bytecode.
func (l *Loader) SetIntervals(ordinary, sensitive time.Duration) error {
	m := l.coll.Maps["cfg"]
	if m == nil {
		return errors.New("ebpf: cfg map missing")
	}
	for slot, d := range map[uint32]time.Duration{
		cfgFlowIntervalNS:      ordinary,
		cfgSensitiveIntervalNS: sensitive,
	} {
		v := uint64(d.Nanoseconds())
		if err := m.Update(slot, v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("ebpf: set cfg slot %d: %w", slot, err)
		}
	}
	return nil
}

// SetRawFrameMode switches the program between its two reporting styles:
// off (default) is the selective, in-kernel-tiered reporting described at
// the top of BeeEye.bpf.c; on makes every packet emit EVT_RAW_FRAME, a
// whole-frame mirror, so the ring buffer can act as a live.Source (see
// source.go) on par with AF_PACKET instead of feeding the aggregation this
// package's other methods are for. The two modes are not meant to run
// together — raw-frame mode bypasses device_stats/flow tracking entirely.
func (l *Loader) SetRawFrameMode(enabled bool) error {
	m := l.coll.Maps["cfg"]
	if m == nil {
		return errors.New("ebpf: cfg map missing")
	}
	var v uint64
	if enabled {
		v = 1
	}
	if err := m.Update(cfgRawFrameMode, v, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("ebpf: set raw frame mode: %w", err)
	}
	return nil
}

// deviceKey mirrors `struct device_key` (6-byte MAC + 2 bytes of padding).
type deviceKey struct {
	MAC [6]byte
	_   [2]byte
}

// deviceStat mirrors `struct device_stat`.
type deviceStat struct {
	TxBytes   uint64
	RxBytes   uint64
	ConnCount uint64
	LastSeen  uint64
	Category  uint8
	_         [7]byte
}

// SetCategory writes a fingerprinting result back into the kernel so tiered
// monitoring is decided in-kernel rather than in userspace (§3.5.2 step 4).
func (l *Loader) SetCategory(mac net.HardwareAddr, category uint8) error {
	if len(mac) != 6 {
		return fmt.Errorf("ebpf: expected a 6-byte MAC, got %d bytes", len(mac))
	}
	m := l.coll.Maps["device_stats"]
	if m == nil {
		return errors.New("ebpf: device_stats map missing")
	}
	var k deviceKey
	copy(k.MAC[:], mac)

	var st deviceStat
	if err := m.Lookup(k, &st); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("ebpf: lookup device: %w", err)
		}
		// The device has not been seen on the wire yet; pre-seed the tier so
		// its very first packet is already classified correctly.
	}
	st.Category = category
	return m.Update(k, st, ebpf.UpdateAny)
}

// DeviceCounters snapshots the per-MAC byte counters the kernel maintains.
func (l *Loader) DeviceCounters() (map[string]deviceStat, error) {
	m := l.coll.Maps["device_stats"]
	if m == nil {
		return nil, errors.New("ebpf: device_stats map missing")
	}
	out := map[string]deviceStat{}
	var k deviceKey
	var v deviceStat
	it := m.Iterate()
	for it.Next(&k, &v) {
		out[net.HardwareAddr(k.MAC[:]).String()] = v
	}
	return out, it.Err()
}

// Events streams decoded ringbuf records until the loader is closed. The
// channel is closed when the reader stops, so callers can range over it.
//
// The buffer is generous (8192, not the smaller size an earlier version
// used) because raw-frame mode (EVT_RAW_FRAME, SetRawFrameMode) turns this
// into a mirror of every packet on the interface rather than the selective
// handful of kinds the rest of this package emits — a burst of ordinary
// traffic can legitimately produce thousands of events in a fraction of a
// second, and this channel being the bottleneck would silently drop frames
// a consumer never even got a chance to see.
func (l *Loader) Events() <-chan *Event {
	ch := make(chan *Event, 8192)
	go func() {
		defer close(ch)
		for {
			rec, err := l.rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("ebpf: ringbuf read: %v", err)
				continue
			}
			ev, err := ParseEvent(rec.RawSample)
			if err != nil {
				log.Printf("ebpf: %v", err)
				continue
			}
			select {
			case ch <- ev:
			default:
				// Userspace is behind. Dropping here is the right trade:
				// blocking would back-pressure the ringbuf and start losing
				// kernel-side samples instead, which we cannot account for.
			}
		}
	}()
	return ch
}

// Close detaches every program and releases the maps.
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var firstErr error
	if l.rd != nil {
		if err := l.rd.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, lk := range l.links {
		if err := lk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.links = nil
	if l.coll != nil {
		l.coll.Close()
	}
	return firstErr
}
