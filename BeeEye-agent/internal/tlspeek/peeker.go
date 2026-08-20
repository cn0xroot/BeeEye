//go:build linux

package tlspeek

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// bpfObject is built from bpf/BeeEye_tls.bpf.c by `make bpf`, which copies it
// into this package so `go build` alone works afterwards.
//
//go:embed BeeEye_tls.bpf.o
var bpfObject []byte

// ErrNotSupported reports a kernel that cannot host the uprobes. Callers
// degrade — plaintext capture is an extra, never a precondition for running.
var ErrNotSupported = errors.New("tlspeek: kernel cannot host the TLS uprobes (needs ≥5.8 with BTF)")

// Peeker owns the loaded programs, the ring buffer and every attachment.
type Peeker struct {
	coll *ebpf.Collection
	rd   *ringbuf.Reader

	mu       sync.Mutex
	links    []link.Link
	attached map[string]bool // path|pid, so the same target is not probed twice
	closed   bool
}

// Load verifies and loads the programs. Nothing is attached yet: attaching is
// always an explicit, named act, because it is what starts reading content.
func Load() (*Peeker, error) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("%w: /sys/kernel/btf/vmlinux missing", ErrNotSupported)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("tlspeek: remove memlock: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("tlspeek: parse object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("tlspeek: verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("tlspeek: load collection: %w", err)
	}
	rd, err := ringbuf.NewReader(coll.Maps["tls_events"])
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("tlspeek: open ringbuf: %w", err)
	}
	return &Peeker{coll: coll, rd: rd, attached: map[string]bool{}}, nil
}

// Attach probes one library. pid > 0 restricts capture to that process; pid 0
// probes every process using the library, which is a much bigger decision and
// so has to be spelled out by the caller rather than being the default.
func (p *Peeker) Attach(libPath string, pid int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("tlspeek: peeker is closed")
	}
	key := fmt.Sprintf("%s|%d", libPath, pid)
	if p.attached[key] {
		return nil
	}

	// Which library family this is decides which symbols to hook — the rule
	// table is the single place that knowledge lives (rules.go), so a new
	// library is supported by adding a rule, not by editing this function.
	rule := matchRule(libPath)
	if rule == nil {
		return fmt.Errorf("tlspeek: no decryption rule matches %s", libPath)
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("tlspeek: open %s: %w", libPath, err)
	}
	var opts *link.UprobeOptions
	if pid > 0 {
		opts = &link.UprobeOptions{PID: pid}
	}

	// Attach all three or none: a half-attached target would report writes
	// with no matching reads, which reads as "the server said nothing".
	var added []link.Link
	fail := func(what string, err error) error {
		for _, l := range added {
			l.Close()
		}
		return fmt.Errorf("tlspeek: attach %s (%s) on %s: %w", what, rule.Name, libPath, err)
	}

	l, err := ex.Uprobe(rule.WriteSym, p.coll.Programs["BeeEye_uprobe_ssl_write"], opts)
	if err != nil {
		return fail(rule.WriteSym, err)
	}
	added = append(added, l)

	if l, err = ex.Uprobe(rule.ReadSym, p.coll.Programs["BeeEye_uprobe_ssl_read"], opts); err != nil {
		return fail(rule.ReadSym, err)
	}
	added = append(added, l)

	if l, err = ex.Uretprobe(rule.ReadSym, p.coll.Programs["BeeEye_uretprobe_ssl_read"], opts); err != nil {
		return fail(rule.ReadSym+" return", err)
	}
	added = append(added, l)

	p.links = append(p.links, added...)
	p.attached[key] = true
	return nil
}

// Targets reports what is currently probed, for the UI to show. Capturing
// content without being able to see what is being captured would be the wrong
// shape for this feature.
func (p *Peeker) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.attached))
	for k := range p.attached {
		out = append(out, k)
	}
	return out
}

// Events streams decoded chunks until the Peeker is closed.
func (p *Peeker) Events() <-chan *Event {
	ch := make(chan *Event, 256)
	go func() {
		defer close(ch)
		for {
			rec, err := p.rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("tlspeek: ringbuf read: %v", err)
				continue
			}
			ev, err := ParseEvent(rec.RawSample)
			if err != nil {
				log.Printf("tlspeek: %v", err)
				continue
			}
			select {
			case ch <- ev:
			default:
				// A slow consumer must not stall the ring and start
				// dropping in the kernel instead; losing the newest
				// chunk here is the cheaper failure.
			}
		}
	}()
	return ch
}

// Close detaches every probe and releases the programs.
func (p *Peeker) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	for _, l := range p.links {
		l.Close()
	}
	p.links = nil
	if p.rd != nil {
		p.rd.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
	return nil
}
