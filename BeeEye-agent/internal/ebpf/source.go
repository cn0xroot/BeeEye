//go:build linux

package ebpf

import (
	"sync"
	"sync/atomic"
	"time"

	"BeeEye/internal/live"
)

// rawFrameSource adapts the eBPF ring buffer into a live.Source, so callers
// that already speak AF_PACKET's Source interface (the analyzer's dissect
// loop, internal/livesource's pipeline) get an eBPF-backed capture for free.
// It consumes only KindRawFrame records — every other kind this package's
// Loader can emit exists for the selective, in-kernel-tiered reporting
// BeeEye.bpf.c documents at its top, a different purpose than feeding a
// packet-by-packet dissect pipeline.
type rawFrameSource struct {
	loader *Loader
	iface  string

	ch        chan live.Packet
	closeOnce sync.Once
	done      chan struct{}

	captured atomic.Int64
	bytes    atomic.Int64
	index    atomic.Int64
}

// OpenEBPF loads the CO-RE program, attaches it to iface in both directions,
// and switches it into raw-frame mode. The kernel/attach failure paths are
// exactly Load/AttachInterface's — callers are expected to fall back to
// AF_PACKET on any error, the same way live.Open falls back to the simulator
// (see internal/capsource, which is where that fallback chain lives).
func OpenEBPF(iface string) (live.Source, error) {
	l, err := Load()
	if err != nil {
		return nil, err
	}
	if err := l.AttachInterface(iface); err != nil {
		l.Close()
		return nil, err
	}
	if err := l.SetRawFrameMode(true); err != nil {
		l.Close()
		return nil, err
	}
	s := &rawFrameSource{
		loader: l,
		iface:  iface,
		ch:     make(chan live.Packet, 8192),
		done:   make(chan struct{}),
	}
	go s.run()
	return s, nil
}

func (s *rawFrameSource) run() {
	defer close(s.ch)
	for ev := range s.loader.Events() {
		if ev.Kind != KindRawFrame || len(ev.Payload) == 0 {
			continue // another event kind, or a truncated-to-nothing frame
		}
		idx := s.index.Add(1)
		s.captured.Add(1)
		s.bytes.Add(int64(len(ev.Payload)))
		pkt := live.Packet{
			Index: idx,
			// Wall-clock time, not ev.TS (a bpf_ktime_get_ns monotonic
			// reading with no fixed epoch) — the same choice AF_PACKET's
			// source makes, so both sources' packet timestamps are
			// directly comparable and neither needs a boot-time offset
			// computed to be meaningful.
			TS:      time.Now(),
			Iface:   s.loader.IfaceName(ev.IfIndex),
			Data:    ev.Payload,
			CapLen:  len(ev.Payload),
			OrigLen: int(ev.PktLen),
		}
		select {
		case s.ch <- pkt:
		case <-s.done:
			return
		}
	}
}

func (s *rawFrameSource) Name() string                { return "ebpf" }
func (s *rawFrameSource) Iface() string               { return s.iface }
func (s *rawFrameSource) Packets() <-chan live.Packet { return s.ch }

func (s *rawFrameSource) Stats() live.Stats {
	return live.Stats{Captured: s.captured.Load(), Bytes: s.bytes.Load()}
}

func (s *rawFrameSource) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		err = s.loader.Close()
	})
	return err
}
