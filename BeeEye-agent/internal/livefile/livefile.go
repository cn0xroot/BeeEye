// Package livefile replays a capture file — classic pcap or pcapng, both
// auto-detected by pcapfile.Open — as a live.Source — the same interface a
// real capture uses, so the analyzer's existing pipeline (dissect, ring
// buffer, filter, subscribers) needs no separate code path for "reading a
// file" versus "capturing a NIC". Opening a file and starting a live capture
// end up going through the exact same Session.startWith.
//
// Replay runs as fast as the reader can go, not paced to the original
// capture's timestamps: someone opening a file to look at it wants to see it
// now, not wait out however long the original capture took.
package livefile

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"BeeEye/internal/live"
	"BeeEye/internal/pcapfile"
)

// Open wraps r (already positioned at the start of a capture file — classic
// pcap or pcapng, whichever it turns out to be) as a live.Source, named for
// the UI's benefit — typically the uploaded filename, since that is the
// only "interface name" a replayed file has. Ownership of r passes to the
// returned Source: it is closed when replay finishes or Close is called,
// whichever comes first.
func Open(r io.ReadCloser, name string) (live.Source, error) {
	pr, err := pcapfile.Open(r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("livefile: %w", err)
	}
	s := &source{
		name:    name,
		packets: make(chan live.Packet, 256),
		done:    make(chan struct{}),
	}
	go s.run(pr, r)
	return s, nil
}

type source struct {
	name    string
	packets chan live.Packet
	done    chan struct{}
	once    sync.Once

	captured atomic.Int64
	bytes    atomic.Int64
}

func (s *source) run(pr pcapfile.PacketReader, r io.Closer) {
	defer close(s.packets)
	defer r.Close()
	for {
		pk, err := pr.Next()
		if err != nil {
			// io.EOF is the ordinary end of the file; anything else (a
			// truncated record, a bad file) also just stops replay here —
			// whatever was read before the error is still in the ring
			// buffer and still analyzable, which is the more useful
			// failure mode for a person looking at a possibly-imperfect
			// capture someone handed them.
			return
		}
		s.captured.Add(1)
		s.bytes.Add(int64(pk.OrigLen))
		select {
		case s.packets <- live.Packet{
			Index:    pk.Index,
			TS:       pk.TS,
			Iface:    s.name,
			Data:     pk.Data,
			LinkType: pk.LinkType,
			CapLen:   pk.CapLen,
			OrigLen:  pk.OrigLen,
		}:
		case <-s.done:
			return
		}
	}
}

func (s *source) Name() string                { return "pcap-file" }
func (s *source) Iface() string               { return s.name }
func (s *source) Packets() <-chan live.Packet { return s.packets }

func (s *source) Stats() live.Stats {
	return live.Stats{Captured: s.captured.Load(), Bytes: s.bytes.Load()}
}

// Close stops replay early — the reader has nothing left to read, but this
// still unblocks run() if it is mid-send on a full channel with nobody
// draining it (the session was closed out from under an open file).
func (s *source) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}
