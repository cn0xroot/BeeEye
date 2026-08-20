// Package gui implements the BeeEye live analyzer server (program.md §3.12).
//
// It is deliberately a second, independent process from the agent (F42): its
// own port, its own frontend bundle, and no database connection at all. Live
// analysis happens entirely in memory, so nothing the analyzer does can slow
// down the overview UI's queries — or vice versa.
package gui

import (
	"log"
	"sync"
	"time"

	"BeeEye/internal/dfilter"
	"BeeEye/internal/dissect"
	"BeeEye/internal/live"
	"BeeEye/internal/namemap"
	"BeeEye/internal/render"
)

// RenderChannels are the rows of the traffic colour field, in display order.
// They are fixed for the life of the process: a field whose rows silently
// change meaning is unreadable, so an unrecognised protocol falls into
// "other" rather than claiming a row of its own.
var RenderChannels = []string{"tls", "http", "dns", "mqtt", "arp", "icmp", "tcp", "other"}

// renderChannel maps a dissected packet onto one of RenderChannels.
func renderChannel(r *dissect.Result) string {
	for _, want := range []string{"tls", "http", "mqtt", "arp", "icmp"} {
		if r.HasProtocol(want) {
			return want
		}
	}
	if r.HasProtocol("dns") || r.HasProtocol("mdns") {
		return "dns"
	}
	if r.HasProtocol("tcp") {
		return "tcp"
	}
	return "other"
}

// DefaultRingSize caps how many dissected packets are retained. A live capture
// on a busy gateway is unbounded, so something has to give; keeping the most
// recent N and saying so is better than growing until the process is OOM-killed
// mid-investigation.
const DefaultRingSize = 20000

// Session is one running (or stopped) capture.
type Session struct {
	mu sync.RWMutex

	src         live.Source
	iface       string
	realCapture bool   // false when the simulator is standing in (F43)
	fallbackErr string // why the real capture was unavailable
	started     time.Time
	running     bool

	dis     *dissect.Dissector
	ring    []*dissect.Result // most recent packets, oldest first
	size    int
	dropped int64 // dissected packets evicted from the ring

	filter *dfilter.Expr

	subs   map[int]chan *dissect.Result
	nextID int

	hist     *render.History
	renderer render.Renderer
	rotStop  chan struct{}

	// Persistent capture: every frame is streamed to a pcap file so a packet's
	// bytes outlive the in-memory ring and its detail can be read back after
	// eviction (see pcapsink.go). Off until EnablePersistence is called.
	sink       *pcapSink
	captureDir string
	captureMax int64

	// names accumulates the IP ↔ domain association observed in this capture
	// (F21). It survives a filter change but is reset when a new capture
	// starts, because the associations belong to the traffic that taught them.
	names *namemap.Map
}

// NewSession returns an idle session.
func NewSession(ringSize int) *Session {
	if ringSize <= 0 {
		ringSize = DefaultRingSize
	}
	s := &Session{
		size:     ringSize,
		subs:     map[int]chan *dissect.Result{},
		dis:      dissect.New(),
		hist:     render.NewHistory(RenderChannels, render.DefaultWidth),
		names:    namemap.New(0),
		renderer: render.NewRenderer(),
		rotStop:  make(chan struct{}),
	}
	// One column per tick. At 80ms a 1024-wide field holds ~82s of history,
	// which is the span where a beacon's rhythm becomes visible to the eye.
	go func() {
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-s.rotStop:
				return
			case <-t.C:
				s.hist.Rotate()
			}
		}
	}()
	return s
}

// EnablePersistence turns on writing captured frames to pcap files under dir,
// capped at maxBytes per file (two files are kept). Call before Start. A dir of
// "" leaves persistence off and the analyzer behaves as ring-only.
func (s *Session) EnablePersistence(dir string, maxBytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captureDir = dir
	if maxBytes <= 0 {
		maxBytes = 512 << 20 // 512 MiB per file
	}
	s.captureMax = maxBytes
}

// CaptureFile reports the pcap file currently being written, or "" when
// persistence is off. Shown in the status so the operator knows where the saved
// traffic is.
func (s *Session) CaptureFile() string {
	s.mu.RLock()
	sink := s.sink
	s.mu.RUnlock()
	if sink == nil {
		return ""
	}
	return sink.Path()
}

// Names exposes the IP ↔ domain associations learned from this capture.
func (s *Session) Names() *namemap.Map {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.names
}

// Renderer exposes the active colour-field backend (cuda or cpu).
func (s *Session) Renderer() render.Renderer { return s.renderer }

// History exposes the intensity ring the renderer draws from.
func (s *Session) History() *render.History { return s.hist }

// Close stops the capture and releases renderer resources.
func (s *Session) Close() error {
	close(s.rotStop)
	err := s.Stop()
	if s.renderer != nil {
		s.renderer.Close()
	}
	return err
}

// StartOptions are the knobs the GUI's toolbar exposes.
type StartOptions struct {
	Iface   string `json:"iface"`
	Promisc bool   `json:"promisc"`
	SnapLen int    `json:"snaplen"`
	Filter  string `json:"filter"`
}

// Start opens a capture source and begins dissecting. Starting while already
// running restarts cleanly rather than stacking two readers on one interface.
func (s *Session) Start(opt StartOptions) error {
	if err := s.Stop(); err != nil {
		return err
	}

	expr, err := dfilter.Compile(opt.Filter)
	if err != nil {
		return err
	}

	// Deliberately live.Open, not capsource.Open: the analyzer stays on
	// AF_PACKET rather than competing for the same interface's eBPF TCX
	// hook the agent may already be using. On this host, verified with
	// bpftool prog show's run_cnt, only the *first* program attached to an
	// interface's TCX chain is ever actually invoked — a second attach
	// "succeeds" (no error) but never sees a packet. Since the agent is the
	// long-running process eBPF's lower overhead matters most for, it gets
	// first claim; the analyzer, started on demand, uses the capture path
	// that has always supported multiple independent readers on one NIC.
	src, real, openErr := live.Open(opt.Iface, opt.SnapLen, opt.Promisc)

	s.mu.Lock()
	s.src = src
	s.iface = opt.Iface
	s.realCapture = real
	s.fallbackErr = ""
	if !real && openErr != nil {
		s.fallbackErr = openErr.Error()
	}
	s.started = time.Now()
	s.running = true
	s.dis = dissect.New()
	s.ring = nil
	s.dropped = 0
	s.filter = expr
	s.names = namemap.New(0)
	if s.sink != nil {
		s.sink.Close()
		s.sink = nil
	}
	if s.captureDir != "" {
		snap := uint32(opt.SnapLen)
		if snap == 0 {
			snap = live.DefaultSnapLen
		}
		if sink, err := newPcapSink(s.captureDir, opt.Iface, snap, s.captureMax); err != nil {
			log.Printf("gui: packet persistence disabled: %v", err)
		} else {
			s.sink = sink
			log.Printf("gui: saving live capture to %s", sink.Path())
		}
	}
	packets := src.Packets()
	s.mu.Unlock()

	go s.consume(packets)
	return nil
}

// consume dissects every frame and fans it out to subscribers.
func (s *Session) consume(packets <-chan live.Packet) {
	names := s.Names()
	for p := range packets {
		// Dissecting is real work (field trees, string building) and s.dis is
		// only ever touched from this one goroutine, so it does not need the
		// session lock — doing it first keeps the critical section down to
		// the ring/filter/subs bookkeeping, which is what a packet-detail
		// request (Packet, an RLock) is actually contending with. Under fast
		// capture this lock is re-acquired every packet; every microsecond
		// held here is a microsecond a UI click waits behind it.
		res := s.dis.Packet(p)

		s.mu.Lock()
		s.ring = append(s.ring, res)
		if len(s.ring) > s.size {
			// Drop the oldest in one slice re-slice rather than shifting.
			over := len(s.ring) - s.size
			s.ring = s.ring[over:]
			s.dropped += int64(over)
		}
		matches := s.filter.Match(res)
		subs := make([]chan *dissect.Result, 0, len(s.subs))
		if matches {
			for _, ch := range s.subs {
				subs = append(subs, ch)
			}
		}
		s.mu.Unlock()

		// Feed the colour field and the name map from the one dissection we
		// already did. Both have their own locks, so this stays outside the
		// session's.
		s.hist.Add(renderChannel(res), float64(p.OrigLen))
		names.Learn(res)

		// Persist the raw frame so its detail survives ring eviction. The sink
		// has its own lock; keep this outside the session's.
		if sink := s.sink; sink != nil {
			sink.Write(res.No, res.TS, p.OrigLen, res.Raw)
		}

		for _, ch := range subs {
			select {
			case ch <- res:
			default:
				// This subscriber's browser is behind. Skipping keeps the
				// dissect loop at wire speed for everyone else; the packet is
				// still in the ring and still reachable via /api/packets.
			}
		}
	}
}

// Stop halts the capture. Stopping an idle session is not an error.
func (s *Session) Stop() error {
	s.mu.Lock()
	src := s.src
	s.src = nil
	s.running = false
	s.mu.Unlock()

	s.mu.Lock()
	sink := s.sink
	s.sink = nil
	s.mu.Unlock()
	if sink != nil {
		sink.Close()
	}

	if src != nil {
		return src.Close()
	}
	return nil
}

// SetFilter recompiles the display filter without disturbing the capture —
// changing what you are looking at must never cost you what you captured.
func (s *Session) SetFilter(text string) error {
	expr, err := dfilter.Compile(text)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.filter = expr
	s.mu.Unlock()
	return nil
}

// Subscribe registers a live feed. The returned cancel func must be called.
func (s *Session) Subscribe(buffer int) (<-chan *dissect.Result, func()) {
	ch := make(chan *dissect.Result, buffer)
	s.mu.Lock()
	id := s.nextID
	s.nextID++
	s.subs[id] = ch
	s.mu.Unlock()

	return ch, func() {
		s.mu.Lock()
		delete(s.subs, id)
		s.mu.Unlock()
		close(ch)
	}
}

// Status is what the GUI's status bar renders.
type Status struct {
	Running        bool      `json:"running"`
	Iface          string    `json:"iface"`
	Source         string    `json:"source"`       // af_packet | simulator | ebpf
	RealCapture    bool      `json:"real_capture"` // F43: never imply live data we do not have
	FallbackReason string    `json:"fallback_reason,omitempty"`
	Started        time.Time `json:"started"`
	Filter         string    `json:"filter"`
	Captured       int64     `json:"captured"`
	KernelDrops    int64     `json:"kernel_drops"`
	Bytes          int64     `json:"bytes"`
	Buffered       int       `json:"buffered"`
	Displayed      int       `json:"displayed"`
	Evicted        int64     `json:"evicted"`
	RingSize       int       `json:"ring_size"`
	CaptureFile    string    `json:"capture_file,omitempty"` // where the live capture is being saved
}

func (s *Session) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := Status{
		Running:        s.running,
		Iface:          s.iface,
		RealCapture:    s.realCapture,
		FallbackReason: s.fallbackErr,
		Started:        s.started,
		Buffered:       len(s.ring),
		Evicted:        s.dropped,
		RingSize:       s.size,
	}
	if s.sink != nil {
		st.CaptureFile = s.sink.Path()
	}
	if s.filter != nil {
		st.Filter = s.filter.String()
	}
	if s.src != nil {
		st.Source = s.src.Name()
		stats := s.src.Stats()
		st.Captured = stats.Captured
		st.KernelDrops = stats.Dropped
		st.Bytes = stats.Bytes
	}
	for _, r := range s.ring {
		if s.filter.Match(r) {
			st.Displayed++
		}
	}
	return st
}

// Packets returns the retained packets matching the current display filter,
// most recent last, capped at limit (0 = all).
func (s *Session) Packets(limit int) []*dissect.Result {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*dissect.Result, 0, min(len(s.ring), max(limit, 1)))
	for _, r := range s.ring {
		if s.filter.Match(r) {
			out = append(out, r)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Packet looks up one retained packet by its capture ordinal.
//
// This used to scan the ring linearly (up to s.size, normally 20000). No is
// the capture ordinal — every frame that arrives gets one, strictly
// increasing, whether or not it matches the display filter (see consume) —
// so the ring is exactly a contiguous window [ring[0].No, ring[0].No+len)
// and the lookup is a subtraction, not a search. That mattered in practice:
// a click on a packet detail (this RLock) was competing with consume's
// Lock, re-acquired on every arriving frame under fast capture, and a full
// scan while finally holding the lock made that wait worse, not just
// unlucky timing.
func (s *Session) Packet(no int64) *dissect.Result {
	s.mu.RLock()
	if len(s.ring) > 0 {
		if idx := no - s.ring[0].No; idx >= 0 && idx < int64(len(s.ring)) {
			r := s.ring[idx]
			s.mu.RUnlock()
			return r
		}
	}
	sink := s.sink
	s.mu.RUnlock()

	// Not in the ring: recover the frame from disk and re-dissect it. A fresh
	// dissector is fine for one packet — No and TS come from the stored record,
	// so the result identifies the same packet; only RelTime (relative to the
	// first packet of a capture) is not reconstructed, which the detail view
	// does not use.
	if sink != nil {
		if pk, ok := sink.Read(no); ok {
			return dissect.New().Packet(pk)
		}
	}
	return nil
}

// Matches reports whether r passes the current display filter.
func (s *Session) Matches(r *dissect.Result) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.filter.Match(r)
}
