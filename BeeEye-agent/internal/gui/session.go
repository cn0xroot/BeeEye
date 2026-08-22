// Package gui implements the BeeEye live analyzer server (program.md §3.12).
//
// It is deliberately a second, independent process from the agent (F42): its
// own port, its own frontend bundle, and no database connection at all. Live
// analysis happens entirely in memory, so nothing the analyzer does can slow
// down the overview UI's queries — or vice versa.
package gui

import (
	"io"
	"log"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"BeeEye/internal/analyze"
	"BeeEye/internal/dfilter"
	"BeeEye/internal/dissect"
	"BeeEye/internal/live"
	"BeeEye/internal/livefile"
	"BeeEye/internal/namemap"
	"BeeEye/internal/procmap"
	"BeeEye/internal/render"
)

// RenderChannels are the rows of the traffic colour field, in display order.
// They are fixed for the life of the process: a field whose rows silently
// change meaning is unreadable, so an unrecognised protocol falls into
// "other" rather than claiming a row of its own. sip/sctp/gtp/sim were added
// once those dissectors shipped (SIP/SCTP/GTP-U/GTP-C, SIMtrace-style
// GSMTAP/SIM) — before this they had a real dissector but no row of their
// own here, so telecom-signaling traffic silently fell into "other".
var RenderChannels = []string{"tls", "http", "dns", "mqtt", "sip", "sctp", "gtp", "sim", "arp", "icmp", "tcp", "other"}

// renderChannel maps a dissected packet onto one of RenderChannels.
func renderChannel(r *dissect.Result) string {
	for _, want := range []string{"tls", "http", "mqtt", "sip", "sctp", "gtp", "arp", "icmp"} {
		if r.HasProtocol(want) {
			return want
		}
	}
	if r.HasProtocol("dns") || r.HasProtocol("mdns") {
		return "dns"
	}
	// gsmtap is the radio-layer wrapper; sim is the ISO/IEC 7816-4 APDU
	// payload it carries — either one puts this packet in the same row, since
	// both describe the same SIM/mobile-radio traffic to someone reading the
	// field.
	if r.HasProtocol("gsmtap") || r.HasProtocol("sim") {
		return "sim"
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
	// offline is true when src is replaying a .pcap file (OpenFile) rather
	// than capturing a NIC — its own honesty flag alongside realCapture,
	// since "this is history, not this second" is a different fact than
	// "this is the simulator standing in" (F43 is about the latter).
	offline bool
	// consumeDone is closed by the currently running consume() goroutine
	// when its packet channel closes and it returns. startWith waits on it
	// before resetting ring/dropped/etc. for the capture it is about to
	// start — Stop() closing the previous source only asks that goroutine to
	// exit, asynchronously; without this wait it can still be mid-append to
	// s.ring after startWith has already reset it, leaking a few frames
	// from the capture that just stopped into the one about to begin. A few
	// stray live packets bleeding across an interface swap reads as mildly
	// stale; the same leak into a freshly opened .pcap file's packet list is
	// wrong data, not stale data.
	consumeDone chan struct{}

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
	// channelBytes is a non-decaying running total, unlike hist (an 80ms-per-
	// bucket, 1024-bucket-wide ring — real-time-driven, so anything it holds
	// scrolls out after ~82s regardless of whether the capture that produced
	// it is still running). An offline import can finish in well under a
	// second, and "what protocols make up this file" needs to stay a stable,
	// accurate answer for as long as the session stays open, not decay away
	// on its own a minute or two after the import — see RenderChannels for
	// why the field's rows are exactly these channel names.
	channelBytes map[string]int64

	// report is the capture-report view (program.md's Pcap-Analyzer-shaped
	// summary/protocols/talkers/conversations/credentials/files/findings/geo
	// breakdown), computed once when a file is opened rather than derived
	// from the ring — the ring evicts under a live capture's own retention
	// limit, but a report should describe the whole file regardless of size.
	// nil for a live capture (no single finished file to summarize).
	report *analyze.Report

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

	// procs attributes a flow to a local process (procmap). Owned here, not
	// by Server, so consume() can look a flow up the moment its packet
	// arrives — see procCache.
	procs *procmap.Resolver
	// procCache holds the attribution decided at capture time, keyed by
	// packet ordinal. Looking this up later, on demand (the API's old
	// behaviour), is too late for a short-lived connection: by the time a
	// browser click asks about it, the process may have exited and its
	// socket already be gone from /proc. Capture time is the one moment a
	// packet's own connection is guaranteed to still be live. Evicted
	// alongside the ring entry it belongs to, so this cannot outgrow it.
	procCache map[int64]procAttr
}

// procAttr is the process attribution decided for one packet at capture
// time. ok mirrors procmap.Resolver.LookupFlow's own ok — false is a real,
// cacheable answer ("this flow is not local"), not a miss.
type procAttr struct {
	proc procmap.Process
	side string
	ok   bool
}

// NewSession returns an idle session.
func NewSession(ringSize int) *Session {
	if ringSize <= 0 {
		ringSize = DefaultRingSize
	}
	s := &Session{
		size:         ringSize,
		subs:         map[int]chan *dissect.Result{},
		dis:          dissect.New(),
		hist:         render.NewHistory(RenderChannels, render.DefaultWidth),
		channelBytes: map[string]int64{},
		names:        namemap.New(0),
		renderer:     render.NewRenderer(),
		rotStop:      make(chan struct{}),
		// 2s of staleness is a deliberate trade: the /proc scans are far more
		// expensive than the dissection they annotate, and socket ownership
		// does not change meaningfully faster than that.
		procs: procmap.New(2 * time.Second),
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

// LookupProcess attributes a flow to a local process, preferring the
// attribution decided when the packet was captured (see consume) over a
// fresh lookup — the flow's connection is only guaranteed to still exist at
// that moment, not whenever this is later called. A packet from before this
// cache existed (persisted to disk, then read back after ring eviction)
// falls back to a live lookup, which is honestly best-effort at that point.
func (s *Session) LookupProcess(r *dissect.Result) (procmap.Process, string, bool) {
	s.mu.RLock()
	a, cached := s.procCache[r.No]
	s.mu.RUnlock()
	if cached {
		return a.proc, a.side, a.ok
	}
	return s.lookupProcessNow(r)
}

// lookupProcessNow queries procmap directly, with no cache involved. Called
// from consume() at capture time (the cache being filled) and as
// LookupProcess's fallback for anything the cache never saw.
func (s *Session) lookupProcessNow(r *dissect.Result) (procmap.Process, string, bool) {
	if s.procs == nil || r.Transport == "" || r.SrcPort == 0 {
		return procmap.Process{}, "", false
	}
	src, err := netip.ParseAddr(r.Src)
	if err != nil {
		return procmap.Process{}, "", false
	}
	dst, err := netip.ParseAddr(r.Dst)
	if err != nil {
		return procmap.Process{}, "", false
	}
	return s.procs.LookupFlow(r.Transport,
		netip.AddrPortFrom(src, uint16(r.SrcPort)),
		netip.AddrPortFrom(dst, uint16(r.DstPort)))
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
	return s.startWith(src, opt.Iface, opt.SnapLen, opt.Filter, real, openErr, false)
}

// OpenFile replays a previously captured .pcap file through the exact same
// pipeline a live capture uses — same dissector, same ring buffer, same
// display filter, same subscribers — so the packet list, traffic field and
// protocol detail panes need no separate "offline" rendering path. r is
// typically an uploaded file's multipart.File; ownership passes to the
// session (see livefile.Open), which closes it when replay finishes or the
// session moves on to something else.
//
// The only thing that distinguishes this from Start is honesty: Status.Offline
// tells the UI what is on screen is history, not this second (see the
// offline field's own comment — a different fact than F43's realCapture).
func (s *Session) OpenFile(r io.ReadCloser, name string) error {
	src, err := livefile.Open(r, name)
	if err != nil {
		return err
	}
	return s.startWith(src, name, 0, "", true, nil, true)
}

// startWith is Start and OpenFile's shared machinery: stop whatever was
// running, reset every piece of state a fresh capture invalidates, and hand
// the new source's packet channel to a consume goroutine. filterText is
// compiled before anything is torn down, so a typo in it leaves the
// previous capture running rather than stopping it for nothing.
func (s *Session) startWith(src live.Source, iface string, snapLen int, filterText string, real bool, openErr error, offline bool) error {
	expr, err := dfilter.Compile(filterText)
	if err != nil {
		if src != nil {
			src.Close()
		}
		return err
	}

	if err := s.Stop(); err != nil {
		if src != nil {
			src.Close()
		}
		return err
	}

	// See consumeDone's field comment: Stop() above only asked the previous
	// consume() goroutine to exit by closing its source, which is
	// asynchronous — wait for it to actually finish before resetting
	// anything it might still be writing to.
	s.mu.Lock()
	prevDone := s.consumeDone
	s.mu.Unlock()
	if prevDone != nil {
		<-prevDone
	}

	done := make(chan struct{})
	s.mu.Lock()
	s.src = src
	s.iface = iface
	s.realCapture = real
	s.offline = offline
	s.consumeDone = done
	s.fallbackErr = ""
	if !real && openErr != nil {
		s.fallbackErr = openErr.Error()
	}
	s.started = time.Now()
	s.running = true
	s.dis = dissect.New()
	s.ring = nil
	s.dropped = 0
	s.procCache = nil
	s.filter = expr
	s.names = namemap.New(0)
	s.channelBytes = map[string]int64{}
	s.report = nil
	if s.sink != nil {
		s.sink.Close()
		s.sink = nil
	}
	// Replaying a file that is itself a pcap makes writing a second copy of
	// it pointless — the persistence this feeds is for recovering a live
	// capture's own bytes after ring eviction, which a replayed file never
	// needs (its bytes are sitting right there in the file it came from).
	if s.captureDir != "" && !offline {
		snap := uint32(snapLen)
		if snap == 0 {
			snap = live.DefaultSnapLen
		}
		if sink, err := newPcapSink(s.captureDir, iface, snap, s.captureMax); err != nil {
			log.Printf("gui: packet persistence disabled: %v", err)
		} else {
			s.sink = sink
			log.Printf("gui: saving live capture to %s", sink.Path())
		}
	}
	packets := src.Packets()
	s.mu.Unlock()

	go s.consume(packets, done)
	return nil
}

// consume dissects every frame and fans it out to subscribers. done is
// closed on return — after the range loop exits, never before — so
// startWith's next call can wait for that instead of racing this goroutine's
// last few in-flight appends to s.ring.
func (s *Session) consume(packets <-chan live.Packet, done chan struct{}) {
	defer close(done)
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

		// Attribute the flow now, while its connection is still guaranteed
		// to exist — this packet is the proof it was just active. Waiting
		// for a later API request to ask (the old behaviour) meant a
		// short-lived connection (curl, any one-shot command) was routinely
		// gone from /proc — socket closed, process exited — by the time
		// anyone looked, misreporting a perfectly local flow as remote.
		proc, side, ok := s.lookupProcessNow(res)
		// Also fold it into the field index so the display filter can query
		// it directly (process.comm contains "curl") -- the same mechanism
		// every other field already uses, no separate query path for this
		// one dimension. Safe to write here, before res is shared with any
		// other goroutine via the ring or subs.
		if ok {
			if res.Fields == nil {
				res.Fields = map[string][]string{}
			}
			res.Fields["process.comm"] = []string{proc.Comm}
			res.Fields["process.pid"] = []string{strconv.Itoa(proc.PID)}
		}

		s.mu.Lock()
		s.channelBytes[renderChannel(res)] += int64(p.OrigLen)
		s.ring = append(s.ring, res)
		if len(s.ring) > s.size {
			// Drop the oldest in one slice re-slice rather than shifting.
			over := len(s.ring) - s.size
			for _, evicted := range s.ring[:over] {
				delete(s.procCache, evicted.No)
			}
			s.ring = s.ring[over:]
			s.dropped += int64(over)
		}
		if s.procCache == nil {
			s.procCache = map[int64]procAttr{}
		}
		s.procCache[res.No] = procAttr{proc: proc, side: side, ok: ok}
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
	// The channel closing is the source's own signal that there is nothing
	// left to read — Stop() calling this for a live capture, or (offline)
	// livefile.Open reaching the end of the file on its own. Either way,
	// Status.Running must go false here rather than staying stuck at
	// whatever Start last set it to: for a replayed file this is the only
	// place anything ever clears it, since nobody calls Stop() for it.
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
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
	// Offline is true while replaying a .pcap file (OpenFile) — Iface holds
	// the filename in that case. Own honesty flag alongside RealCapture: "this
	// is history, not this second" is a different fact than F43's "this is
	// the simulator standing in for a NIC we could not open."
	Offline bool `json:"offline,omitempty"`
}

// SetReport stores the capture-report computed for the file currently open
// (see Server.openFile) — a separate step from OpenFile itself because
// analyze.Analyze reads the whole file up front to build its own aggregates
// (talkers, conversations, credentials, ...) rather than consuming it
// packet-by-packet the way the live dissect/consume path does.
func (s *Session) SetReport(r *analyze.Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report = r
}

// Report returns the current capture-report, or nil if none has been
// computed yet (idle, or a live capture with no single file behind it).
func (s *Session) Report() *analyze.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.report
}

// ChannelTotals returns a copy of the current capture's bytes-per-channel
// running total (see channelBytes' own comment on why this exists alongside
// hist) — the protocol composition of the whole session, not a decaying
// window of it.
func (s *Session) ChannelTotals() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.channelBytes))
	for k, v := range s.channelBytes {
		out[k] = v
	}
	return out
}

func (s *Session) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := Status{
		Running:        s.running,
		Iface:          s.iface,
		RealCapture:    s.realCapture,
		Offline:        s.offline,
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
