package gui

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"BeeEye/internal/analyze"
	"BeeEye/internal/dfilter"
	"BeeEye/internal/dissect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/live"
	"BeeEye/internal/procmap"
	"BeeEye/internal/render"
	"BeeEye/internal/tlspeek"
)

// Server is the analyzer's HTTP surface.
type Server struct {
	sess    *Session
	webDir  string
	decrypt *Decryptor
}

// NewServer builds the analyzer's HTTP surface. decryptDefault turns HTTPS
// decryption on at startup (the "on by default" behaviour) — it attaches
// uprobes to the gateway's OpenSSL libraries and surfaces the plaintext. It is
// best-effort: without CAP_BPF the analyzer runs fine, just without decryption.
//
// Folding an opened file into the overview's own store too is the
// frontend's job (api.importToOverview, called from Toolbar's openFile) —
// not this server's: CORS is already open on the overview's API
// (Access-Control-Allow-Origin: *), so a plain client-side fetch reaches it
// directly, and doing it here as well would double-import every file opened
// through the UI.
//
// Process attribution (procmap) is owned by Session, not here — see
// Session.LookupProcess — because it needs to run the moment a packet is
// captured, not whenever an HTTP handler happens to ask about it.
func NewServer(sess *Session, webDir string, decryptDefault bool) *Server {
	srv := &Server{sess: sess, webDir: webDir, decrypt: NewDecryptor()}
	if decryptDefault {
		srv.decrypt.Enable()
	}
	return srv
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/interfaces", s.interfaces)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("POST /api/capture/start", s.start)
	mux.HandleFunc("POST /api/capture/stop", s.stop)
	mux.HandleFunc("POST /api/pcap/open", s.openFile)
	mux.HandleFunc("GET /api/report", s.report)
	mux.HandleFunc("GET /api/report/bars.png", s.reportBars)
	mux.HandleFunc("GET /api/report/files/{fid}", s.reportFile)
	mux.HandleFunc("POST /api/filter", s.setFilter)
	mux.HandleFunc("POST /api/filter/validate", s.validateFilter)
	mux.HandleFunc("GET /api/packets", s.packets)
	mux.HandleFunc("GET /api/packets/{no}", s.packetDetail)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("GET /api/export/pcap", s.exportPCAP)
	mux.HandleFunc("GET /api/render/info", s.renderInfo)
	mux.HandleFunc("GET /api/render/frame.png", s.renderFrame)
	mux.HandleFunc("GET /api/render/totals", s.renderTotals)
	mux.HandleFunc("GET /api/analyze", s.analyzeLive)
	mux.HandleFunc("GET /api/names", s.names)
	mux.HandleFunc("GET /api/decrypt", s.decryptStatus)
	mux.HandleFunc("POST /api/decrypt", s.decryptToggle)
	mux.HandleFunc("GET /api/plaintext", s.plaintext)
	mux.HandleFunc("GET /api/decrypt/libs", s.decryptLibs)
	mux.Handle("/", s.spa())
	return withCORS(mux)
}

// ------------------------------------------------------------------ handlers

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": "ok", "role": "BeeEye-gui", "time": time.Now()})
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	ifs, err := live.ListInterfaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, ifs)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.sess.Status())
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	var opt StartOptions
	if err := json.NewDecoder(r.Body).Decode(&opt); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if opt.SnapLen == 0 {
		opt.SnapLen = live.DefaultSnapLen
	}
	if err := s.sess.Start(opt); err != nil {
		// A bad display filter is the user's typo, not a server fault.
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, s.sess.Status())
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	if err := s.sess.Stop(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, s.sess.Status())
}

// maxPcapOpenBytes bounds an uploaded .pcap file — large enough for a
// realistic capture session, small enough that a client cannot use this
// endpoint to exhaust the process reading it into memory.
const maxPcapOpenBytes = 512 << 20 // 512 MiB

// openFile replays an uploaded .pcap file through the same pipeline a live
// capture uses (Session.OpenFile) — Wireshark's File > Open, in effect.
// Stops whatever capture or replay was already running the same way
// switching interfaces does.
func (s *Server) openFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPcapOpenBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()
	// Read the whole upload into memory rather than handing the multipart
	// reader straight to Session.OpenFile: analyze.Analyze below needs its
	// own independent read of the same bytes once OpenFile's background
	// consume() goroutine has started reading from it — sharing one live,
	// singly-consumable reader between the two would be a race, not a
	// shortcut. Bounded by maxPcapOpenBytes (512 MiB), same as the size this
	// endpoint already caps.
	data, err := io.ReadAll(file)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.sess.OpenFile(io.NopCloser(bytes.NewReader(data)), hdr.Filename); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Best-effort: the live packet-level session above is this endpoint's
	// primary job and has already succeeded by this point, so a report
	// computation failure (an exotic link type analyze.Analyze does not
	// know, say) does not fail the request — the file is still open and
	// inspectable, just without the summary/protocols/talkers view.
	if rep, err := analyze.Analyze(bytes.NewReader(data), hdr.Filename, int64(len(data))); err != nil {
		log.Printf("gui: report for %q: %v", hdr.Filename, err)
		s.sess.SetReport(nil)
	} else {
		s.sess.SetReport(rep)
	}
	writeJSON(w, s.sess.Status())
}

// report returns the current capture-report as JSON — nil (a bare "null")
// while idle or mid-live-capture, since there is no single finished file to
// summarize yet.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.sess.Report())
}

// reportFile serves one carved file's raw bytes as an opaque attachment,
// never inline — the same "never rendered, always downloaded" policy the
// overview's own file-carving view used, because these bytes came out of
// arbitrary captured traffic and are not to be trusted as, say, an image
// safe to decode in the browser.
func (s *Server) reportFile(w http.ResponseWriter, r *http.Request) {
	rep := s.sess.Report()
	if rep == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no report loaded"))
		return
	}
	fid := r.PathValue("fid")
	for _, f := range rep.Files {
		if f.ID != fid {
			continue
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+f.Filename+"\"")
		_, _ = w.Write(f.Data)
		return
	}
	writeErr(w, http.StatusNotFound, fmt.Errorf("file %q not in this report", fid))
}

// reportBarsWidth/Height match the field frame's own resolution (render.
// DefaultWidth/Height) — no reason for the report's charts to use a
// different geometry than everything else this renderer draws.
const (
	reportBarsWidth  = render.DefaultWidth
	reportBarsHeight = 220
)

// reportBars renders one of the report's ranked lists (protocols by bytes,
// top talkers by bytes, top conversations by bytes) as a GPU/CPU bar-chart
// frame (render.Renderer.RenderBars) — the same glow/bloom visual language
// TrafficField and the overview's traffic trend already use, so this reads
// as the same tool rather than a plainer chart pasted into it. kind selects
// which list; count caps how many rows (bars) are drawn, since the field
// this shares its renderer with has no notion of "too many rows" the way an
// unbounded talkers list does.
func (s *Server) reportBars(w http.ResponseWriter, r *http.Request) {
	rep := s.sess.Report()
	if rep == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no report loaded"))
		return
	}
	kind := r.URL.Query().Get("kind")
	count := 8
	if n, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && n > 0 && n <= 16 {
		count = n
	}

	type row struct {
		bytes int64
		proto string
	}
	var rows []row
	switch kind {
	case "protocols":
		for _, p := range rep.Protocols {
			rows = append(rows, row{p.Bytes, p.Protocol})
		}
	case "talkers":
		for _, t := range rep.Talkers {
			rows = append(rows, row{t.Bytes, ""}) // identity here is rank, not protocol
		}
	case "conversations":
		for _, c := range rep.Conversations {
			rows = append(rows, row{c.Bytes, c.AppProto})
		}
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("unknown kind %q (want protocols, talkers or conversations)", kind))
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].bytes > rows[j].bytes })
	if len(rows) > count {
		rows = rows[:count]
	}
	if len(rows) == 0 {
		writeErr(w, http.StatusNotFound, fmt.Errorf("report has no %s", kind))
		return
	}

	values := make([]float32, len(rows))
	colors := make([]float32, len(rows)*3)
	maxBytes := rows[0].bytes
	for i, rr := range rows {
		if maxBytes > 0 {
			values[i] = float32(rr.bytes) / float32(maxBytes)
		}
		rgb := protoColor(rr.proto, i)
		colors[i*3+0], colors[i*3+1], colors[i*3+2] = rgb[0], rgb[1], rgb[2]
	}

	height, _ := strconv.Atoi(r.URL.Query().Get("h"))
	if height <= 0 || height > 2048 {
		height = reportBarsHeight
	}
	hot := [3]float32{1.000, 0.976, 0.929}
	base := [3]float32{0.043, 0.062, 0.118}
	out := make([]byte, reportBarsWidth*height*4)
	if err := s.sess.Renderer().RenderBars(values, colors, len(rows), reportBarsWidth, height, hot, base, out); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	png, err := render.EncodePNG(out, reportBarsWidth, height)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// protoColor picks a report bar's colour from the same validated palette the
// field/packet-list use (render.ChannelColors, indexed the same way
// renderChannel maps a protocol onto RenderChannels) — a protocols chart's
// rows ARE those channel names, so it looks each one up for real and gets
// the exact hue the field and packet list already show for it. A talkers
// chart has no single "protocol" per row in that sense, so it falls back to
// cycling the palette by the row's own rank (idx) — deterministic per chart,
// not a shared counter that would make two requests colour the same row
// differently depending on request order.
func protoColor(proto string, idx int) [3]float32 {
	if proto != "" {
		for i, ch := range RenderChannels {
			if strings.EqualFold(ch, proto) {
				return render.ChannelColors[min(i, len(render.ChannelColors)-1)]
			}
		}
	}
	return render.ChannelColors[idx%len(render.ChannelColors)]
}

func (s *Server) setFilter(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filter string `json:"filter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.sess.SetFilter(body.Filter); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, s.sess.Status())
}

// validateFilter lets the filter box go green/red as the user types, without
// touching the running capture.
func (s *Server) validateFilter(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filter string `json:"filter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if _, err := dfilter.Compile(body.Filter); err != nil {
		writeJSON(w, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"valid": true})
}

// summary is the packet-list row. It stays small on purpose: the list can hold
// thousands of rows, and the field tree and hex are fetched only for the one
// packet the user actually selected.
type summary struct {
	No int64 `json:"no"`
	// Process is set only when one end of the flow is a socket on THIS host.
	// For traffic between other devices it stays nil — a packet carries no
	// process identity, and inventing one would be worse than saying nothing.
	Process     *procmap.Process `json:"process,omitempty"`
	ProcessSide string           `json:"process_side,omitempty"`
	Time        float64          `json:"time"`
	TS          int64            `json:"ts_ms"`
	Src         string           `json:"src"`
	Dst         string           `json:"dst"`
	Proto       string           `json:"proto"`
	Length      int              `json:"length"`
	Info        string           `json:"info"`
	Iface       string           `json:"iface"`
	Country     string           `json:"country,omitempty"`
	// Names observed for each endpoint, with the source that taught them
	// (F21). Empty when this capture never carried a name for the address —
	// which is a fact worth showing, not a gap to paper over with a reverse
	// lookup that would leak the destination to someone else's resolver.
	SrcName    string `json:"src_name,omitempty"`
	SrcNameSrc string `json:"src_name_source,omitempty"`
	DstName    string `json:"dst_name,omitempty"`
	DstNameSrc string `json:"dst_name_source,omitempty"`
}

func (srv *Server) toSummary(r *dissect.Result) summary {
	s := summary{
		No: r.No, Time: r.RelTime, TS: r.TS.UnixMilli(),
		Src: r.Src, Dst: r.Dst, Proto: r.Proto,
		Length: r.Length, Info: r.Info, Iface: r.Iface,
	}
	// Geo is resolved offline (§3.5.5) — no per-packet third-party lookup.
	if g := geoip.Lookup(r.Dst); g.Country != "" && g.Country != "??" {
		s.Country = g.Country
	}
	if p, side, ok := srv.lookupProcess(r); ok {
		s.Process, s.ProcessSide = &p, side
	}
	if names := srv.sess.Names(); names != nil {
		if n, src := names.Lookup(r.Src); n != "" {
			s.SrcName, s.SrcNameSrc = n, string(src)
		}
		if n, src := names.Lookup(r.Dst); n != "" {
			s.DstName, s.DstNameSrc = n, string(src)
		}
	}
	return s
}

// lookupProcess attributes a flow to a local process where that is
// meaningful. Delegates to the session, which decided this at capture time
// (see Session.LookupProcess) rather than now, for anything dissected since
// this cache existed.
func (srv *Server) lookupProcess(r *dissect.Result) (procmap.Process, string, bool) {
	return srv.sess.LookupProcess(r)
}

func (s *Server) packets(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 2000
	}
	rows := s.sess.Packets(limit)
	out := make([]summary, 0, len(rows))
	for _, p := range rows {
		out = append(out, s.toSummary(p))
	}
	writeJSON(w, out)
}

// packetDetail returns the full field tree plus the raw bytes for the hex pane.
func (s *Server) packetDetail(w http.ResponseWriter, r *http.Request) {
	no, err := strconv.ParseInt(r.PathValue("no"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	p := s.sess.Packet(no)
	if p == nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("packet %d is no longer buffered", no))
		return
	}
	detail := map[string]any{
		"summary":   s.toSummary(p),
		"layers":    p.Layers,
		"fields":    p.Fields,
		"protocols": p.Protocols,
		"sni":       p.SNI,
		"alpn":      p.ALPN,
		"ja3":       p.JA3,
		"geo":       geoip.Lookup(p.Dst),
		"hex":       p.Raw,
	}
	if proc, side, ok := s.lookupProcess(p); ok {
		detail["process"] = proc
		detail["process_side"] = side
	}
	writeJSON(w, detail)
}

// stream pushes matching packets over Server-Sent Events. SSE rather than a
// WebSocket because the flow is strictly one-way and the browser reconnects on
// its own — no upgrade handshake, no extra dependency (§3.12 tech choices).
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported by this server"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // defeat proxy buffering

	feed, cancel := s.sess.Subscribe(2048)
	defer cancel()

	// Packets are batched on a timer instead of written one per event: at a
	// few thousand packets a second, one SSE frame each would spend more time
	// in JSON and flush syscalls than in dissection.
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	batch := make([]summary, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		b, err := json.Marshal(batch)
		batch = batch[:0]
		if err != nil {
			return
		}
		fmt.Fprintf(w, "event: packets\ndata: %s\n\n", b)
		flusher.Flush()
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case p, ok := <-feed:
			if !ok {
				return
			}
			batch = append(batch, s.toSummary(p))
			if len(batch) >= 256 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-keepalive.C:
			st, _ := json.Marshal(s.sess.Status())
			fmt.Fprintf(w, "event: status\ndata: %s\n\n", st)
			flusher.Flush()
		}
	}
}

// names returns the whole IP ↔ domain association table (F21).
func (s *Server) names(w http.ResponseWriter, r *http.Request) {
	if ip := r.URL.Query().Get("ip"); ip != "" {
		writeJSON(w, s.sess.Names().All(ip))
		return
	}
	writeJSON(w, s.sess.Names().Snapshot())
}

// analyzeLive runs the offline analysis engine over the packets currently
// retained in memory (F40 + the analysis feature set).
//
// It is the same engine an uploaded capture goes through — one implementation,
// so a live capture and a pcap of that same traffic cannot report different
// findings. The `all` parameter chooses whether to analyse everything retained
// or only what the display filter currently shows, because "what did this one
// device do" and "what is on this network" are different questions.
func (s *Server) analyzeLive(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	packets := s.sess.Packets(limit)

	c := analyze.NewCollector()
	st := s.sess.Status()
	c.Meta(fmt.Sprintf("live: %s (%s)", st.Iface, st.Source), st.Bytes, "Ethernet", 0)
	if !st.RealCapture {
		// The report must carry the same caveat the status bar does.
		c.Warn("this analysis covers SIMULATED traffic, not a real capture")
	}
	if st.Evicted > 0 {
		c.Warn(fmt.Sprintf("%d packets were evicted from the in-memory ring before this analysis and are not included", st.Evicted))
	}
	for _, p := range packets {
		c.Add(p)
	}
	writeJSON(w, c.Report())
}

// ------------------------------------------------------- colour-field render

// renderInfo tells the UI which backend is actually drawing the field and
// which palette it uses, so the surrounding chrome can be built from the same
// colours rather than a second set that almost matches.
func (s *Server) renderInfo(w http.ResponseWriter, r *http.Request) {
	rd := s.sess.Renderer()
	writeJSON(w, map[string]any{
		"backend":  rd.Name(),
		"device":   rd.Device(),
		"channels": RenderChannels,
		"palette":  render.PaletteCSS(),
		"ground":   "#070c17",
		"width":    render.DefaultWidth,
		"height":   render.DefaultHeight,
	})
}

// renderTotals answers "what does this capture's traffic actually consist
// of" — a non-decaying bytes-per-channel total for the whole session (see
// Session.channelBytes' own comment on why this is a separate counter from
// the field's own rolling history), most directly useful for an offline
// import: once a replayed file finishes, this is still the file's real
// protocol composition, not a rolling window that has since scrolled it away.
func (s *Server) renderTotals(w http.ResponseWriter, r *http.Request) {
	totals := s.sess.ChannelTotals()
	var sum int64
	for _, v := range totals {
		sum += v
	}
	writeJSON(w, map[string]any{"totals": totals, "total_bytes": sum})
}

// renderFrame renders one frame of the traffic colour field as a PNG.
func (s *Server) renderFrame(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	width := s.sess.History().Width()
	height, _ := strconv.Atoi(q.Get("h"))
	if height <= 0 || height > 2048 {
		height = render.DefaultHeight
	}

	intensity := s.sess.History().Snapshot()
	channels := len(RenderChannels)
	buf := make([]byte, width*height*4)

	// The sweep is driven by wall time so successive frames animate rather
	// than each looking like a fresh still.
	t := float32(time.Now().UnixMilli()%600000) / 1000

	if err := s.sess.Renderer().Render(intensity, render.ChannelRGB(channels),
		channels, width, height, t, buf); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	png, err := render.EncodePNG(buf, width, height)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	// Every frame is different; a cached one would freeze the animation.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-BeeEye-Render-Backend", s.sess.Renderer().Name())
	_, _ = w.Write(png)
}

// ------------------------------------------------------------- PCAP export

// pcap link type 1 = Ethernet.
const pcapLinkTypeEthernet = 1

// exportPCAP writes the currently displayed packets as a classic libpcap file
// (F44), so anything the analyzer surfaces can be taken into Wireshark or
// tshark for deeper work rather than being trapped in this UI.
func (s *Server) exportPCAP(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	packets := s.sess.Packets(limit)

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition",
		`attachment; filename="BeeEye-`+time.Now().Format("20060102-150405")+`.pcap"`)

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)           // magic, µs resolution
	binary.LittleEndian.PutUint16(hdr[4:], 2)                    // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4)                    // version minor
	binary.LittleEndian.PutUint32(hdr[16:], live.DefaultSnapLen) // snaplen
	binary.LittleEndian.PutUint32(hdr[20:], pcapLinkTypeEthernet)
	if _, err := w.Write(hdr); err != nil {
		return
	}

	rec := make([]byte, 16)
	for _, p := range packets {
		if len(p.Raw) == 0 {
			continue
		}
		binary.LittleEndian.PutUint32(rec[0:], uint32(p.TS.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(p.TS.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(p.Raw))) // captured
		binary.LittleEndian.PutUint32(rec[12:], uint32(p.Length))  // original
		if _, err := w.Write(rec); err != nil {
			return
		}
		if _, err := w.Write(p.Raw); err != nil {
			return
		}
	}
}

// ------------------------------------------------------------------ plumbing

func (s *Server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(s.webDir); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<html><body style="font-family:system-ui;padding:2rem;line-height:1.6">
<h2>🐝 BeeEye Analyzer (BeeEye-gui) is running</h2>
<p>The analyzer UI has not been built yet. Run <code>make gui-web</code>,
or <code>cd BeeEye-gui && npm install && npm run dev</code> for a dev server.</p>
<p>API is live: <a href="/api/interfaces">/api/interfaces</a> ·
<a href="/api/status">/api/status</a> · <a href="/api/packets">/api/packets</a></p>
<p>This process is independent of the overview UI on :8080 — stopping either
one leaves the other running.</p></body></html>`)
			return
		}
		// See BeeEye-agent/internal/api/api.go's spaHandler for why index.html
		// must always be revalidated while a hashed /assets/*.js can be cached
		// indefinitely: without this, a browser can keep running a pre-redeploy
		// bundle for a long time, which looks exactly like "the fix didn't
		// ship" to whoever is testing it.
		p := filepath.Join(s.webDir, filepath.Clean(r.URL.Path))
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache")
			}
			http.ServeFile(w, r, p)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(s.webDir, "index.html"))
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// decryptStatus reports whether HTTPS decryption is on and how many libraries
// are probed (F14; "on by default").
func (s *Server) decryptStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.decrypt.Status())
}

// decryptToggle turns decryption on or off at runtime: POST {"enabled":true}.
func (s *Server) decryptToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if body.Enabled {
		s.decrypt.Enable()
	} else {
		s.decrypt.Disable()
	}
	writeJSON(w, s.decrypt.Status())
}

// plaintext returns recently decrypted chunks. With ?pid=N it restricts to one
// process, which is how the packet detail shows the plaintext for the flow it
// is looking at; without it, the whole recent stream.
func (s *Server) plaintext(w http.ResponseWriter, r *http.Request) {
	pid, _ := strconv.Atoi(r.URL.Query().Get("pid"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	writeJSON(w, map[string]any{
		"status": s.decrypt.Status(),
		"chunks": s.decrypt.Recent(pid, limit),
	})
}

// decryptLibs surveys the crypto libraries on this host and whether uprobe
// decryption can attach to each — the "detect crypto libraries" capability
// (rules.go drives it). Lets an operator see which of their tools are covered.
func (s *Server) decryptLibs(w http.ResponseWriter, r *http.Request) {
	libs, err := tlspeek.Detect()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"libraries": libs, "rules": tlspeek.RuleNames()})
}
