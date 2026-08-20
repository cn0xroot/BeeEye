// Package api exposes the BeeEye REST API consumed by the self-built web UI
// (program.md §3.2, §3.6.1). All category / event_type values are returned as
// enum keys — the frontend localizes them (§3.8.1) so language switching never
// leaves mixed zh/en text.
package api

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"BeeEye/internal/analyze"
	"BeeEye/internal/config"
	"BeeEye/internal/detect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/mitm"
	"BeeEye/internal/model"
	"BeeEye/internal/store"
	"BeeEye/internal/tcapture"
)

type Server struct {
	st      *store.Store
	cfg     *config.Config
	reports *analyze.Store

	// Data-source honesty (F43): what the overview is actually showing. Set by
	// main once it knows whether the live capture opened or the simulator is
	// standing in, so the UI can badge simulated data rather than passing it
	// off as real. A hot-plug interface swap (F20) can call SetSource again
	// from another goroutine after startup, so this is an atomic pointer to
	// an immutable struct rather than three plain fields — otherwise a
	// concurrent reader could see live=true paired with the previous iface.
	src atomic.Pointer[sourceInfo]

	// tcap serves F11 (on-demand targeted capture). nil until main wires one
	// in via SetTargetedCapture — which only happens when a live pipeline is
	// actually running, since a targeted capture has nothing to filter
	// packets out of otherwise. Also swapped on every hot-plug interface
	// change, hence the same atomic-pointer treatment as src.
	tcap atomic.Pointer[tcapture.Manager]

	// mitmProxy serves F45's endpoints. nil unless mitm.enabled is true in
	// config, in which case main wires one in via SetMITM once the proxy is
	// actually listening — the CA-download and status endpoints answer a
	// clear "not enabled" error rather than a generic 404 when it's off.
	mitmProxy atomic.Pointer[mitm.Proxy]
}

type sourceInfo struct {
	live  bool
	iface string
	name  string
}

func New(st *store.Store, cfg *config.Config) *Server {
	s := &Server{st: st, cfg: cfg, reports: analyze.NewStore(10)}
	s.src.Store(&sourceInfo{name: "simulated"})
	return s
}

// SetSource records whether the overview's data is a live capture or the
// simulated scenario. Called at startup, and again by the hot-plug
// supervisor (F20) whenever the capture interface changes.
func (s *Server) SetSource(live bool, iface, name string) {
	s.src.Store(&sourceInfo{live: live, iface: iface, name: name})
}

// SetTargetedCapture wires in the manager F11's on-demand capture endpoints
// use. Called once at startup when a live pipeline exists, and again after
// every hot-plug interface swap (F20) so the endpoints keep working against
// whichever pipeline is currently running.
func (s *Server) SetTargetedCapture(m *tcapture.Manager) { s.tcap.Store(m) }

// SetMITM wires in the running F45 proxy once main has started it (only
// happens when mitm.enabled is true in config). Never called otherwise, so
// the mitm endpoints correctly answer "not enabled" rather than a nil
// dereference.
func (s *Server) SetMITM(p *mitm.Proxy) { s.mitmProxy.Store(p) }

// Routes builds the HTTP handler (Go 1.22 pattern-based ServeMux, no router dep).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/summary", s.summary)
	mux.HandleFunc("GET /api/config", s.getConfig)
	mux.HandleFunc("GET /api/source", s.getSource)
	mux.HandleFunc("GET /api/devices", s.devices)
	mux.HandleFunc("POST /api/devices/{mac}/ack", s.ackDevice)
	mux.HandleFunc("POST /api/devices/{mac}/category", s.setCategory)
	mux.HandleFunc("GET /api/connections", s.connections)
	mux.HandleFunc("GET /api/dns", s.dns)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("POST /api/events/{id}/ack", s.ackEvent)
	mux.HandleFunc("GET /api/views/ip", s.ipView)
	mux.HandleFunc("GET /api/views/protocol", s.protocolView)
	mux.HandleFunc("GET /api/views/topn", s.topN)
	mux.HandleFunc("GET /api/views/geopairs", s.geoPairs)
	mux.HandleFunc("GET /api/timeseries", s.timeseries)
	mux.HandleFunc("GET /api/export", s.export)
	mux.HandleFunc("GET /api/geoip", s.geoipLookup)
	mux.HandleFunc("GET /api/geoip/status", s.geoipStatus)

	// Offline capture-file analysis.
	mux.HandleFunc("POST /api/pcap/upload", s.pcapUpload)
	mux.HandleFunc("GET /api/pcap", s.pcapList)
	mux.HandleFunc("GET /api/pcap/{id}", s.pcapReport)
	mux.HandleFunc("GET /api/pcap/{id}/files/{fid}", s.pcapFile)

	// On-demand targeted capture (F11): a fresh, MAC-filtered pcap distinct
	// from a snapshot of the rolling ring buffer.
	mux.HandleFunc("POST /api/capture/targeted", s.startTargetedCapture)
	mux.HandleFunc("GET /api/capture/targeted", s.listTargetedCaptures)
	mux.HandleFunc("GET /api/capture/targeted/{id}", s.targetedCaptureStatus)
	mux.HandleFunc("GET /api/capture/targeted/{id}/download", s.targetedCaptureDownload)

	// Opt-in MITM decryption (F45) — off unless mitm.enabled is set.
	mux.HandleFunc("GET /api/mitm/status", s.mitmStatus)
	mux.HandleFunc("GET /api/mitm/ca.pem", s.mitmCA)
	mux.HandleFunc("GET /api/mitm/ca.mobileconfig", s.mitmMobileConfig)
	mux.HandleFunc("GET /api/mitm/exchanges", s.mitmExchanges)
	mux.HandleFunc("GET /api/mitm/exchanges/{id}", s.mitmExchange)

	// static frontend (SPA) — serve dist if built, else a hint page.
	fs := s.spaHandler()
	mux.Handle("/", fs)
	return cors(mux)
}

// ---------- handlers ----------

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": "ok", "time": time.Now()})
}

// getSource tells the UI whether it is looking at real captured traffic or the
// simulated scenario, so the overview can show an honest badge (F43).
func (s *Server) getSource(w http.ResponseWriter, r *http.Request) {
	src := s.src.Load()
	writeJSON(w, map[string]any{
		"live":   src.live,
		"iface":  src.iface,
		"source": src.name, // "af_packet" | "simulated"
	})
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"interfaces":      s.cfg.Interfaces,
		"risk_thresholds": s.cfg.Detection.RiskThresholds,
		"beacon":          s.cfg.Detection.Beacon,
		"auto_block":      s.cfg.Detection.AutoBlock,
		"signal_weights":  detect.SignalWeights,
	})
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.st.Devices()
	evts, _ := s.st.Events(1000)
	catCount := map[string]int{}
	newDevices := 0
	for _, d := range devs {
		catCount[string(d.Category)]++
		if d.IsNew {
			newDevices++
		}
	}
	sev := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	for _, e := range evts {
		sev[string(e.Severity)]++
	}
	conns, _ := s.st.Connections(store.ConnFilter{Limit: 100000})
	var totalBytes int64
	internal := 0
	for _, c := range conns {
		totalBytes += c.Bytes
		if c.Internal {
			internal++
		}
	}
	writeJSON(w, map[string]any{
		"device_count":     len(devs),
		"new_devices":      newDevices,
		"category_count":   catCount,
		"event_count":      len(evts),
		"severity_count":   sev,
		"connection_count": len(conns),
		"internal_flows":   internal,
		"total_bytes":      totalBytes,
	})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	d, err := s.st.Devices()
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, d)
}

func (s *Server) ackDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.st.AckDevice(r.PathValue("mac")); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) setCategory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.st.SetCategory(r.PathValue("mac"), model.DeviceCategory(body.Category)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// parseFilter builds a ConnFilter from query params — the single place the
// multi-dimension filter (F30) is decoded, shared by the connection list, the
// time series and the export endpoint so all three stay in lockstep (§3.6.1).
func parseFilter(q url.Values, defLimit int) store.ConnFilter {
	f := store.ConnFilter{Limit: atoiDefault(q.Get("limit"), defLimit)}
	if v := q.Get("mac"); v != "" {
		f.MACs = strings.Split(v, ",")
	}
	f.IPLike = q.Get("ip")
	if v := q.Get("proto"); v != "" {
		f.Protos = strings.Split(v, ",")
	}
	f.PortMin = atoiDefault(q.Get("port_min"), 0)
	f.PortMax = atoiDefault(q.Get("port_max"), 0)
	if v := q.Get("since"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.Since = time.Unix(sec, 0)
		}
	}
	if v := q.Get("until"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.Until = time.Unix(sec, 0)
		}
	}
	f.InternalOnly = q.Get("internal") == "1"
	return f
}

// connections implements the multi-dimension filter (F30).
func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r.URL.Query(), 500)
	conns, err := s.st.Connections(f)
	if err != nil {
		writeErr(w, err)
		return
	}
	// enrich with geo of dst for the UI
	type enriched struct {
		model.Connection
		Geo    model.GeoInfo `json:"geo"`
		Domain string        `json:"domain"`
	}
	out := make([]enriched, 0, len(conns))
	for _, c := range conns {
		e := enriched{Connection: c, Geo: geoip.Lookup(c.DstIP)}
		if d, ok := s.st.DomainForIP(c.DstIP); ok {
			e.Domain = d
		} else if c.SNI != "" {
			e.Domain = c.SNI
		}
		out = append(out, e)
	}
	writeJSON(w, out)
}

func (s *Server) dns(w http.ResponseWriter, r *http.Request) {
	recs, err := s.st.DNSRecords(r.URL.Query().Get("mac"), atoiDefault(r.URL.Query().Get("limit"), 500))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, recs)
}

// events lists risk events, enriched with the destination IP's domain and
// geo (country/city/lat-lon) — the same enrichment connections/ipView
// already carry, extended here so an alert row can show "what" and "where"
// without the UI having to reach into the raw Detail blob itself. Not every
// event has a destination: signals scored at the MAC level (fanout,
// baseline_deviation, dns_anomaly, a threat-intel hit on a domain rather
// than an IP) stamp dst_ip as "" in detect.Engine.score, and those rows are
// enriched with nothing rather than a bogus 0,0 geo point.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	e, err := s.st.Events(atoiDefault(r.URL.Query().Get("limit"), 500))
	if err != nil {
		writeErr(w, err)
		return
	}
	type enriched struct {
		model.Event
		DstIP  string         `json:"dst_ip,omitempty"`
		Geo    *model.GeoInfo `json:"geo,omitempty"`
		Domain string         `json:"domain,omitempty"`
	}
	out := make([]enriched, 0, len(e))
	for _, ev := range e {
		row := enriched{Event: ev}
		if ip, _ := ev.Detail["dst_ip"].(string); ip != "" {
			row.DstIP = ip
			geo := geoip.Lookup(ip)
			row.Geo = &geo
			if d, ok := s.st.DomainForIP(ip); ok {
				row.Domain = d
			}
		}
		out = append(out, row)
	}
	writeJSON(w, out)
}

func (s *Server) ackEvent(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.st.AckEvent(id); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// GeoPair is one recent external connection reduced to what the world-map
// view needs to draw a source→destination arc: nothing about the connection
// itself, just where it went and roughly how big it was.
type GeoPair struct {
	DstIP   string    `json:"dst_ip"`
	Lat     float64   `json:"lat"`
	Lon     float64   `json:"lon"`
	Country string    `json:"country"`
	City    string    `json:"city"`
	Domain  string    `json:"domain"`
	Proto   string    `json:"proto"`
	Bytes   int64     `json:"bytes"`
	TS      time.Time `json:"ts"`
}

// geoPairs feeds the world-map / traffic-globe view (F32): the most recent
// external connections with a resolvable geo point, newest first. Internal
// (east-west) traffic and anything geoip can't place on a map (private/CGNAT
// ranges, or a public IP the offline database has no coordinates for) are
// left out — an arc to 0,0 would be worse than no arc. The client is
// expected to poll this and diff against the newest ts it has already drawn,
// so this endpoint stays a plain snapshot rather than a push stream.
func (s *Server) geoPairs(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 150)
	// Over-fetch: most rows on a home network are internal or already-seen
	// repeat destinations, so asking the store for exactly `limit` would
	// starve the response on a chatty LAN.
	conns, err := s.st.Connections(store.ConnFilter{Limit: limit * 8})
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]GeoPair, 0, limit)
	for _, c := range conns {
		if c.Internal || len(out) >= limit {
			continue
		}
		geo := geoip.Lookup(c.DstIP)
		if geo.Local || (geo.Lat == 0 && geo.Lon == 0) {
			continue
		}
		gp := GeoPair{
			DstIP: c.DstIP, Lat: geo.Lat, Lon: geo.Lon, Country: geo.Country, City: geo.City,
			Proto: firstNonEmpty(c.AppProtocol, c.Proto), Bytes: c.Bytes, TS: c.TS,
		}
		if d, ok := s.st.DomainForIP(c.DstIP); ok {
			gp.Domain = d
		} else if c.SNI != "" {
			gp.Domain = c.SNI
		}
		out = append(out, gp)
	}
	writeJSON(w, out)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ipView aggregates connections by destination IP (F25).
func (s *Server) ipView(w http.ResponseWriter, r *http.Request) {
	conns, _ := s.st.Connections(store.ConnFilter{Limit: 100000})
	type agg struct {
		IP        string         `json:"ip"`
		Domain    string         `json:"domain"`
		Geo       model.GeoInfo  `json:"geo"`
		Devices   []string       `json:"devices"`
		Protocols []string       `json:"protocols"`
		Ports     map[int]string `json:"ports"`
		Bytes     int64          `json:"bytes"`
		ConnCount int            `json:"conn_count"`
		FirstSeen time.Time      `json:"first_seen"`
		LastSeen  time.Time      `json:"last_seen"`
		Internal  bool           `json:"internal"`
	}
	m := map[string]*agg{}
	devSet := map[string]map[string]bool{}
	protoSet := map[string]map[string]bool{}
	for _, c := range conns {
		a := m[c.DstIP]
		if a == nil {
			a = &agg{IP: c.DstIP, Geo: geoip.Lookup(c.DstIP), Ports: map[int]string{},
				FirstSeen: c.TS, LastSeen: c.TS, Internal: c.Internal}
			if d, ok := s.st.DomainForIP(c.DstIP); ok {
				a.Domain = d
			}
			m[c.DstIP] = a
			devSet[c.DstIP] = map[string]bool{}
			protoSet[c.DstIP] = map[string]bool{}
		}
		a.Bytes += c.Bytes
		a.ConnCount++
		a.Ports[c.DstPort] = c.Service
		devSet[c.DstIP][c.MAC] = true
		protoSet[c.DstIP][c.AppProtocol] = true
		if c.TS.Before(a.FirstSeen) {
			a.FirstSeen = c.TS
		}
		if c.TS.After(a.LastSeen) {
			a.LastSeen = c.TS
		}
	}
	out := make([]*agg, 0, len(m))
	for ip, a := range m {
		a.Devices = keys(devSet[ip])
		a.Protocols = keys(protoSet[ip])
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	writeJSON(w, out)
}

// protocolView aggregates by application protocol (F26).
func (s *Server) protocolView(w http.ResponseWriter, r *http.Request) {
	conns, _ := s.st.Connections(store.ConnFilter{Limit: 100000})
	type agg struct {
		Protocol   string         `json:"protocol"`
		Bytes      int64          `json:"bytes"`
		ConnCount  int            `json:"conn_count"`
		Devices    []string       `json:"devices"`
		Ports      map[int]string `json:"ports"`
		TopTargets []string       `json:"top_targets"`
	}
	m := map[string]*agg{}
	devSet := map[string]map[string]bool{}
	tgtBytes := map[string]map[string]int64{}
	for _, c := range conns {
		a := m[c.AppProtocol]
		if a == nil {
			a = &agg{Protocol: c.AppProtocol, Ports: map[int]string{}}
			m[c.AppProtocol] = a
			devSet[c.AppProtocol] = map[string]bool{}
			tgtBytes[c.AppProtocol] = map[string]int64{}
		}
		a.Bytes += c.Bytes
		a.ConnCount++
		a.Ports[c.DstPort] = c.Service
		devSet[c.AppProtocol][c.MAC] = true
		tgtBytes[c.AppProtocol][c.DstIP] += c.Bytes
	}
	out := make([]*agg, 0, len(m))
	for p, a := range m {
		a.Devices = keys(devSet[p])
		a.TopTargets = topKeys(tgtBytes[p], 5)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	writeJSON(w, out)
}

// topN ranks by a chosen dimension (F27).
func (s *Server) topN(w http.ResponseWriter, r *http.Request) {
	dim := r.URL.Query().Get("dim")
	if dim == "" {
		dim = "device"
	}
	n := atoiDefault(r.URL.Query().Get("n"), 10)
	conns, _ := s.st.Connections(store.ConnFilter{Limit: 100000})
	bytesBy := map[string]int64{}
	for _, c := range conns {
		switch dim {
		case "device":
			bytesBy[c.MAC] += c.Bytes
		case "ip":
			bytesBy[c.DstIP] += c.Bytes
		case "country":
			cc := geoip.Lookup(c.DstIP).Country
			bytesBy[cc] += c.Bytes
		case "domain":
			d := c.SNI
			if d == "" {
				if dm, ok := s.st.DomainForIP(c.DstIP); ok {
					d = dm
				}
			}
			if d != "" {
				bytesBy[d] += c.Bytes
			}
		}
	}
	type row struct {
		Key   string `json:"key"`
		Bytes int64  `json:"bytes"`
	}
	rows := make([]row, 0, len(bytesBy))
	for k, v := range bytesBy {
		rows = append(rows, row{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
	if len(rows) > n {
		rows = rows[:n]
	}
	writeJSON(w, map[string]any{"dim": dim, "rows": rows})
}

func (s *Server) geoipLookup(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, geoip.Lookup(r.URL.Query().Get("ip")))
}

// geoipStatus reports whether geoip is running on a real MaxMind database and
// what it can resolve (F22): city+ASN, country-only, or the built-in coarse
// table. The overview UI uses this to tell an operator why locations are
// approximate rather than leaving them to guess.
func (s *Server) geoipStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, geoip.GetStatus())
}

// timeseries buckets traffic over time for the trend chart (F7). Series are
// split by the requested dimension so the chart legend can be localized from
// enum keys rather than server-rendered labels (§3.8.1).
func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bucket := atoiDefault(q.Get("bucket"), 300) // seconds
	if bucket < 10 {
		bucket = 10
	}
	split := q.Get("split") // "" | category | protocol | device
	conns, err := s.st.Connections(parseFilter(q, 100000))
	if err != nil {
		writeErr(w, err)
		return
	}
	cats := map[string]string{}
	if split == "category" {
		devs, _ := s.st.Devices()
		for _, d := range devs {
			cats[d.MAC] = string(d.Category)
		}
	}

	// bucket → series → bytes
	type cell struct {
		Bytes int64 `json:"bytes"`
		Conns int   `json:"conns"`
	}
	buckets := map[int64]map[string]*cell{}
	seriesSet := map[string]bool{}
	var minT, maxT int64
	for i, c := range conns {
		b := c.TS.Unix() / int64(bucket) * int64(bucket)
		if i == 0 || b < minT {
			minT = b
		}
		if i == 0 || b > maxT {
			maxT = b
		}
		key := "all"
		switch split {
		case "category":
			key = cats[c.MAC]
			if key == "" {
				key = "unknown"
			}
		case "protocol":
			key = c.AppProtocol
		case "device":
			key = c.MAC
		}
		seriesSet[key] = true
		if buckets[b] == nil {
			buckets[b] = map[string]*cell{}
		}
		if buckets[b][key] == nil {
			buckets[b][key] = &cell{}
		}
		buckets[b][key].Bytes += c.Bytes
		buckets[b][key].Conns++
	}
	series := keys(seriesSet)

	// emit a dense (gap-free) series so the chart draws a continuous line
	type point struct {
		TS     int64            `json:"ts"`
		Values map[string]*cell `json:"values"`
	}
	points := []point{}
	if len(conns) > 0 {
		for t := minT; t <= maxT; t += int64(bucket) {
			vals := map[string]*cell{}
			for _, k := range series {
				if c := buckets[t][k]; c != nil {
					vals[k] = c
				} else {
					vals[k] = &cell{}
				}
			}
			points = append(points, point{TS: t, Values: vals})
		}
	}
	writeJSON(w, map[string]any{"bucket": bucket, "split": split, "series": series, "points": points})
}

// export streams the filtered connection set as CSV or JSON (F31). Enum keys
// are exported as-is so downstream analysis is language-independent.
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	conns, err := s.st.Connections(parseFilter(q, 100000))
	if err != nil {
		writeErr(w, err)
		return
	}
	stamp := time.Now().Format("20060102-150405")
	if q.Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="BeeEye-connections-`+stamp+`.json"`)
		_ = json.NewEncoder(w).Encode(conns)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="BeeEye-connections-`+stamp+`.csv"`)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM so Excel reads CJK correctly
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"ts", "mac", "src_ip", "src_port", "dst_ip", "dst_port",
		"proto", "app_protocol", "service", "bytes", "packets", "iface", "sni", "ja3",
		"internal", "domain", "country", "city"})
	for _, c := range conns {
		g := geoip.Lookup(c.DstIP)
		domain := c.SNI
		if d, ok := s.st.DomainForIP(c.DstIP); ok {
			domain = d
		}
		_ = cw.Write([]string{
			c.TS.Format(time.RFC3339), c.MAC, c.SrcIP, strconv.Itoa(c.SrcPort),
			c.DstIP, strconv.Itoa(c.DstPort), c.Proto, c.AppProtocol, c.Service,
			strconv.FormatInt(c.Bytes, 10), strconv.FormatInt(c.Packets, 10),
			c.Iface, c.SNI, c.JA3, strconv.FormatBool(c.Internal),
			domain, g.Country, g.City,
		})
	}
}

// ------------------------------------------------- offline pcap analysis

// maxUploadBytes caps an uploaded capture. Analysis holds reconstructed
// sessions in memory, so an unbounded upload would be an easy way to take the
// gateway down.
const maxUploadBytes = 256 << 20 // 256 MiB

func (s *Server) pcapUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErrStatus(w, http.StatusBadRequest, err)
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErrStatus(w, http.StatusBadRequest, err)
		return
	}
	defer file.Close()

	rep, err := analyze.Analyze(file, hdr.Filename, hdr.Size)
	if err != nil {
		// A wrong file type is the user's mistake, not a server fault, and the
		// message says what to do about it.
		writeErrStatus(w, http.StatusBadRequest, err)
		return
	}
	id := s.reports.Put(rep)
	writeJSON(w, map[string]any{"id": id, "report": rep})
}

func (s *Server) pcapList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.reports.List())
}

func (s *Server) pcapReport(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.reports.Get(r.PathValue("id"))
	if !ok {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no analysis with id %q — reports are kept in memory and do not survive a restart", r.PathValue("id")))
		return
	}
	writeJSON(w, rep)
}

func (s *Server) pcapFile(w http.ResponseWriter, r *http.Request) {
	f, ok := s.reports.File(r.PathValue("id"), r.PathValue("fid"))
	if !ok {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no such carved file"))
		return
	}
	// Always as an attachment with a generic type: a carved body may well be
	// malware, and letting a browser render or execute it inline would be a
	// poor way to end a forensics session.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(f.Filename)+"\"")
	_, _ = w.Write(f.Data)
}

// startTargetedCapture begins one F11 session: a fresh pcap file capturing
// only frames touching the given MAC, for a bounded duration/byte budget.
func (s *Server) startTargetedCapture(w http.ResponseWriter, r *http.Request) {
	mgr := s.tcap.Load()
	if mgr == nil {
		writeErrStatus(w, http.StatusServiceUnavailable,
			fmt.Errorf("targeted capture needs a running live-capture pipeline, which is not active right now"))
		return
	}
	var req struct {
		MAC       string `json:"mac"`
		DurationS int    `json:"duration_s"`
		MaxBytes  int64  `json:"max_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrStatus(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	sess, err := mgr.Start(req.MAC, time.Duration(req.DurationS)*time.Second, req.MaxBytes)
	if err != nil {
		writeErrStatus(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, sess.Status())
}

func (s *Server) listTargetedCaptures(w http.ResponseWriter, r *http.Request) {
	mgr := s.tcap.Load()
	if mgr == nil {
		writeJSON(w, []tcapture.Status{})
		return
	}
	writeJSON(w, mgr.List())
}

func (s *Server) targetedCaptureStatus(w http.ResponseWriter, r *http.Request) {
	mgr := s.tcap.Load()
	if mgr == nil {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no targeted-capture session %q", r.PathValue("id")))
		return
	}
	sess, ok := mgr.Get(r.PathValue("id"))
	if !ok {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no targeted-capture session %q", r.PathValue("id")))
		return
	}
	writeJSON(w, sess.Status())
}

func (s *Server) targetedCaptureDownload(w http.ResponseWriter, r *http.Request) {
	mgr := s.tcap.Load()
	if mgr == nil {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no targeted-capture session %q", r.PathValue("id")))
		return
	}
	sess, ok := mgr.Get(r.PathValue("id"))
	if !ok {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no targeted-capture session %q", r.PathValue("id")))
		return
	}
	f, err := os.Open(sess.Path())
	if err != nil {
		writeErrStatus(w, http.StatusInternalServerError, err)
		return
	}
	defer f.Close()
	name := strings.ReplaceAll(sess.MAC, ":", "-")
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", "attachment; filename=\"beeeye-targeted-"+name+"-"+sess.ID+".pcap\"")
	_, _ = io.Copy(w, f)
}

// mitmNotEnabled is the shared error for every F45 endpoint when main never
// started a proxy — either mitm.enabled is false, or the config was never
// changed from its shipped default.
func mitmNotEnabled() error {
	return fmt.Errorf("MITM decryption is not enabled — set mitm.enabled: true in config.yaml and restart")
}

func (s *Server) mitmStatus(w http.ResponseWriter, r *http.Request) {
	p := s.mitmProxy.Load()
	if p == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, map[string]any{
		"enabled":     true,
		"listen_addr": p.Addr(),
		"fingerprint": p.CA().Fingerprint(),
		"exchanges":   len(p.Exchanges(0)),
	})
}

// mitmCA serves the root CA a phone or computer installs to start trusting
// this proxy. application/x-x509-ca-cert is what makes iOS/Android offer to
// install it as a trusted profile when this link is opened directly on the
// device, rather than just downloading a file named ca.pem.
func (s *Server) mitmCA(w http.ResponseWriter, r *http.Request) {
	p := s.mitmProxy.Load()
	if p == nil {
		writeErrStatus(w, http.StatusServiceUnavailable, mitmNotEnabled())
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"beeeye-mitm-ca.pem\"")
	_, _ = w.Write(p.CA().PEM())
}

// mitmMobileConfig serves the same CA wrapped as an Apple Configuration
// Profile — a nicer install prompt on iOS/iPadOS/macOS (named, described)
// than a bare PEM download, though the manual "enable full trust" step in
// Settings afterward is unavoidable either way (see CA.MobileConfig's doc).
func (s *Server) mitmMobileConfig(w http.ResponseWriter, r *http.Request) {
	p := s.mitmProxy.Load()
	if p == nil {
		writeErrStatus(w, http.StatusServiceUnavailable, mitmNotEnabled())
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", "attachment; filename=\"beeeye-mitm-ca.mobileconfig\"")
	_, _ = w.Write(p.CA().MobileConfig())
}

func (s *Server) mitmExchanges(w http.ResponseWriter, r *http.Request) {
	p := s.mitmProxy.Load()
	if p == nil {
		writeErrStatus(w, http.StatusServiceUnavailable, mitmNotEnabled())
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, p.Exchanges(limit))
}

// mitmExchange returns one decrypted request/response pair in full,
// including bodies — base64-encoded explicitly (req_body_b64/resp_body_b64)
// rather than left to encoding/json's implicit []byte→base64 behavior, the
// same explicit-naming fix applied after that behavior once caused a blank
// packet-detail panel elsewhere in this codebase (see CHANGELOG.zh-CN.md).
func (s *Server) mitmExchange(w http.ResponseWriter, r *http.Request) {
	p := s.mitmProxy.Load()
	if p == nil {
		writeErrStatus(w, http.StatusServiceUnavailable, mitmNotEnabled())
		return
	}
	ex, ok := p.Exchange(r.PathValue("id"))
	if !ok {
		writeErrStatus(w, http.StatusNotFound, fmt.Errorf("no such exchange %q", r.PathValue("id")))
		return
	}
	writeJSON(w, struct {
		mitm.Summary
		ReqHeaders  http.Header `json:"req_headers"`
		ReqBodyB64  string      `json:"req_body_b64"`
		RespHeaders http.Header `json:"resp_headers"`
		RespBodyB64 string      `json:"resp_body_b64"`
	}{
		Summary:     ex.Summary(),
		ReqHeaders:  ex.ReqHeaders,
		ReqBodyB64:  base64.StdEncoding.EncodeToString(ex.ReqBody),
		RespHeaders: ex.RespHeaders,
		RespBodyB64: base64.StdEncoding.EncodeToString(ex.RespBody),
	})
}

// spaHandler serves the built SPA and falls back to index.html for client routes.
func (s *Server) spaHandler() http.Handler {
	dir := s.cfg.WebDir
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(dir); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<html><body style="font-family:sans-serif;padding:2rem">
<h2>🐝 BeeEye 蜂眼 API is running</h2>
<p>The web UI has not been built yet. Run <code>cd BeeEye-web && npm install && npm run build</code>,
or in dev use <code>npm run dev</code> (proxied to this API).</p>
<p>Try <a href="/api/summary">/api/summary</a> or <a href="/api/devices">/api/devices</a>.</p>
</body></html>`))
			return
		}
		path := filepath.Join(dir, filepath.Clean(r.URL.Path))
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			http.ServeFile(w, r, path)
			return
		}
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrStatus(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func cors(h http.Handler) http.Handler {
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

func atoiDefault(s string, d int) int {
	if s == "" {
		return d
	}
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return d
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func topKeys(m map[string]int64, n int) []string {
	type kv struct {
		k string
		v int64
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	out := []string{}
	for i := 0; i < len(arr) && i < n; i++ {
		out = append(out, arr[i].k)
	}
	return out
}
