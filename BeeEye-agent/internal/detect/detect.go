// Package detect implements the post-intrusion behavioral detectors and the
// multi-signal weighted risk model (program.md §3.11).
//
// All detectors operate purely on the connections / dns_records tables — no
// extra capture capability is required (§3.11 opening note). Every detector is
// a pure function over its inputs so it can be unit-tested against synthetic
// traffic (see detect_test.go).
package detect

import (
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"BeeEye/internal/config"
	"BeeEye/internal/geoip"
	"BeeEye/internal/model"
)

// Signal weights from program.md §3.11.5. Kept as a map so they are config-like
// rather than hardcoded at call sites.
var SignalWeights = map[string]int{
	"threat_intel":       50,
	"lateral":            40,
	"fanout":             30,
	"beacon":             25,
	"dns_anomaly":        20,
	"ja3_mismatch":       15,
	"first_target":       10,
	"geo_anomaly":        10,
	"baseline_deviation": 15,
	"offhours":           5,
}

// ThreatIntel holds offline blocklists (program.md F29). BadIPs/BadDomains/
// BadJA3 are exact-match sets (hand-injected or learned); BadCIDRs holds the
// network ranges a public feed publishes (internal/threatintel) — a single
// hijacked /20 is one CIDR entry, not thousands of individual IPs.
type ThreatIntel struct {
	BadIPs     map[string]bool
	BadDomains map[string]bool
	BadJA3     map[string]bool
	BadCIDRs   []*net.IPNet
}

// MatchIP reports whether ip is covered by an exact entry or a CIDR range,
// and a human-readable string naming what matched (the IP itself, or the
// covering CIDR) for the event detail.
func (t ThreatIntel) MatchIP(ip string) (string, bool) {
	if t.BadIPs[ip] {
		return ip, true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	for _, n := range t.BadCIDRs {
		if n != nil && n.Contains(parsed) {
			return n.String(), true
		}
	}
	return "", false
}

// Subject is the (device, remote target) pair a risk score is computed for.
type Subject struct {
	MAC   string
	DstIP string
}

// Signal is one contributing weak indicator (§3.11.5).
type Signal struct {
	Key    string         `json:"key"`
	Weight int            `json:"weight"`
	Detail map[string]any `json:"detail"`
}

// Engine runs all detectors and produces weighted-scored events.
type Engine struct {
	Cfg   *config.Detection
	Intel ThreatIntel
	Cats  map[string]model.DeviceCategory // mac → category
}

// fanoutThresholds returns (uniqueDstIP, uniquePortPerIP) alarm thresholds by
// category (program.md §3.11.3).
func fanoutThresholds(cat model.DeviceCategory) (int, int) {
	switch cat {
	case model.CatLock, model.CatCamera:
		return 5, 3
	case model.CatNAS, model.CatRouter:
		return 20, 10
	default:
		return 50, 15
	}
}

// BaselineHit is a device whose traffic volume this hour is a statistical
// outlier against its own history in that hour-of-day bucket (F10).
type BaselineHit struct {
	Hour       int
	ValueBytes float64
	MeanBytes  float64
	StdDevKB   float64
	Z          float64
}

// Baseline learns, per device and hour-of-day, a distribution of bytes
// transferred in that hour across the days seen in conns, and flags today's
// value for the *current* hour as an outlier when it is more than
// Cfg.Baseline.ZThreshold standard deviations from that device's own mean —
// e.g. a NAS that only ever talks 09:00–18:00 suddenly active at 03:00.
//
// This stays a pure function over conns like every other detector here (see
// the package doc): there is no persisted model, so a restart costs the
// learned baseline, exactly like the rest of the engine's state. conns is
// already the full rolling window the caller queries from the store, so
// recomputing the distribution on every call is the same O(n) shape as
// Beacon/Fanout, not new overhead.
func (e *Engine) Baseline(conns []model.Connection, now time.Time) map[Subject]BaselineHit {
	type key struct {
		mac  string
		hour int
	}
	// perDayBytes[key][day] = bytes that device sent/received in that
	// hour-of-day, on that calendar day.
	perDayBytes := map[key]map[string]int64{}
	for _, c := range conns {
		k := key{c.MAC, c.TS.Hour()}
		day := c.TS.Format("2006-01-02")
		if perDayBytes[k] == nil {
			perDayBytes[k] = map[string]int64{}
		}
		perDayBytes[k][day] += c.Bytes
	}

	minDays := e.Cfg.Baseline.MinDays
	if minDays <= 0 {
		minDays = 5
	}
	zThresh := e.Cfg.Baseline.ZThreshold
	if zThresh <= 0 {
		zThresh = 3.0
	}
	minStdDev := e.Cfg.Baseline.MinStdDevKB * 1024

	curHour := now.Hour()
	curDay := now.Format("2006-01-02")

	out := map[Subject]BaselineHit{}
	for k, days := range perDayBytes {
		if k.hour != curHour {
			continue // only ever score "this hour" against its own history
		}
		today, hasToday := days[curDay]
		if !hasToday {
			continue
		}
		// Welford's online mean/variance over every *other* day seen in this
		// hour-bucket — today must not be part of its own baseline.
		var mean, m2, n float64
		for day, b := range days {
			if day == curDay {
				continue
			}
			n++
			delta := float64(b) - mean
			mean += delta / n
			m2 += delta * (float64(b) - mean)
		}
		if n < float64(minDays) {
			continue
		}
		stddev := math.Sqrt(m2 / n)
		if stddev < minStdDev {
			stddev = minStdDev
		}
		z := (float64(today) - mean) / stddev
		if math.Abs(z) >= zThresh {
			out[Subject{MAC: k.mac}] = BaselineHit{
				Hour: k.hour, ValueBytes: float64(today), MeanBytes: mean,
				StdDevKB: stddev / 1024, Z: z,
			}
		}
	}
	return out
}

// Analyze runs the full pipeline over a batch of connections + DNS records and
// returns the events to persist. baselinePairs is the set of (mac|dstIP) pairs
// considered "already known" for first-target detection (§3.11.1).
func (e *Engine) Analyze(conns []model.Connection, dns []model.DNSRecord, baselinePairs map[string]bool) []model.Event {
	signals := map[Subject][]Signal{}
	add := func(mac, dst, key string, detail map[string]any) {
		s := Subject{MAC: mac, DstIP: dst}
		signals[s] = append(signals[s], Signal{Key: key, Weight: SignalWeights[key], Detail: detail})
	}

	// --- threat intel (F29) ---
	for _, c := range conns {
		if matched, ok := e.Intel.MatchIP(c.DstIP); ok {
			add(c.MAC, c.DstIP, "threat_intel", map[string]any{"matched": matched, "kind": "ip"})
		}
		if c.JA3 != "" && e.Intel.BadJA3[c.JA3] {
			add(c.MAC, c.DstIP, "threat_intel", map[string]any{"matched": c.JA3, "kind": "ja3"})
		}
	}
	for _, r := range dns {
		if e.Intel.BadDomains[strings.ToLower(r.Domain)] {
			// map to any connection dst; attribute at device level
			add(r.MAC, "", "threat_intel", map[string]any{"matched": r.Domain, "kind": "domain"})
		}
	}

	// --- beaconing (F35) ---
	for sub, hit := range e.Beacon(conns) {
		add(sub.MAC, sub.DstIP, "beacon", map[string]any{
			"interval_s": round1(hit.MeanInterval), "cv": round3(hit.CV), "count": hit.Count})
	}

	// --- behavioral baseline (F10) ---
	for sub, hit := range e.Baseline(conns, time.Now()) {
		add(sub.MAC, "", "baseline_deviation", map[string]any{
			"hour": hit.Hour, "z_score": round3(hit.Z),
			"value_kb": round1(hit.ValueBytes / 1024), "mean_kb": round1(hit.MeanBytes / 1024),
			"stddev_kb": round1(hit.StdDevKB)})
	}

	// --- fanout / scan (F36) ---
	for _, f := range e.Fanout(conns) {
		add(f.MAC, "", "fanout", map[string]any{
			"unique_dst_ip": f.UniqueDstIP, "unique_ports": f.MaxUniquePorts, "window": "5m"})
	}

	// --- lateral / east-west (F34) ---
	for _, l := range e.Lateral(conns) {
		add(l.MAC, l.DstIP, "lateral", map[string]any{
			"dst_ip": l.DstIP, "port": l.Port, "service": l.Service})
	}

	// --- DNS anomaly / DGA (F33) ---
	for mac, d := range e.DNSAnomaly(dns) {
		add(mac, "", "dns_anomaly", map[string]any{
			"nxdomain": d.NXDomain, "mean_entropy": round3(d.MeanEntropy)})
	}

	// --- first-target (§3.11.1) ---
	for _, c := range conns {
		if geoip.IsPrivateStr(c.DstIP) {
			continue
		}
		key := c.MAC + "|" + c.DstIP
		if !baselinePairs[key] {
			add(c.MAC, c.DstIP, "first_target", map[string]any{"dst_ip": c.DstIP})
		}
	}

	// --- geo anomaly (F28) & off-hours (§3.11.5) ---
	for _, c := range conns {
		if !geoip.IsPrivateStr(c.DstIP) {
			g := geoip.Lookup(c.DstIP)
			if g.Country == "RU" || g.Country == "??" { // demo: flag high-risk/unknown geo
				add(c.MAC, c.DstIP, "geo_anomaly", map[string]any{"country": g.Country})
			}
		}
		h := c.TS.Hour()
		if h >= 1 && h <= 5 { // 01:00–05:00 quiet hours
			add(c.MAC, c.DstIP, "offhours", map[string]any{"hour": h})
		}
	}

	return e.score(signals)
}

// score collapses signals per subject into weighted risk events (§3.11.5).
func (e *Engine) score(signals map[Subject][]Signal) []model.Event {
	var out []model.Event
	for sub, sigs := range signals {
		// de-dup identical signal keys per subject, keep max weight instance
		best := map[string]Signal{}
		for _, s := range sigs {
			if ex, ok := best[s.Key]; !ok || s.Weight > ex.Weight {
				best[s.Key] = s
			}
		}
		total := 0
		var keys []string
		detail := map[string]any{}
		for k, s := range best {
			total += s.Weight
			keys = append(keys, k)
			detail[k] = s.Detail
		}
		sort.Strings(keys)

		sev := e.level(total)
		if sev == "" {
			continue // score < low threshold → not alarmed (§3.11.5)
		}
		detail["dst_ip"] = sub.DstIP
		etype := primaryEventType(best)
		out = append(out, model.Event{
			TS:        time.Now(),
			MAC:       sub.MAC,
			EventType: etype,
			Severity:  sev,
			RiskScore: total,
			Detail:    detail,
			Signals:   keys,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RiskScore > out[j].RiskScore })
	return out
}

// level maps a score to a severity using configured thresholds (§3.11.5).
func (e *Engine) level(score int) model.Severity {
	switch {
	case score >= e.Cfg.RiskThresholds.High:
		return model.SevHigh
	case score >= e.Cfg.RiskThresholds.Medium:
		return model.SevMedium
	case score >= e.Cfg.RiskThresholds.Low:
		return model.SevLow
	default:
		return ""
	}
}

// primaryEventType picks the highest-weight signal as the headline event type.
func primaryEventType(best map[string]Signal) string {
	top, topW := "anomaly", -1
	for k, s := range best {
		if s.Weight > topW {
			top, topW = k, s.Weight
		}
	}
	return top
}

// ---------------- individual detectors ----------------

// BeaconHit is a suspected C2 heartbeat (§3.11.2).
type BeaconHit struct {
	Count        int
	MeanInterval float64 // seconds
	CV           float64
}

// Beacon detects regular-interval callbacks per (mac, dstIP) using the CV test.
func (e *Engine) Beacon(conns []model.Connection) map[Subject]BeaconHit {
	byPair := map[Subject][]time.Time{}
	for _, c := range conns {
		if c.DstPort == 123 || c.Service == "NTP" { // NTP whitelist (§3.11.2)
			continue
		}
		if geoip.IsPrivateStr(c.DstIP) {
			continue
		}
		s := Subject{MAC: c.MAC, DstIP: c.DstIP}
		byPair[s] = append(byPair[s], c.TS)
	}
	out := map[Subject]BeaconHit{}
	for sub, ts := range byPair {
		if len(ts) < e.Cfg.Beacon.MinSamples {
			continue
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		var deltas []float64
		for i := 1; i < len(ts); i++ {
			deltas = append(deltas, ts[i].Sub(ts[i-1]).Seconds())
		}
		mean, cv := meanCV(deltas)
		if mean < e.Cfg.Beacon.MinIntervalS || mean > e.Cfg.Beacon.MaxIntervalS {
			continue
		}
		if cv < e.Cfg.Beacon.CVThreshold {
			out[sub] = BeaconHit{Count: len(ts), MeanInterval: mean, CV: cv}
		}
	}
	return out
}

// FanoutHit is a suspected scan / DDoS-participation source (§3.11.3).
type FanoutHit struct {
	MAC            string
	UniqueDstIP    int
	MaxUniquePorts int
}

// Fanout flags devices exceeding per-category thresholds in any 5-minute window.
func (e *Engine) Fanout(conns []model.Connection) []FanoutHit {
	byMAC := map[string][]model.Connection{}
	for _, c := range conns {
		byMAC[c.MAC] = append(byMAC[c.MAC], c)
	}
	var out []FanoutHit
	const window = 5 * time.Minute
	for mac, cs := range byMAC {
		sort.Slice(cs, func(i, j int) bool { return cs[i].TS.Before(cs[j].TS) })
		ipThresh, portThresh := fanoutThresholds(e.Cats[mac])
		maxIPs, maxPorts := 0, 0
		// sliding window
		for i := range cs {
			ips := map[string]bool{}
			portsPerIP := map[string]map[int]bool{}
			for j := i; j < len(cs) && cs[j].TS.Sub(cs[i].TS) <= window; j++ {
				ips[cs[j].DstIP] = true
				if portsPerIP[cs[j].DstIP] == nil {
					portsPerIP[cs[j].DstIP] = map[int]bool{}
				}
				portsPerIP[cs[j].DstIP][cs[j].DstPort] = true
			}
			if len(ips) > maxIPs {
				maxIPs = len(ips)
			}
			for _, p := range portsPerIP {
				if len(p) > maxPorts {
					maxPorts = len(p)
				}
			}
		}
		if maxIPs > ipThresh || maxPorts > portThresh {
			out = append(out, FanoutHit{MAC: mac, UniqueDstIP: maxIPs, MaxUniquePorts: maxPorts})
		}
	}
	return out
}

// LateralHit is an east-west intranet connection of concern (§3.11.4).
type LateralHit struct {
	MAC     string
	DstIP   string
	Port    int
	Service string
}

// mgmtPorts are management/service ports that "dumb" IoT devices should never
// initiate to another intranet host (§3.11.4).
var mgmtPorts = map[int]bool{22: true, 23: true, 80: true, 445: true, 3389: true, 8080: true, 139: true}

// dumbCats are devices with no legitimate reason to scan the LAN.
func dumbCat(c model.DeviceCategory) bool {
	switch c {
	case model.CatCamera, model.CatLock, model.CatFridge, model.CatSpeaker, model.CatTV:
		return true
	}
	return false
}

// Lateral flags intranet→intranet connections from dumb devices to mgmt ports.
func (e *Engine) Lateral(conns []model.Connection) []LateralHit {
	seen := map[string]bool{}
	var out []LateralHit
	for _, c := range conns {
		if !c.Internal {
			continue
		}
		if !mgmtPorts[c.DstPort] {
			continue
		}
		if !dumbCat(e.Cats[c.MAC]) {
			continue // e.g. a laptop hitting the router admin page is normal
		}
		key := c.MAC + "|" + c.DstIP + "|" + itoa(c.DstPort)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, LateralHit{MAC: c.MAC, DstIP: c.DstIP, Port: c.DstPort, Service: c.Service})
	}
	return out
}

// DNSAnomalyHit summarizes suspicious DNS behavior per device (§3.11 / F33).
type DNSAnomalyHit struct {
	NXDomain    int
	MeanEntropy float64
}

// DNSAnomaly flags high NXDOMAIN counts and high-entropy (DGA-like) domains.
func (e *Engine) DNSAnomaly(dns []model.DNSRecord) map[string]DNSAnomalyHit {
	type acc struct {
		nx      int
		entropy []float64
	}
	byMAC := map[string]*acc{}
	for _, r := range dns {
		a := byMAC[r.MAC]
		if a == nil {
			a = &acc{}
			byMAC[r.MAC] = a
		}
		if r.RCode == "NXDOMAIN" {
			a.nx++
		}
		a.entropy = append(a.entropy, domainEntropy(r.Domain))
	}
	out := map[string]DNSAnomalyHit{}
	for mac, a := range byMAC {
		me := meanF(a.entropy)
		// DGA heuristic: many NXDOMAINs OR consistently high-entropy labels.
		if a.nx >= 5 || (me >= 3.6 && len(a.entropy) >= 5) {
			out[mac] = DNSAnomalyHit{NXDomain: a.nx, MeanEntropy: me}
		}
	}
	return out
}

// ---------------- math helpers ----------------

func meanCV(xs []float64) (mean, cv float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	if mean == 0 {
		return 0, 0
	}
	var variance float64
	for _, x := range xs {
		variance += (x - mean) * (x - mean)
	}
	variance /= float64(len(xs))
	cv = math.Sqrt(variance) / mean
	return mean, cv
}

func meanF(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

// domainEntropy computes Shannon entropy over the second-level label — the core
// DGA signal (random-looking domains have high entropy).
func domainEntropy(domain string) float64 {
	label := domain
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) >= 2 {
		label = parts[len(parts)-2] // second-level label
	}
	if label == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range label {
		freq[r]++
	}
	n := float64(len(label))
	var h float64
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

func itoa(i int) string {
	// small helper to avoid importing strconv at call sites above
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
