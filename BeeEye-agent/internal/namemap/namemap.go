// Package namemap builds the IP ↔ name association from observed traffic
// (program.md F21: the domain ↔ IP ↔ device join).
//
// Nothing here queries anything. Every name is one this capture actually
// carried — a DNS answer, a TLS SNI, an HTTP Host header, an mDNS record — and
// each association records which of those it came from, because they are not
// equally trustworthy:
//
//	dns  — the resolver's answer; the strongest association
//	sni  — what the client asked for; strong, and present even without DNS
//	http — the Host header; strong for plaintext, absent otherwise
//	mdns — local service names; only meaningful on the LAN
//
// An address with no observed name stays nameless. Reverse-resolving it would
// mean sending the device's destinations to someone else's resolver, which is
// exactly what §3.5.5 rules out.
package namemap

import (
	"sort"
	"strings"
	"sync"
	"time"

	"BeeEye/internal/dissect"
)

// Source ranks how a name was learned, best first.
type Source string

const (
	SourceDNS  Source = "dns"
	SourceSNI  Source = "sni"
	SourceHTTP Source = "http"
	SourceMDNS Source = "mdns"
)

func rank(s Source) int {
	switch s {
	case SourceDNS:
		return 4
	case SourceSNI:
		return 3
	case SourceHTTP:
		return 2
	case SourceMDNS:
		return 1
	}
	return 0
}

// Name is one observed association.
type Name struct {
	Name   string    `json:"name"`
	Source Source    `json:"source"`
	Seen   time.Time `json:"seen"`
	Count  int       `json:"count"`
}

// Map holds every association learned so far.
type Map struct {
	mu    sync.RWMutex
	byIP  map[string]map[string]*Name // ip → name → record
	limit int
}

// New returns an empty map. limit caps how many addresses are remembered, so a
// long capture against a CDN cannot grow it without bound.
func New(limit int) *Map {
	if limit <= 0 {
		limit = 20000
	}
	return &Map{byIP: map[string]map[string]*Name{}, limit: limit}
}

// Learn extracts every association a dissected packet carries.
func (m *Map) Learn(r *dissect.Result) {
	if r == nil {
		return
	}

	// A DNS answer is the authoritative association: this name resolved to
	// these addresses, according to the resolver the device actually used.
	if r.HasProtocol("dns") || r.HasProtocol("mdns") {
		src := SourceDNS
		if r.HasProtocol("mdns") {
			src = SourceMDNS
		}
		if names := r.FieldValues("dns.qry.name"); len(names) > 0 {
			domain := names[0]
			for _, ip := range r.FieldValues("dns.a") {
				m.add(ip, domain, src, r.TS)
			}
			for _, ip := range r.FieldValues("dns.aaaa") {
				m.add(ip, domain, src, r.TS)
			}
		}
		// Answers whose owner name differs from the question (CNAME chains)
		// are recorded too — the address genuinely serves that name.
		if resp := r.FieldValues("dns.resp.name"); len(resp) > 0 {
			for _, ip := range r.FieldValues("dns.a") {
				m.add(ip, resp[len(resp)-1], src, r.TS)
			}
		}
	}

	// The SNI names the destination the client believed it was reaching, which
	// holds even when DNS happened before the capture started.
	if r.SNI != "" && r.Dst != "" {
		m.add(r.Dst, r.SNI, SourceSNI, r.TS)
	}

	if hosts := r.FieldValues("http.host"); len(hosts) > 0 && r.Dst != "" {
		// Strip any :port the Host header carried.
		host := hosts[0]
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		m.add(r.Dst, host, SourceHTTP, r.TS)
	}
}

func (m *Map) add(ip, name string, src Source, ts time.Time) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if ip == "" || name == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	names := m.byIP[ip]
	if names == nil {
		if len(m.byIP) >= m.limit {
			return // at capacity; keep what we have rather than thrash
		}
		names = map[string]*Name{}
		m.byIP[ip] = names
	}
	if n := names[name]; n != nil {
		n.Count++
		if ts.After(n.Seen) {
			n.Seen = ts
		}
		if rank(src) > rank(n.Source) {
			n.Source = src
		}
		return
	}
	names[name] = &Name{Name: name, Source: src, Seen: ts, Count: 1}
}

// Lookup returns the best name for an address, or "" if none was observed.
// Best means the strongest source; ties break toward the more frequently seen
// name, which on a shared CDN address is the one the device actually uses.
func (m *Map) Lookup(ip string) (string, Source) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	best := (*Name)(nil)
	for _, n := range m.byIP[ip] {
		if best == nil || rank(n.Source) > rank(best.Source) ||
			(rank(n.Source) == rank(best.Source) && n.Count > best.Count) {
			best = n
		}
	}
	if best == nil {
		return "", ""
	}
	return best.Name, best.Source
}

// All returns every name observed for an address, best first — a single IP
// often serves many names, and collapsing that to one would hide it.
func (m *Map) All(ip string) []Name {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Name, 0, len(m.byIP[ip]))
	for _, n := range m.byIP[ip] {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank(out[i].Source) != rank(out[j].Source) {
			return rank(out[i].Source) > rank(out[j].Source)
		}
		return out[i].Count > out[j].Count
	})
	return out
}

// Size reports how many addresses have at least one name.
func (m *Map) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byIP)
}

// Snapshot returns the whole association table, for the UI's name view.
type Entry struct {
	IP    string `json:"ip"`
	Names []Name `json:"names"`
}

func (m *Map) Snapshot() []Entry {
	m.mu.RLock()
	ips := make([]string, 0, len(m.byIP))
	for ip := range m.byIP {
		ips = append(ips, ip)
	}
	m.mu.RUnlock()

	out := make([]Entry, 0, len(ips))
	for _, ip := range ips {
		out = append(out, Entry{IP: ip, Names: m.All(ip)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
