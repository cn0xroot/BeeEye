// Package threatintel pulls public IP blocklists into detect.ThreatIntel
// (program.md F29), replacing the previous "the caller injects everything"
// design with a real, periodically-refreshed source.
//
// The feeds are the plain-text lists blocklist operators actually publish —
// no API key, no signup, one HTTP GET. A fetch failure (offline host, feed
// down) never blocks capture: Start loads whatever was cached on the previous
// successful fetch and keeps using it, logging a warning instead of an error.
package threatintel

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"BeeEye/internal/detect"
)

// Feed is one public blocklist source.
type Feed struct {
	Name string
	URL  string
}

// KnownFeeds are the sources understood by name in config.yaml's
// threat_intel.feeds list.
var KnownFeeds = map[string]Feed{
	// Spamhaus DROP: hijacked / bulletproof-hosted netblocks spammers and
	// botnets operate from. Free for this kind of defensive use, no auth,
	// refreshed by Spamhaus roughly daily — the "3600h TTL" of program.md
	// F29 in practice. EDROP was merged into DROP in 2026 so it is not
	// listed separately here.
	"spamhaus_drop": {Name: "spamhaus_drop", URL: "https://www.spamhaus.org/drop/drop.txt"},
}

// FeedsByName resolves configured feed names, skipping (and logging) any
// name that is not in KnownFeeds rather than failing startup over a typo.
func FeedsByName(names []string) []Feed {
	out := make([]Feed, 0, len(names))
	for _, n := range names {
		f, ok := KnownFeeds[n]
		if !ok {
			log.Printf("threatintel: unknown feed %q, skipping", n)
			continue
		}
		out = append(out, f)
	}
	return out
}

// parseList reads a DROP-style list: comment lines start with ';' or '#',
// data lines are "<CIDR-or-IP> ; <reference>". A line that fails to parse is
// skipped — one bad line must not drop the rest of a 47000-entry feed.
func parseList(r io.Reader) (cidrs []*net.IPNet, ips []string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		field := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		if field == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(field); err == nil {
			cidrs = append(cidrs, n)
			continue
		}
		if ip := net.ParseIP(field); ip != nil {
			ips = append(ips, ip.String())
		}
	}
	return cidrs, ips
}

// Store owns the live threat-intel snapshot: a fixed base (hand-injected /
// demo entries) merged with whatever the configured feeds last returned.
type Store struct {
	base     detect.ThreatIntel
	feeds    []Feed
	cacheDir string
	interval time.Duration
	client   *http.Client

	mu    sync.RWMutex
	cidrs []*net.IPNet
	ips   map[string]bool

	onUpdate func(detect.ThreatIntel)
}

// NewStore builds a Store. base carries hand-injected entries (e.g. the demo
// C2 IP/domain) that stay in the snapshot regardless of feed state; cacheDir
// is where each feed's last-good copy is written so a restart with no
// network still has yesterday's list instead of an empty one.
func NewStore(cacheDir string, feeds []Feed, interval time.Duration, base detect.ThreatIntel) *Store {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &Store{
		base:     base,
		feeds:    feeds,
		cacheDir: cacheDir,
		interval: interval,
		client:   &http.Client{Timeout: 20 * time.Second},
		ips:      map[string]bool{},
	}
}

// OnUpdate registers a callback fired after every successful refresh cycle
// with the new snapshot, so a long-running consumer (the detection engine)
// can pick up fresh entries without restarting.
func (s *Store) OnUpdate(fn func(detect.ThreatIntel)) { s.onUpdate = fn }

// Start loads the on-disk cache synchronously (fast, no network) so the
// first Snapshot() after Start returns is never empty just because the feed
// fetch hasn't finished, then begins refreshing in the background. It does
// not block on the network — call sites must not wait for it.
func (s *Store) Start() {
	s.loadCache()
	go s.refreshLoop()
}

func (s *Store) refreshLoop() {
	s.refreshOnce()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for range t.C {
		s.refreshOnce()
	}
}

func (s *Store) refreshOnce() {
	if len(s.feeds) == 0 {
		return
	}
	var allCIDRs []*net.IPNet
	allIPs := map[string]bool{}
	ok := false
	for _, f := range s.feeds {
		cidrs, ips, err := s.fetch(f)
		if err != nil {
			log.Printf("threatintel: %s refresh failed (%v), keeping last cached copy", f.Name, err)
			continue
		}
		ok = true
		allCIDRs = append(allCIDRs, cidrs...)
		for _, ip := range ips {
			allIPs[ip] = true
		}
		s.saveCache(f, cidrs, ips)
	}
	if !ok {
		return // every feed failed this round — s.cidrs/s.ips (cache or last good) stay as-is
	}
	s.mu.Lock()
	s.cidrs = allCIDRs
	s.ips = allIPs
	s.mu.Unlock()
	log.Printf("threatintel: refreshed %d CIDR ranges, %d IPs from %d feed(s)", len(allCIDRs), len(allIPs), len(s.feeds))
	if s.onUpdate != nil {
		s.onUpdate(s.Snapshot())
	}
}

func (s *Store) fetch(f Feed) ([]*net.IPNet, []string, error) {
	req, err := http.NewRequest(http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	cidrs, ips := parseList(resp.Body)
	if len(cidrs)+len(ips) == 0 {
		return nil, nil, fmt.Errorf("feed returned zero usable entries")
	}
	return cidrs, ips, nil
}

func (s *Store) cachePath(name string) string {
	return filepath.Join(s.cacheDir, name+".txt")
}

func (s *Store) saveCache(f Feed, cidrs []*net.IPNet, ips []string) {
	if s.cacheDir == "" {
		return
	}
	if err := os.MkdirAll(s.cacheDir, 0o755); err != nil {
		log.Printf("threatintel: cache dir: %v", err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; BeeEye threatintel cache — %s — fetched %s\n", f.Name, time.Now().Format(time.RFC3339))
	for _, n := range cidrs {
		fmt.Fprintln(&b, n.String())
	}
	for _, ip := range ips {
		fmt.Fprintln(&b, ip)
	}
	if err := os.WriteFile(s.cachePath(f.Name), []byte(b.String()), 0o644); err != nil {
		log.Printf("threatintel: write cache for %s: %v", f.Name, err)
	}
}

// loadCache reads whatever is on disk from a previous run, best-effort — a
// missing or corrupt cache file just means an empty feed until the first
// successful refresh, never an error.
func (s *Store) loadCache() {
	if s.cacheDir == "" {
		return
	}
	var cidrs []*net.IPNet
	ips := map[string]bool{}
	for _, f := range s.feeds {
		b, err := os.ReadFile(s.cachePath(f.Name))
		if err != nil {
			continue
		}
		c, i := parseList(strings.NewReader(string(b)))
		cidrs = append(cidrs, c...)
		for _, ip := range i {
			ips[ip] = true
		}
	}
	if len(cidrs)+len(ips) == 0 {
		return
	}
	s.mu.Lock()
	s.cidrs = cidrs
	s.ips = ips
	s.mu.Unlock()
	log.Printf("threatintel: loaded %d CIDR ranges, %d IPs from local cache", len(cidrs), len(ips))
}

// Snapshot returns the current merged threat intel: base entries plus
// whatever the feeds last successfully returned (or the on-disk cache, or
// nothing, in that order of preference). Safe for concurrent use.
func (s *Store) Snapshot() detect.ThreatIntel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := detect.ThreatIntel{
		BadIPs:     map[string]bool{},
		BadDomains: map[string]bool{},
		BadJA3:     map[string]bool{},
		BadCIDRs:   append([]*net.IPNet(nil), s.cidrs...),
	}
	for k := range s.base.BadIPs {
		out.BadIPs[k] = true
	}
	for k := range s.ips {
		out.BadIPs[k] = true
	}
	for k := range s.base.BadDomains {
		out.BadDomains[k] = true
	}
	for k := range s.base.BadJA3 {
		out.BadJA3[k] = true
	}
	return out
}
