package threatintel

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"BeeEye/internal/detect"
)

const sampleDROP = `; Spamhaus DROP List 2026/08/19
; https://www.spamhaus.org/drop/drop.txt
1.10.16.0/20 ; SBL256894
2.56.192.0/22 ; SBL459831
not-a-cidr-or-ip ; malformed, must be skipped
`

func TestParseList(t *testing.T) {
	cidrs, ips := parseList(strings.NewReader(sampleDROP))
	if len(cidrs) != 2 {
		t.Fatalf("got %d CIDRs, want 2 (malformed line must be skipped, not abort the feed): %v", len(cidrs), cidrs)
	}
	if len(ips) != 0 {
		t.Fatalf("got %d bare IPs, want 0", len(ips))
	}
	if cidrs[0].String() != "1.10.16.0/20" {
		t.Errorf("first CIDR = %s, want 1.10.16.0/20", cidrs[0])
	}
}

func TestStoreFetchAndSnapshot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sampleDROP)
	}))
	defer srv.Close()

	base := detect.ThreatIntel{
		BadIPs:     map[string]bool{"45.13.34.7": true},
		BadDomains: map[string]bool{"malware-c2.example": true},
		BadJA3:     map[string]bool{},
	}
	dir := t.TempDir()
	s := NewStore(dir, []Feed{{Name: "test_feed", URL: srv.URL}}, time.Hour, base)

	updated := make(chan detect.ThreatIntel, 1)
	s.OnUpdate(func(ti detect.ThreatIntel) { updated <- ti })
	s.Start()

	select {
	case snap := <-updated:
		if len(snap.BadCIDRs) != 2 {
			t.Fatalf("snapshot has %d CIDRs, want 2", len(snap.BadCIDRs))
		}
		if !snap.BadIPs["45.13.34.7"] {
			t.Error("base entry must survive a feed merge")
		}
		if !snap.BadDomains["malware-c2.example"] {
			t.Error("base domain entry must survive a feed merge")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the first refresh")
	}

	// The cache file must exist so a restart with no network still has data.
	if _, err := os.Stat(filepath.Join(dir, "test_feed.txt")); err != nil {
		t.Errorf("expected a cache file, got error: %v", err)
	}
}

func TestStoreLoadsCacheWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	// Seed the cache as if a previous run had fetched it.
	seed := NewStore(dir, nil, time.Hour, detect.ThreatIntel{})
	seed.saveCache(Feed{Name: "test_feed"}, mustCIDRs(t, "5.42.92.0/23"), nil)

	// Point the feed at an address that refuses connections, so the only way
	// this store has data is the on-disk cache.
	s := NewStore(dir, []Feed{{Name: "test_feed", URL: "http://127.0.0.1:1"}}, time.Hour, detect.ThreatIntel{})
	s.loadCache()
	snap := s.Snapshot()
	if len(snap.BadCIDRs) != 1 || snap.BadCIDRs[0].String() != "5.42.92.0/23" {
		t.Errorf("snapshot after loadCache = %v, want [5.42.92.0/23]", snap.BadCIDRs)
	}
}

func mustCIDRs(t *testing.T, s string) []*net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return []*net.IPNet{n}
}
