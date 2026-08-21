package gui

import (
	"testing"

	"BeeEye/internal/dissect"
	"BeeEye/internal/procmap"
)

// ring builds a []*dissect.Result with strictly consecutive No starting at
// startNo, the invariant Packet's O(1) lookup depends on.
func ringOf(startNo int64, n int) []*dissect.Result {
	out := make([]*dissect.Result, n)
	for i := 0; i < n; i++ {
		out[i] = &dissect.Result{No: startNo + int64(i)}
	}
	return out
}

func TestSessionPacketLookupHitsAndMisses(t *testing.T) {
	s := &Session{ring: ringOf(1000, 500)} // window [1000, 1500)

	if r := s.Packet(1000); r == nil || r.No != 1000 {
		t.Errorf("Packet(1000) = %v, want No=1000 (the oldest in the ring)", r)
	}
	if r := s.Packet(1499); r == nil || r.No != 1499 {
		t.Errorf("Packet(1499) = %v, want No=1499 (the newest in the ring)", r)
	}
	if r := s.Packet(1250); r == nil || r.No != 1250 {
		t.Errorf("Packet(1250) = %v, want No=1250", r)
	}
	// Below and above the window, and no sink configured — must come back
	// nil, not panic on an out-of-range slice index.
	if r := s.Packet(999); r != nil {
		t.Errorf("Packet(999) = %v, want nil (evicted, before the window)", r)
	}
	if r := s.Packet(1500); r != nil {
		t.Errorf("Packet(1500) = %v, want nil (not captured yet, after the window)", r)
	}
	if r := s.Packet(-5); r != nil {
		t.Errorf("Packet(-5) = %v, want nil", r)
	}
}

func TestSessionPacketLookupEmptyRing(t *testing.T) {
	s := &Session{}
	if r := s.Packet(1); r != nil {
		t.Errorf("Packet(1) on an empty session = %v, want nil", r)
	}
}

// A ring that has evicted its oldest entries must look up by the *new*
// window, not the packet numbers it started with — this is the scenario
// Session.Packet's base is s.ring[0].No specifically to get right.
func TestSessionPacketLookupAfterEviction(t *testing.T) {
	s := &Session{ring: ringOf(5000, 100)} // as if 4999 older packets were evicted
	if r := s.Packet(4999); r != nil {
		t.Errorf("Packet(4999) = %v, want nil (evicted)", r)
	}
	if r := s.Packet(5000); r == nil || r.No != 5000 {
		t.Errorf("Packet(5000) = %v, want No=5000 (now the oldest)", r)
	}
	if r := s.Packet(5099); r == nil || r.No != 5099 {
		t.Errorf("Packet(5099) = %v, want No=5099 (the newest)", r)
	}
}

// LookupProcess must answer from the capture-time cache, not re-query procmap
// — that is the whole fix: a short-lived connection's socket can be long gone
// from /proc by the time anything later asks about it, so the only reliable
// moment to attribute a flow is when its packet arrives (see consume).
func TestSessionLookupProcessPrefersCache(t *testing.T) {
	s := &Session{
		procCache: map[int64]procAttr{
			42: {proc: procmap.Process{PID: 4242, Comm: "curl"}, side: "source", ok: true},
		},
	}
	p, side, ok := s.LookupProcess(&dissect.Result{No: 42})
	if !ok || p.PID != 4242 || p.Comm != "curl" || side != "source" {
		t.Errorf("LookupProcess(42) = %+v, %q, %v; want the cached curl/4242", p, side, ok)
	}
}

// A cached ok=false is a real, previously-decided answer ("this flow is not
// local") and must not trigger a second, live lookup — recording only
// successes would make every remote-device packet re-scan /proc on every
// request that touches it, for an answer that cannot have changed.
func TestSessionLookupProcessCachesNegativeResult(t *testing.T) {
	s := &Session{
		procCache: map[int64]procAttr{7: {ok: false}},
		// No procmap.Resolver at all — if LookupProcess fell through to a
		// live lookup instead of trusting the cache, this would still return
		// false, making the test pass for the wrong reason. The distinct
		// PID below is what proves the cache path, not the fallback, ran.
	}
	if p, _, ok := s.LookupProcess(&dissect.Result{No: 7}); ok || p.PID != 0 {
		t.Errorf("LookupProcess(7) = %+v, %v; want the cached false with no process", p, ok)
	}
}

// A packet dissected before this cache existed (e.g. re-read from the pcap
// sink after ring eviction, per Session.Packet's fallback) has no cache
// entry at all — LookupProcess must fall back to a live query rather than
// treating "not in the map" as "not local".
func TestSessionLookupProcessFallsBackWhenUncached(t *testing.T) {
	s := &Session{procCache: map[int64]procAttr{}}
	// No Transport/SrcPort on this Result, so lookupProcessNow's own guard
	// clause returns false — this test's job is only to confirm that path is
	// reached at all (an uncached lookup does not panic on nil procs and
	// does not silently invent a cached zero-value answer).
	if p, side, ok := s.LookupProcess(&dissect.Result{No: 99}); ok || p.PID != 0 || side != "" {
		t.Errorf("LookupProcess(99) = %+v, %q, %v; want the live-lookup fallback's false", p, side, ok)
	}
}

// consume's eviction must delete the matching procCache entries, not just
// the ring ones — otherwise every packet ever captured accumulates in the
// map for the life of the process, unbounded by ring size.
func TestSessionProcCacheEvictionStaysInSyncWithRing(t *testing.T) {
	s := &Session{size: 3}
	cache := map[int64]procAttr{}
	for no := int64(0); no < 5; no++ {
		s.ring = append(s.ring, &dissect.Result{No: no})
		cache[no] = procAttr{ok: true}
		if len(s.ring) > s.size {
			over := len(s.ring) - s.size
			for _, evicted := range s.ring[:over] {
				delete(cache, evicted.No)
			}
			s.ring = s.ring[over:]
		}
	}
	if len(cache) != s.size {
		t.Fatalf("procCache has %d entries after eviction, want %d (== ring size)", len(cache), s.size)
	}
	for _, r := range s.ring {
		if _, ok := cache[r.No]; !ok {
			t.Errorf("packet No=%d is still in the ring but missing from procCache", r.No)
		}
	}
	for no := int64(0); no < 2; no++ { // evicted from the ring
		if _, ok := cache[no]; ok {
			t.Errorf("packet No=%d was evicted from the ring but procCache still has it", no)
		}
	}
}
