package gui

import (
	"testing"

	"BeeEye/internal/dissect"
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
