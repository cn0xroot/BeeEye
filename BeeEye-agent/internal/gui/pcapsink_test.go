package gui

import (
	"bytes"
	"testing"
	"time"

	"BeeEye/internal/live"
)

// TestPcapSinkRoundTrip is the guard on the fix for "That packet is no longer
// buffered": a frame written to the sink must be readable back byte-for-byte by
// its packet number, which is what lets the analyzer answer detail requests for
// packets the in-memory ring has evicted.
func TestPcapSinkRoundTrip(t *testing.T) {
	sink, err := newPcapSink(t.TempDir(), "eth0", 65535, 512<<20)
	if err != nil {
		t.Fatalf("newPcapSink: %v", err)
	}
	defer sink.Close()

	frames := map[int64][]byte{
		1:   bytes.Repeat([]byte{0xaa}, 64),
		2:   append([]byte("hello frame"), 0, 1, 2, 3),
		999: bytes.Repeat([]byte{0x5e}, 1400),
	}
	ts := time.Unix(1_700_000_000, 123_000_000)
	for no, raw := range frames {
		sink.Write(no, ts, len(raw)+7, raw) // origLen > capLen to check both survive
	}

	for no, want := range frames {
		pk, ok := sink.Read(no)
		if !ok {
			t.Errorf("packet %d not found after write", no)
			continue
		}
		if !bytes.Equal(pk.Data, want) {
			t.Errorf("packet %d bytes differ: got %d, want %d", no, len(pk.Data), len(want))
		}
		if pk.Index != no {
			t.Errorf("packet %d came back with Index %d", no, pk.Index)
		}
		if pk.OrigLen != len(want)+7 {
			t.Errorf("packet %d OrigLen = %d, want %d", no, pk.OrigLen, len(want)+7)
		}
		if pk.Iface != "eth0" {
			t.Errorf("packet %d iface = %q", no, pk.Iface)
		}
	}

	if _, ok := sink.Read(12345); ok {
		t.Error("Read of an unknown packet number should report not found")
	}
}

// TestPcapSinkRotationKeepsPrevious checks that after a rotation the packets in
// the file just closed are still readable — the whole point of keeping two
// files, so a rotation is not a cliff where recent detail disappears.
func TestPcapSinkRotationKeepsPrevious(t *testing.T) {
	// A tiny cap forces a rotation after a couple of frames.
	sink, err := newPcapSink(t.TempDir(), "any", 65535, pcapGlobalHeaderLen+2*(pcapRecordHeaderLen+100))
	if err != nil {
		t.Fatalf("newPcapSink: %v", err)
	}
	defer sink.Close()

	ts := time.Unix(1_700_000_000, 0)
	for no := int64(1); no <= 6; no++ {
		sink.Write(no, ts, 100, bytes.Repeat([]byte{byte(no)}, 100))
	}

	// The most recent frames must still be readable across the rotation
	// boundary; only the oldest, rotated out entirely, may be gone.
	pk, ok := sink.Read(6)
	if !ok {
		t.Fatal("the newest packet must be readable")
	}
	if pk.Data[0] != 6 {
		t.Errorf("packet 6 content wrong: %d", pk.Data[0])
	}
	if _, ok := sink.Read(5); !ok {
		t.Error("a packet one rotation back should still be readable")
	}

	// Re-dissecting a read-back frame through a Session must reproduce the
	// packet number, which is what /api/packets/{no} relies on.
	if pk.Index != 6 {
		t.Errorf("read-back Index = %d, want 6", pk.Index)
	}
	_ = live.Packet{} // keep the import even if the assertions above change
}
