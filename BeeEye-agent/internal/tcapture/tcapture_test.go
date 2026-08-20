package tcapture

import (
	"net"
	"os"
	"testing"
	"time"

	"BeeEye/internal/live"
	"BeeEye/internal/pcapfile"
)

func ethFrame(dst, src net.HardwareAddr, payloadLen int) []byte {
	f := make([]byte, 14+payloadLen)
	copy(f[0:6], dst)
	copy(f[6:12], src)
	f[12], f[13] = 0x08, 0x00 // EtherType IPv4, contents don't matter for this test
	return f
}

func TestStartFeedsOnlyMatchingMAC(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, pcapfile.LinkEthernet, 65535)

	target := net.HardwareAddr{0x3c, 0x84, 0x6a, 0x11, 0x00, 0x02}
	other := net.HardwareAddr{0x02, 0x42, 0xbe, 0xee, 0x00, 0x01}
	gw := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	s, err := m.Start(target.String(), time.Minute, 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Matches as destination.
	m.Feed(live.Packet{TS: time.Now(), Data: ethFrame(target, gw, 20), OrigLen: 34})
	// Matches as source.
	m.Feed(live.Packet{TS: time.Now(), Data: ethFrame(gw, target, 20), OrigLen: 34})
	// Does not match either side — must not be counted.
	m.Feed(live.Packet{TS: time.Now(), Data: ethFrame(other, gw, 20), OrigLen: 34})

	st := s.Status()
	if st.Packets != 2 {
		t.Fatalf("packets = %d, want 2 (only frames touching the target MAC)", st.Packets)
	}
}

func TestByteCapClosesSession(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, pcapfile.LinkEthernet, 65535)
	target := net.HardwareAddr{0x3c, 0x84, 0x6a, 0x11, 0x00, 0x02}
	gw := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	s, err := m.Start(target.String(), time.Minute, 100) // tiny cap
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for i := 0; i < 5; i++ {
		m.Feed(live.Packet{TS: time.Now(), Data: ethFrame(target, gw, 60), OrigLen: 74})
	}
	st := s.Status()
	if !st.Done {
		t.Error("expected the session to be closed once it crossed max_bytes")
	}
	if st.Packets == 0 || st.Packets >= 5 {
		t.Errorf("packets = %d, want somewhere between 1 and 4 (stops once the cap is crossed)", st.Packets)
	}

	// The file on disk must be a valid, readable pcap even though the
	// session stopped mid-stream rather than via the deadline timer.
	f, err := os.Open(s.Path())
	if err != nil {
		t.Fatalf("open written file: %v", err)
	}
	defer f.Close()
	r, err := pcapfile.NewReader(f)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	n := 0
	for {
		if _, err := r.Next(); err != nil {
			break
		}
		n++
	}
	if int64(n) != st.Packets {
		t.Errorf("pcap file has %d records, status says %d packets", n, st.Packets)
	}
}

func TestDeadlineClosesSession(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, pcapfile.LinkEthernet, 65535)
	target := net.HardwareAddr{0x3c, 0x84, 0x6a, 0x11, 0x00, 0x02}

	s, err := m.Start(target.String(), 30*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if !s.Status().Done {
		t.Error("expected the session to be closed by its deadline timer even with no traffic")
	}
}

func TestStartRejectsInvalidMAC(t *testing.T) {
	m := NewManager(t.TempDir(), pcapfile.LinkEthernet, 65535)
	if _, err := m.Start("not-a-mac", time.Minute, 0); err == nil {
		t.Error("expected an error for a malformed MAC address")
	}
}

func TestListOrdersMostRecentFirst(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, pcapfile.LinkEthernet, 65535)
	macs := []string{"3c:84:6a:11:00:01", "3c:84:6a:11:00:02", "3c:84:6a:11:00:03"}
	for _, mac := range macs {
		if _, err := m.Start(mac, time.Minute, 0); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("got %d sessions, want 3", len(list))
	}
	if list[0].MAC != macs[2] || list[2].MAC != macs[0] {
		t.Errorf("List order = %v, want most-recently-started first", list)
	}
}
