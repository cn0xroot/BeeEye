//go:build linux

package ebpf

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestAttachLoopback exercises the whole kernel path end to end: load, attach
// both directions to an interface, generate traffic, and decode what comes back
// out of the ringbuf. It needs CAP_BPF/CAP_NET_ADMIN, so it skips when not run
// as root rather than failing an unprivileged `go test ./...`.
func TestAttachLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF + CAP_NET_ADMIN) to load and attach")
	}
	l, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()

	if err := l.SetIntervals(100*time.Millisecond, 50*time.Millisecond); err != nil {
		t.Fatalf("SetIntervals: %v", err)
	}
	if err := l.AttachInterface("lo"); err != nil {
		t.Fatalf("AttachInterface(lo): %v", err)
	}

	events := l.Events()

	// A UDP datagram to port 53 on loopback must surface as a DNS event with
	// its payload intact — that is the F21 path in miniature.
	go func() {
		for i := 0; i < 20; i++ {
			c, err := net.Dial("udp", "127.0.0.1:53")
			if err != nil {
				return
			}
			// A minimal DNS query header + QNAME "test".
			c.Write([]byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
				4, 't', 'e', 's', 't', 0, 0, 1, 0, 1})
			c.Close()
			time.Sleep(20 * time.Millisecond)
		}
	}()

	deadline := time.After(6 * time.Second)
	var sawDNS, sawAny bool
	for !sawDNS {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatal("event channel closed early")
			}
			sawAny = true
			if ev.Kind == KindDNS && ev.DstPort == 53 {
				if len(ev.Payload) < 12 {
					t.Errorf("DNS event payload too short: %d bytes", len(ev.Payload))
				} else if ev.Payload[0] != 0xab || ev.Payload[1] != 0xcd {
					t.Errorf("DNS payload does not match what was sent: % x", ev.Payload[:4])
				}
				if ev.IfIndex == 0 {
					t.Error("event carries no ifindex (F17 needs it)")
				}
				if got := l.IfaceName(ev.IfIndex); got != "lo" {
					t.Errorf("IfaceName(%d) = %q, want lo", ev.IfIndex, got)
				}
				sawDNS = true
			}
		case <-deadline:
			t.Fatalf("no DNS event within 6s (saw other events: %v)", sawAny)
		}
	}

	counters, err := l.DeviceCounters()
	if err != nil {
		t.Fatalf("DeviceCounters: %v", err)
	}
	if len(counters) == 0 {
		t.Error("device_stats map is empty after traffic")
	}
}
