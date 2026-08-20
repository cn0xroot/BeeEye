//go:build linux

package ebpf

import (
	"net"
	"os"
	"testing"
	"time"

	"BeeEye/internal/dissect"
)

// TestOpenEBPFCapturesRealDNSAsRawFrame is the eBPF-ringbuf counterpart to
// afpacket's own capture tests: it proves the whole point of raw-frame mode
// end to end — a real UDP/53 packet on loopback comes back through OpenEBPF
// as a live.Packet holding the *entire* Ethernet frame (not just a DNS
// payload slice the kernel picked out), and that frame re-dissects into a
// correct DNS query exactly the way an AF_PACKET-sourced frame would. That
// equivalence is what lets internal/capsource swap eBPF in ahead of
// AF_PACKET for the agent without the rest of the pipeline knowing the
// difference.
func TestOpenEBPFCapturesRealDNSAsRawFrame(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF + CAP_NET_ADMIN) to load and attach")
	}

	src, err := OpenEBPF("lo")
	if err != nil {
		t.Fatalf("OpenEBPF(lo): %v", err)
	}
	defer src.Close()

	if src.Name() != "ebpf" {
		t.Errorf("Name() = %q, want ebpf", src.Name())
	}
	if src.Iface() != "lo" {
		t.Errorf("Iface() = %q, want lo", src.Iface())
	}

	// This host runs a real local proxy that generates a continuous stream of
	// unrelated TCP/TLS traffic over loopback (verified separately with a
	// packet dump), and raw-frame mode mirrors every one of those frames —
	// that is the point of the mode. So the test sends its marker query
	// often and for a while, rather than assuming it will be seen quickly
	// in a channel that is also carrying that other traffic.
	go func() {
		for i := 0; i < 200; i++ {
			c, err := net.Dial("udp", "127.0.0.1:53")
			if err != nil {
				return
			}
			// Transaction ID 0xBEEE, a minimal query for QNAME "raw".
			c.Write([]byte{0xbe, 0xee, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
				3, 'r', 'a', 'w', 0, 0, 1, 0, 1})
			c.Close()
			time.Sleep(20 * time.Millisecond)
		}
	}()

	dis := dissect.New()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case pkt, ok := <-src.Packets():
			if !ok {
				t.Fatal("packet channel closed before seeing the test query")
			}
			if len(pkt.Data) < 14 {
				continue // shorter than an Ethernet header — not our frame
			}
			r := dis.Packet(pkt)
			if r.Proto != "DNS" && r.Proto != "MDNS" {
				continue // some other packet sharing the host during the test
			}
			if got := r.FieldValues("dns.id"); len(got) != 1 || got[0] != "0xbeee" {
				continue // a DNS packet, but not necessarily ours — keep waiting
			}
			if got := r.FieldValues("dns.qry.name"); len(got) != 1 || got[0] != "raw" {
				t.Errorf("dns.qry.name = %v, want [raw]", got)
			}
			// This is only meaningful because raw-frame mode ships the
			// whole frame: an Ethernet header (14B) + IPv4 (20B) + UDP
			// (8B) + our 21-byte DNS message = 63 bytes, well past what a
			// payload-only capture would have contained.
			if pkt.CapLen < 60 {
				t.Errorf("frame is only %d bytes — looks like a payload slice, not a whole frame", pkt.CapLen)
			}
			return
		case <-deadline:
			t.Fatal("no matching DNS query observed via the eBPF source within 20s")
		}
	}
}
