//go:build linux

package ebpf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// TestEventLayoutMatchesBTF is the guard on the kernel↔userspace contract.
//
// ParseEvent reads the ringbuf record at hardcoded byte offsets. Those offsets
// are only correct as long as they match `struct BeeEye_event` as the compiler
// actually laid it out — a field reordered in BeeEye_events.h would otherwise
// silently produce garbage IPs and ports rather than a build failure. So the
// test reads the real layout out of the object's BTF and compares.
func TestEventLayoutMatchesBTF(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		t.Fatalf("load embedded object: %v", err)
	}
	var st *btf.Struct
	if err := spec.Types.TypeByName("BeeEye_event", &st); err != nil {
		t.Fatalf("struct BeeEye_event not found in BTF: %v", err)
	}

	if got := int(st.Size); got != EventSize {
		t.Errorf("struct size: C says %d, Go EventSize is %d", got, EventSize)
	}

	// Offsets ParseEvent depends on, in bytes.
	want := map[string]uint32{
		"ts": 0, "flow_pkts": 8, "flow_bytes": 16, "flow_first_ts": 24,
		"ifindex": 32, "pkt_len": 36, "payload_len": 40,
		"eth_proto": 44, "vlan": 46, "sport": 48, "dport": 50,
		"smac": 52, "dmac": 58, "saddr": 64, "daddr": 80,
		"kind": 96, "dir": 97, "proto": 98, "family": 99,
		"category": 100, "tcp_flags": 101, "ttl": 102,
		"payload": 104,
	}
	got := map[string]uint32{}
	for _, m := range st.Members {
		got[m.Name] = uint32(m.Offset.Bytes())
	}
	for name, off := range want {
		actual, ok := got[name]
		if !ok {
			t.Errorf("field %q missing from struct BeeEye_event", name)
			continue
		}
		if actual != off {
			t.Errorf("field %q: C offset %d, Go reads at %d", name, actual, off)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok && name != "_pad" {
			t.Errorf("field %q exists in C but Go does not decode it", name)
		}
	}
}

// TestParseEventRoundTrip checks the decoder against a hand-built record.
func TestParseEventRoundTrip(t *testing.T) {
	b := make([]byte, EventSize)
	put64 := func(off int, v uint64) {
		for i := 0; i < 8; i++ {
			b[off+i] = byte(v >> (8 * i))
		}
	}
	put32 := func(off int, v uint32) {
		for i := 0; i < 4; i++ {
			b[off+i] = byte(v >> (8 * i))
		}
	}
	put16 := func(off int, v uint16) {
		b[off] = byte(v)
		b[off+1] = byte(v >> 8)
	}

	put64(0, 123456789)
	put64(8, 42)
	put64(16, 4096)
	put32(32, 7)
	put32(36, 1514)
	put32(40, 4)
	put16(44, 0x0800)
	put16(48, 51234)
	put16(50, 443)
	copy(b[52:58], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01})
	copy(b[58:64], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02})
	copy(b[64:68], []byte{192, 168, 1, 20})
	copy(b[80:84], []byte{104, 16, 20, 5})
	b[96] = byte(KindTLSClient)
	b[97] = byte(DirIngress)
	b[98] = 6
	b[99] = afInet
	b[100] = 1 // camera
	b[101] = 0x18
	b[102] = 64
	copy(b[104:108], []byte{0x16, 0x03, 0x01, 0x02})

	ev, err := ParseEvent(b)
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.SrcIP.String() != "192.168.1.20" {
		t.Errorf("src ip = %s, want 192.168.1.20", ev.SrcIP)
	}
	if ev.DstIP.String() != "104.16.20.5" {
		t.Errorf("dst ip = %s, want 104.16.20.5", ev.DstIP)
	}
	if ev.DstPort != 443 {
		t.Errorf("dst port = %d, want 443", ev.DstPort)
	}
	if ev.Kind != KindTLSClient || ev.Kind.String() != "tls_client_hello" {
		t.Errorf("kind = %v/%s", ev.Kind, ev.Kind)
	}
	if ev.TransportName() != "TCP" {
		t.Errorf("transport = %s, want TCP", ev.TransportName())
	}
	// On ingress the LAN device is the sender.
	if ev.DeviceMAC().String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("device mac = %s", ev.DeviceMAC())
	}
	if len(ev.Payload) != 4 || ev.Payload[0] != 0x16 {
		t.Errorf("payload = % x, want 16 03 01 02", ev.Payload)
	}

	// A truncated record must be rejected, not silently mis-decoded.
	if _, err := ParseEvent(b[:EventSize-1]); err == nil {
		t.Error("ParseEvent accepted a short record")
	}
}
