// Package ebpf loads the BeeEye kernel program and turns its ringbuf records
// into typed Go values (program.md §3.4, §3.5.1 "Ringbuf Reader").
//
// The Event struct below mirrors `struct BeeEye_event` in bpf/BeeEye_events.h
// byte for byte. That correspondence is load-bearing and easy to break, so
// TestEventLayout asserts the size and field offsets rather than trusting it.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// PayloadMax mirrors PAYLOAD_MAX in bpf/BeeEye_events.h. It covers a full
// standard-MTU Ethernet frame (1500) plus header and one VLAN tag, not just a
// protocol header, because EVT_RAW_FRAME needs the whole frame — see Kind.
const PayloadMax = 1536

// EventSize is the on-wire size of one ringbuf record.
const EventSize = 104 + PayloadMax

// Kind enumerates the record types the kernel emits (enum BeeEye_evt).
type Kind uint8

const (
	KindFlowSnapshot Kind = 1
	KindFlowNew      Kind = 2
	KindDNS          Kind = 3
	KindTLSClient    Kind = 4
	KindTLSServer    Kind = 5
	KindNewDevice    Kind = 6
	KindARP          Kind = 7
	KindSSDP         Kind = 8
	KindDHCP         Kind = 9
	// KindRawFrame is only emitted when raw-frame mode is on (SetRawFrameMode):
	// a whole-frame mirror, bypassing every other kind's in-kernel protocol
	// identification, so the ring buffer can serve as a live.Source on par
	// with AF_PACKET (see source.go). Event.Payload is a raw Ethernet frame
	// for this kind, not a protocol payload.
	KindRawFrame Kind = 10
)

// String returns the enum key. It is deliberately a stable machine key, not a
// sentence: the Web UI localizes it (§3.8.1).
func (k Kind) String() string {
	switch k {
	case KindFlowSnapshot:
		return "flow_snapshot"
	case KindFlowNew:
		return "flow_new"
	case KindDNS:
		return "dns"
	case KindTLSClient:
		return "tls_client_hello"
	case KindTLSServer:
		return "tls_server_hello"
	case KindNewDevice:
		return "new_device"
	case KindARP:
		return "arp"
	case KindSSDP:
		return "ssdp"
	case KindDHCP:
		return "dhcp"
	case KindRawFrame:
		return "raw_frame"
	}
	return "unknown"
}

// Direction relative to the attached interface (enum BeeEye_dir).
type Direction uint8

const (
	DirIngress Direction = 0 // from the LAN device toward the gateway
	DirEgress  Direction = 1 // from the gateway toward the LAN device
)

func (d Direction) String() string {
	if d == DirEgress {
		return "egress"
	}
	return "ingress"
}

// Address families as the kernel program reports them.
const (
	afInet  = 2
	afInet6 = 10
)

// Event is one decoded ringbuf record.
type Event struct {
	TS          time.Duration // monotonic ktime at capture
	FlowPkts    uint64
	FlowBytes   uint64
	FlowFirstTS time.Duration

	IfIndex    uint32
	PktLen     uint32
	PayloadLen uint32

	EthProto uint16
	VLAN     uint16
	SrcPort  uint16
	DstPort  uint16

	SrcMAC net.HardwareAddr
	DstMAC net.HardwareAddr
	SrcIP  netip.Addr
	DstIP  netip.Addr

	Kind     Kind
	Dir      Direction
	Proto    uint8
	Family   uint8
	Category uint8
	TCPFlags uint8
	TTL      uint8

	Payload []byte
}

// DeviceMAC returns the MAC of the LAN device this event belongs to. On
// ingress the device is the sender; on egress it is the receiver — the
// distinction is why the program is mounted on the LAN-side interface at all
// (§3.4.1).
func (e *Event) DeviceMAC() net.HardwareAddr {
	if e.Dir == DirEgress {
		return e.DstMAC
	}
	return e.SrcMAC
}

// ParseEvent decodes one ringbuf record. It copies every slice it hands back,
// because the ringbuf sample memory is reused as soon as the reader advances.
func ParseEvent(b []byte) (*Event, error) {
	if len(b) < EventSize {
		return nil, fmt.Errorf("ebpf: short event: got %d bytes, want %d", len(b), EventSize)
	}
	le := binary.LittleEndian
	e := &Event{
		TS:          time.Duration(le.Uint64(b[0:])),
		FlowPkts:    le.Uint64(b[8:]),
		FlowBytes:   le.Uint64(b[16:]),
		FlowFirstTS: time.Duration(le.Uint64(b[24:])),
		IfIndex:     le.Uint32(b[32:]),
		PktLen:      le.Uint32(b[36:]),
		PayloadLen:  le.Uint32(b[40:]),
		EthProto:    le.Uint16(b[44:]),
		VLAN:        le.Uint16(b[46:]),
		SrcPort:     le.Uint16(b[48:]),
		DstPort:     le.Uint16(b[50:]),
		SrcMAC:      net.HardwareAddr(append([]byte(nil), b[52:58]...)),
		DstMAC:      net.HardwareAddr(append([]byte(nil), b[58:64]...)),
		Kind:        Kind(b[96]),
		Dir:         Direction(b[97]),
		Proto:       b[98],
		Family:      b[99],
		Category:    b[100],
		TCPFlags:    b[101],
		TTL:         b[102],
	}
	e.SrcIP = decodeAddr(b[64:80], e.Family)
	e.DstIP = decodeAddr(b[80:96], e.Family)

	n := int(e.PayloadLen)
	if n > PayloadMax {
		n = PayloadMax
	}
	if n > 0 {
		e.Payload = append([]byte(nil), b[104:104+n]...)
	}
	return e, nil
}

// decodeAddr reads the fixed 16-byte address slot. IPv4 lives in the first
// four bytes; family says how many are meaningful.
func decodeAddr(b []byte, family uint8) netip.Addr {
	switch family {
	case afInet:
		return netip.AddrFrom4([4]byte(b[0:4]))
	case afInet6:
		return netip.AddrFrom16([16]byte(b[0:16]))
	}
	return netip.Addr{}
}

// TransportName renders the IP protocol number (F23 transport layer).
func (e *Event) TransportName() string {
	switch e.Proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 0:
		if e.EthProto == 0x0806 {
			return "ARP"
		}
	}
	return fmt.Sprintf("IP-%d", e.Proto)
}
