// Package dissect turns a raw frame into the layered field tree the analyzer
// GUI renders, plus a flat field index the display filter evaluates against.
//
// The split mirrors Wireshark's: the tree is what a human reads, the flat
// index (`ip.src`, `tcp.port`, `dns.qry.name`, …) is what expressions match.
// Both come from one pass so they can never disagree.
//
// Field names follow Wireshark's conventions deliberately — they are technical
// identifiers, not prose, and anyone who has typed a filter before should not
// have to learn a second vocabulary. Only the surrounding UI chrome is
// translated (§3.8.1).
package dissect

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"BeeEye/internal/live"
	"BeeEye/internal/pcapfile"
)

// Node is one row of the protocol tree. Offset/Length point back into the raw
// frame so selecting a row highlights the corresponding bytes in the hex pane.
type Node struct {
	Label string `json:"label"`
	// Proto is the protocol key for a top-level layer ("ip", "tls", …). The
	// UI colours layers and their bytes by this key rather than by matching
	// the English label, which would break the moment a label is reworded.
	Proto    string  `json:"proto,omitempty"`
	Field    string  `json:"field,omitempty"`
	Value    string  `json:"value,omitempty"`
	Offset   int     `json:"offset"`
	Length   int     `json:"length"`
	Children []*Node `json:"children,omitempty"`
}

// layer records a completed top-level protocol layer, tagged with its key.
func (r *Result) layer(n *Node, proto string) {
	n.Proto = proto
	r.Layers = append(r.Layers, n)
}

func node(label string, off, length int) *Node {
	return &Node{Label: label, Offset: off, Length: length}
}

// leaf appends a field row to parent AND registers it in the flat filter
// index. Those two must happen together: a field visible in the tree that the
// filter cannot match is exactly the kind of gap that makes an analyzer
// frustrating to use, so there is no way to add one without the other.
func (r *Result) leaf(parent *Node, label, field, value string, off, length int) *Node {
	c := &Node{Label: label, Field: field, Value: value, Offset: off, Length: length}
	parent.Children = append(parent.Children, c)
	if field != "" && value != "" {
		r.set(field, value)
	}
	return c
}

// Result is everything the GUI needs about one packet.
type Result struct {
	No      int64     `json:"no"`
	TS      time.Time `json:"ts"`
	RelTime float64   `json:"rel_time"` // seconds since the first packet
	Iface   string    `json:"iface"`
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	SrcPort int       `json:"src_port"`
	DstPort int       `json:"dst_port"`
	// Transport is "tcp"/"udp"/"" — kept as its own field because process
	// attribution needs the transport and both ports as values, not as strings
	// dug back out of the field index.
	Transport string `json:"transport,omitempty"`
	Proto     string `json:"proto"` // the highest layer identified
	Length    int    `json:"length"`
	Info      string `json:"info"`

	Layers    []*Node             `json:"layers"`
	Protocols []string            `json:"protocols"`
	Fields    map[string][]string `json:"fields"`

	// Metadata the rest of BeeEye consumes (F3, F21, F23).
	SNI     string   `json:"sni,omitempty"`
	ALPN    []string `json:"alpn,omitempty"`
	JA3     string   `json:"ja3,omitempty"`
	Domains []string `json:"domains,omitempty"`

	Raw []byte `json:"-"`
}

// set records a filterable field. Repeated fields accumulate, which is what
// makes `tcp.port == 443` match either endpoint and `dns.a` match every answer.
func (r *Result) set(field, value string) {
	if r.Fields == nil {
		r.Fields = map[string][]string{}
	}
	// The tree and the explicit machine-readable value often carry the same
	// text ("192.168.1.1"); recording it twice would only clutter the field
	// list the UI shows.
	for _, existing := range r.Fields[field] {
		if existing == value {
			return
		}
	}
	r.Fields[field] = append(r.Fields[field], value)
}

func (r *Result) proto(name string) {
	for _, p := range r.Protocols {
		if p == name {
			return
		}
	}
	r.Protocols = append(r.Protocols, name)
	r.set(name, "")
}

// Dissector holds per-capture state — currently just the epoch used for
// relative timestamps, matching Wireshark's default time column.
type Dissector struct {
	epoch time.Time
}

func New() *Dissector { return &Dissector{} }

// Packet dissects one captured frame.
func (d *Dissector) Packet(p live.Packet) *Result {
	if d.epoch.IsZero() {
		d.epoch = p.TS
	}
	r := &Result{
		No:      p.Index,
		TS:      p.TS,
		RelTime: p.TS.Sub(d.epoch).Seconds(),
		Iface:   p.Iface,
		Length:  p.OrigLen,
		Proto:   "unknown",
		Info:    "",
		Raw:     p.Data,
	}
	r.set("frame.len", strconv.Itoa(p.OrigLen))
	r.set("frame.interface_name", p.Iface)
	r.set("frame.number", strconv.FormatInt(p.Index, 10))
	// Live capture (AF_PACKET/eBPF on a physical or wireless NIC) never sets
	// LinkType — it is always genuine Ethernet framing — so the zero value
	// takes the same path as an explicit LinkEthernet. Only a replayed
	// capture file (livefile) can carry anything else: a tunnel/VPN
	// interface's dump is commonly raw IP with no link header at all, and
	// dissecting that as Ethernet was silently misreading the IP header's
	// own bytes as a bogus MAC pair — see the "vti"/tunnel-capture import
	// this was written for.
	switch p.LinkType {
	case 0, pcapfile.LinkEthernet:
		dissectEthernet(r, p.Data, 0)
	case pcapfile.LinkRaw, pcapfile.LinkRawBSD:
		dissectRawLink(r, p.Data)
	case pcapfile.LinkLinuxSLL:
		dissectLinuxSLL(r, p.Data)
	default:
		// An encapsulation this analyzer does not specifically know —
		// Ethernet is still the best guess (it is what nearly every capture
		// actually is) rather than leaving the frame entirely undissected.
		dissectEthernet(r, p.Data, 0)
	}
	if r.Info == "" {
		r.Info = r.Proto
	}
	return r
}

// ---------------------------------------------------------------- link layer

func dissectEthernet(r *Result, b []byte, off int) {
	if len(b) < off+14 {
		return
	}
	dst := net.HardwareAddr(b[off : off+6])
	src := net.HardwareAddr(b[off+6 : off+12])
	et := binary.BigEndian.Uint16(b[off+12 : off+14])

	r.proto("eth")
	r.Proto = "Ethernet"
	r.Src, r.Dst = src.String(), dst.String()
	r.set("eth.src", src.String())
	r.set("eth.dst", dst.String())
	r.set("eth.addr", src.String())
	r.set("eth.addr", dst.String())
	r.set("eth.type", fmt.Sprintf("0x%04x", et))

	n := node(fmt.Sprintf("Ethernet II, Src: %s, Dst: %s", src, dst), off, 14)
	r.leaf(n, "Destination", "eth.dst", dst.String(), off, 6)
	r.leaf(n, "Source", "eth.src", src.String(), off+6, 6)
	r.leaf(n, "Type: "+etherTypeName(et), "eth.type", fmt.Sprintf("0x%04x", et), off+12, 2)
	r.layer(n, "eth")

	next := off + 14
	// VLAN tags, at most two (QinQ), same bound as the kernel program.
	for i := 0; i < 2 && (et == 0x8100 || et == 0x88a8); i++ {
		if len(b) < next+4 {
			return
		}
		tci := binary.BigEndian.Uint16(b[next : next+2])
		vid := tci & 0x0FFF
		et = binary.BigEndian.Uint16(b[next+2 : next+4])
		r.proto("vlan")
		r.set("vlan.id", strconv.Itoa(int(vid)))
		v := node(fmt.Sprintf("802.1Q Virtual LAN, VLAN ID: %d", vid), next, 4)
		r.leaf(v, "VLAN ID", "vlan.id", strconv.Itoa(int(vid)), next, 2)
		r.layer(v, "vlan")
		next += 4
	}

	switch et {
	case 0x0800:
		dissectIPv4(r, b, next)
	case 0x86dd:
		dissectIPv6(r, b, next)
	case 0x0806:
		dissectARP(r, b, next)
	}
}

// dissectRawLink handles LINKTYPE_RAW / DLT_RAW (pcapfile.LinkRaw and
// LinkRawBSD): the frame *is* an IP packet, with no link-layer header of any
// kind in front of it — common for a dump taken on a tunnel/VPN interface
// (vtiN, tun, ppp) rather than a physical or wireless NIC. There is no
// EtherType to dispatch on, so the only signal available is the IP version
// nibble in the very first byte, which both IPv4 and IPv6 headers carry in
// the same place.
func dissectRawLink(r *Result, b []byte) {
	if len(b) < 1 {
		return
	}
	switch b[0] >> 4 {
	case 4:
		dissectIPv4(r, b, 0)
	case 6:
		dissectIPv6(r, b, 0)
	}
}

// dissectLinuxSLL handles LINKTYPE_LINUX_SLL (pcapfile.LinkLinuxSLL) — the
// 16-byte "Linux cooked capture" pseudo-header tcpdump/dumpcap synthesize
// when capturing on the "any" pseudo-interface, since there is no single
// real link layer to report across every interface at once. Layout (all
// big-endian): packet type(2), ARPHRD_* device type(2), address length(2),
// address(8, only the first `address length` bytes meaningful), protocol —
// an EtherType value(2) — then the payload.
func dissectLinuxSLL(r *Result, b []byte) {
	if len(b) < 16 {
		return
	}
	proto := binary.BigEndian.Uint16(b[14:16])
	switch proto {
	case 0x0800:
		dissectIPv4(r, b, 16)
	case 0x86dd:
		dissectIPv6(r, b, 16)
	case 0x0806:
		dissectARP(r, b, 16)
	}
}

func etherTypeName(et uint16) string {
	switch et {
	case 0x0800:
		return "IPv4 (0x0800)"
	case 0x0806:
		return "ARP (0x0806)"
	case 0x86dd:
		return "IPv6 (0x86dd)"
	case 0x8100:
		return "802.1Q VLAN (0x8100)"
	}
	return fmt.Sprintf("0x%04x", et)
}

func dissectARP(r *Result, b []byte, off int) {
	if len(b) < off+28 {
		return
	}
	op := binary.BigEndian.Uint16(b[off+6 : off+8])
	sha := net.HardwareAddr(b[off+8 : off+14])
	spa := net.IP(b[off+14 : off+18])
	tpa := net.IP(b[off+24 : off+28])

	r.proto("arp")
	r.Proto = "ARP"
	r.set("arp.opcode", strconv.Itoa(int(op)))
	r.set("arp.src.proto_ipv4", spa.String())
	r.set("arp.dst.proto_ipv4", tpa.String())

	n := node("Address Resolution Protocol", off, 28)
	if op == 1 {
		n.Label += " (request)"
		r.Info = fmt.Sprintf("Who has %s? Tell %s", tpa, spa)
	} else {
		n.Label += " (reply)"
		r.Info = fmt.Sprintf("%s is at %s", spa, sha)
	}
	r.leaf(n, "Opcode", "arp.opcode", strconv.Itoa(int(op)), off+6, 2)
	r.leaf(n, "Sender MAC address", "arp.src.hw_mac", sha.String(), off+8, 6)
	r.leaf(n, "Sender IP address", "arp.src.proto_ipv4", spa.String(), off+14, 4)
	r.leaf(n, "Target IP address", "arp.dst.proto_ipv4", tpa.String(), off+24, 4)
	r.layer(n, "arp")
}

// ------------------------------------------------------------- network layer

func dissectIPv4(r *Result, b []byte, off int) {
	if len(b) < off+20 {
		return
	}
	ihl := int(b[off]&0x0F) * 4
	if ihl < 20 || len(b) < off+ihl {
		return
	}
	totalLen := binary.BigEndian.Uint16(b[off+2 : off+4])
	fragOff := binary.BigEndian.Uint16(b[off+6 : off+8])
	ttl := b[off+8]
	proto := b[off+9]
	src := net.IP(b[off+12 : off+16])
	dst := net.IP(b[off+16 : off+20])

	r.proto("ip")
	r.Proto = "IPv4"
	r.Src, r.Dst = src.String(), dst.String()
	r.set("ip.src", src.String())
	r.set("ip.dst", dst.String())
	r.set("ip.addr", src.String())
	r.set("ip.addr", dst.String())
	r.set("ip.ttl", strconv.Itoa(int(ttl)))
	r.set("ip.proto", strconv.Itoa(int(proto)))
	r.set("ip.len", strconv.Itoa(int(totalLen)))

	n := node(fmt.Sprintf("Internet Protocol Version 4, Src: %s, Dst: %s", src, dst), off, ihl)
	r.leaf(n, "Header Length", "ip.hdr_len", strconv.Itoa(ihl), off, 1)
	r.leaf(n, "Total Length", "ip.len", strconv.Itoa(int(totalLen)), off+2, 2)
	r.leaf(n, "Time to Live", "ip.ttl", strconv.Itoa(int(ttl)), off+8, 1)
	r.leaf(n, "Protocol: "+ipProtoName(proto), "ip.proto", strconv.Itoa(int(proto)), off+9, 1)
	r.leaf(n, "Source Address", "ip.src", src.String(), off+12, 4)
	r.leaf(n, "Destination Address", "ip.dst", dst.String(), off+16, 4)
	r.layer(n, "ip")

	// Only the first fragment carries an L4 header; the rest are pure payload.
	if fragOff&0x1FFF != 0 {
		r.Info = fmt.Sprintf("Fragmented IP protocol (proto=%s, off=%d)",
			ipProtoName(proto), (fragOff&0x1FFF)*8)
		return
	}
	dissectTransport(r, b, off+ihl, proto)
}

func dissectIPv6(r *Result, b []byte, off int) {
	if len(b) < off+40 {
		return
	}
	next := b[off+6]
	hop := b[off+7]
	src := net.IP(b[off+8 : off+24])
	dst := net.IP(b[off+24 : off+40])

	r.proto("ipv6")
	r.Proto = "IPv6"
	r.Src, r.Dst = src.String(), dst.String()
	r.set("ipv6.src", src.String())
	r.set("ipv6.dst", dst.String())
	r.set("ipv6.addr", src.String())
	r.set("ipv6.addr", dst.String())
	// ip.addr matching both families is what makes a filter like
	// `ip.addr == fe80::1` behave the way people expect.
	r.set("ip.addr", src.String())
	r.set("ip.addr", dst.String())

	n := node(fmt.Sprintf("Internet Protocol Version 6, Src: %s, Dst: %s", src, dst), off, 40)
	r.leaf(n, "Next Header: "+ipProtoName(next), "ipv6.nxt", strconv.Itoa(int(next)), off+6, 1)
	r.leaf(n, "Hop Limit", "ipv6.hlim", strconv.Itoa(int(hop)), off+7, 1)
	r.leaf(n, "Source Address", "ipv6.src", src.String(), off+8, 16)
	r.leaf(n, "Destination Address", "ipv6.dst", dst.String(), off+24, 16)
	r.layer(n, "ipv6")

	dissectTransport(r, b, off+40, next)
}

func ipProtoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP (1)"
	case 6:
		return "TCP (6)"
	case 17:
		return "UDP (17)"
	case 58:
		return "ICMPv6 (58)"
	case 2:
		return "IGMP (2)"
	case 132:
		return "SCTP (132)"
	}
	return fmt.Sprintf("%d", p)
}

// ----------------------------------------------------------- transport layer

func dissectTransport(r *Result, b []byte, off int, proto uint8) {
	switch proto {
	case 6:
		dissectTCP(r, b, off)
	case 17:
		dissectUDP(r, b, off)
	case 1, 58:
		dissectICMP(r, b, off, proto)
	case 132:
		dissectSCTP(r, b, off)
	}
}

func dissectTCP(r *Result, b []byte, off int) {
	if len(b) < off+20 {
		return
	}
	sport := binary.BigEndian.Uint16(b[off : off+2])
	dport := binary.BigEndian.Uint16(b[off+2 : off+4])
	seq := binary.BigEndian.Uint32(b[off+4 : off+8])
	ack := binary.BigEndian.Uint32(b[off+8 : off+12])
	doff := int(b[off+12]>>4) * 4
	flags := b[off+13]
	win := binary.BigEndian.Uint16(b[off+14 : off+16])
	if doff < 20 || len(b) < off+doff {
		doff = 20
	}

	r.proto("tcp")
	r.Proto = "TCP"
	r.Transport = "tcp"
	r.SrcPort, r.DstPort = int(sport), int(dport)
	r.set("tcp.srcport", strconv.Itoa(int(sport)))
	r.set("tcp.dstport", strconv.Itoa(int(dport)))
	r.set("tcp.port", strconv.Itoa(int(sport)))
	r.set("tcp.port", strconv.Itoa(int(dport)))
	r.set("tcp.seq", strconv.FormatUint(uint64(seq), 10))
	r.set("tcp.flags", fmt.Sprintf("0x%02x", flags))
	for name, bit := range map[string]uint8{
		"tcp.flags.fin": 0x01, "tcp.flags.syn": 0x02, "tcp.flags.reset": 0x04,
		"tcp.flags.push": 0x08, "tcp.flags.ack": 0x10, "tcp.flags.urg": 0x20,
	} {
		if flags&bit != 0 {
			r.set(name, "1")
		} else {
			r.set(name, "0")
		}
	}

	n := node(fmt.Sprintf("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Len: %d",
		sport, dport, seq, max(0, len(b)-(off+doff))), off, doff)
	r.leaf(n, "Source Port", "tcp.srcport", strconv.Itoa(int(sport)), off, 2)
	r.leaf(n, "Destination Port", "tcp.dstport", strconv.Itoa(int(dport)), off+2, 2)
	r.leaf(n, "Sequence Number", "tcp.seq", strconv.FormatUint(uint64(seq), 10), off+4, 4)
	r.leaf(n, "Acknowledgment Number", "tcp.ack", strconv.FormatUint(uint64(ack), 10), off+8, 4)
	r.leaf(n, "Flags: "+tcpFlagString(flags), "tcp.flags", fmt.Sprintf("0x%02x", flags), off+13, 1)
	r.leaf(n, "Window", "tcp.window_size", strconv.Itoa(int(win)), off+14, 2)
	r.layer(n, "tcp")

	r.Info = fmt.Sprintf("%d → %d [%s] Seq=%d Win=%d Len=%d",
		sport, dport, tcpFlagString(flags), seq, win, max(0, len(b)-(off+doff)))

	payload := off + doff
	if payload < len(b) {
		dissectAppTCP(r, b, payload, sport, dport)
	}
}

func tcpFlagString(f uint8) string {
	var parts []string
	for _, fl := range []struct {
		bit  uint8
		name string
	}{{0x02, "SYN"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x01, "FIN"}, {0x04, "RST"}, {0x20, "URG"}} {
		if f&fl.bit != 0 {
			parts = append(parts, fl.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func dissectUDP(r *Result, b []byte, off int) {
	if len(b) < off+8 {
		return
	}
	sport := binary.BigEndian.Uint16(b[off : off+2])
	dport := binary.BigEndian.Uint16(b[off+2 : off+4])
	length := binary.BigEndian.Uint16(b[off+4 : off+6])

	r.proto("udp")
	r.Proto = "UDP"
	r.Transport = "udp"
	r.SrcPort, r.DstPort = int(sport), int(dport)
	r.set("udp.srcport", strconv.Itoa(int(sport)))
	r.set("udp.dstport", strconv.Itoa(int(dport)))
	r.set("udp.port", strconv.Itoa(int(sport)))
	r.set("udp.port", strconv.Itoa(int(dport)))
	r.set("udp.length", strconv.Itoa(int(length)))

	n := node(fmt.Sprintf("User Datagram Protocol, Src Port: %d, Dst Port: %d", sport, dport), off, 8)
	r.leaf(n, "Source Port", "udp.srcport", strconv.Itoa(int(sport)), off, 2)
	r.leaf(n, "Destination Port", "udp.dstport", strconv.Itoa(int(dport)), off+2, 2)
	r.leaf(n, "Length", "udp.length", strconv.Itoa(int(length)), off+4, 2)
	r.layer(n, "udp")

	r.Info = fmt.Sprintf("%d → %d Len=%d", sport, dport, max(0, int(length)-8))
	dissectAppUDP(r, b, off+8, sport, dport)
}

func dissectICMP(r *Result, b []byte, off int, proto uint8) {
	if len(b) < off+4 {
		return
	}
	typ, code := b[off], b[off+1]
	name := "ICMP"
	if proto == 58 {
		name = "ICMPv6"
	}
	r.proto(strings.ToLower(name))
	r.Proto = name
	r.set("icmp.type", strconv.Itoa(int(typ)))
	r.set("icmp.code", strconv.Itoa(int(code)))

	n := node("Internet Control Message Protocol", off, min(8, len(b)-off))
	r.leaf(n, "Type", "icmp.type", strconv.Itoa(int(typ)), off, 1)
	r.leaf(n, "Code", "icmp.code", strconv.Itoa(int(code)), off+1, 1)
	r.layer(n, strings.ToLower(name))

	switch {
	case proto == 1 && typ == 8:
		r.Info = "Echo (ping) request"
	case proto == 1 && typ == 0:
		r.Info = "Echo (ping) reply"
	case proto == 1 && typ == 3:
		r.Info = "Destination unreachable"
	default:
		r.Info = fmt.Sprintf("Type=%d Code=%d", typ, code)
	}
}

// dissectSCTP parses RFC 4960: a fixed 12-byte common header (no length
// field of its own — SCTP relies on the IP layer for that) followed by one
// or more chunks, each type(1) flags(1) length(2) value(length-4), padded to
// a 4-byte boundary. Telecom signaling (SS7-over-IP via SIGTRAN, S1AP/NGAP
// on a mobile core's control plane, and similar) commonly rides on SCTP
// rather than TCP/UDP — the association's own reliability and multi-stream
// framing is why SIGTRAN chose it — so a capture from that world showed only
// "IPv4, protocol 132" with no further detail until this existed.
//
// The higher-layer protocol carried inside DATA chunks (identified by its
// Payload Protocol Identifier) is reported as a bare number rather than
// resolved to a name: IANA's SCTP PPID registry is large and this analyzer
// would rather show "ppid=18" honestly than guess wrong and label someone's
// traffic with the wrong telecom protocol.
func dissectSCTP(r *Result, b []byte, off int) {
	if len(b) < off+12 {
		return
	}
	sport := binary.BigEndian.Uint16(b[off : off+2])
	dport := binary.BigEndian.Uint16(b[off+2 : off+4])
	vtag := binary.BigEndian.Uint32(b[off+4 : off+8])

	r.proto("sctp")
	r.Proto = "SCTP"
	r.Transport = "sctp"
	r.SrcPort, r.DstPort = int(sport), int(dport)
	r.set("sctp.srcport", strconv.Itoa(int(sport)))
	r.set("sctp.dstport", strconv.Itoa(int(dport)))
	r.set("sctp.port", strconv.Itoa(int(sport)))
	r.set("sctp.port", strconv.Itoa(int(dport)))
	r.set("sctp.verification_tag", fmt.Sprintf("0x%08x", vtag))

	n := node(fmt.Sprintf("Stream Control Transmission Protocol, Src Port: %d, Dst Port: %d", sport, dport), off, 12)
	r.leaf(n, "Source Port", "sctp.srcport", strconv.Itoa(int(sport)), off, 2)
	r.leaf(n, "Destination Port", "sctp.dstport", strconv.Itoa(int(dport)), off+2, 2)
	r.leaf(n, "Verification Tag", "sctp.verification_tag", fmt.Sprintf("0x%08x", vtag), off+4, 4)

	q := off + 12
	var names []string
	// Bounded, not just by len(b): a corrupt or hostile chunk-length chain
	// must not be able to spin this loop forever the way it could with only
	// the slice-length check below.
	for chunks := 0; q+4 <= len(b) && chunks < 64; chunks++ {
		ctype := b[q]
		cflags := b[q+1]
		clen := int(binary.BigEndian.Uint16(b[q+2 : q+4]))
		if clen < 4 {
			break
		}
		chunkEnd := min(q+clen, len(b))
		name := sctpChunkName(ctype)
		names = append(names, name)

		c := node(name+" chunk", q, chunkEnd-q)
		r.leaf(c, "Chunk Type: "+name, "sctp.chunk_type", name, q, 1)
		r.leaf(c, "Chunk Flags", "sctp.chunk_flags", fmt.Sprintf("0x%02x", cflags), q+1, 1)
		r.leaf(c, "Chunk Length", "sctp.chunk_length", strconv.Itoa(clen), q+2, 2)

		// DATA's own header: TSN(4) StreamID(2) StreamSeq(2) PPID(4), then
		// the user payload — the one chunk type worth reaching into, since
		// its fields are what actually identifies the higher-layer traffic.
		if ctype == 0 && chunkEnd >= q+16 {
			tsn := binary.BigEndian.Uint32(b[q+4 : q+8])
			sid := binary.BigEndian.Uint16(b[q+8 : q+10])
			ppid := binary.BigEndian.Uint32(b[q+12 : q+16])
			r.leaf(c, "TSN", "sctp.data_tsn", strconv.FormatUint(uint64(tsn), 10), q+4, 4)
			r.leaf(c, "Stream Identifier", "sctp.data_sid", strconv.Itoa(int(sid)), q+8, 2)
			r.leaf(c, "Payload Protocol Identifier", "sctp.data_ppid", strconv.FormatUint(uint64(ppid), 10), q+12, 4)
			r.set("sctp.data_sid", strconv.Itoa(int(sid)))
			r.set("sctp.data_ppid", strconv.FormatUint(uint64(ppid), 10))
		}

		n.Children = append(n.Children, c)
		// Chunks are padded to a 4-byte boundary; that padding is not part
		// of whatever chunk comes next.
		q += (clen + 3) &^ 3
	}
	r.layer(n, "sctp")
	if len(names) > 0 {
		r.Info = strings.Join(names, ", ")
	} else {
		r.Info = "SCTP"
	}
}

func sctpChunkName(t uint8) string {
	switch t {
	case 0:
		return "DATA"
	case 1:
		return "INIT"
	case 2:
		return "INIT_ACK"
	case 3:
		return "SACK"
	case 4:
		return "HEARTBEAT"
	case 5:
		return "HEARTBEAT_ACK"
	case 6:
		return "ABORT"
	case 7:
		return "SHUTDOWN"
	case 8:
		return "SHUTDOWN_ACK"
	case 9:
		return "ERROR"
	case 10:
		return "COOKIE_ECHO"
	case 11:
		return "COOKIE_ACK"
	case 14:
		return "SHUTDOWN_COMPLETE"
	}
	return fmt.Sprintf("chunk type %d", t)
}

// FieldValues implements dfilter.Target. Lookups are case-insensitive on the
// field name so `IP.SRC` and `ip.src` behave the same.
func (r *Result) FieldValues(name string) []string {
	if v, ok := r.Fields[name]; ok {
		return v
	}
	lower := strings.ToLower(name)
	if v, ok := r.Fields[lower]; ok {
		return v
	}
	return nil
}

// HasProtocol implements dfilter.Target for bare presence tests (`dns`, `tls`).
func (r *Result) HasProtocol(name string) bool {
	for _, p := range r.Protocols {
		if strings.EqualFold(p, name) {
			return true
		}
	}
	return false
}
