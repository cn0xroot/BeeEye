package live

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
)

// Frame builders. The simulator emits genuine, well-formed Ethernet frames
// rather than pre-digested records, so the dissector, the display filter and
// the hex pane all run exactly the same code path they run on real capture.
// They double as fixtures for the dissector's tests.

// BuildEthernet prepends an Ethernet II header to payload.
func BuildEthernet(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, payload...)
}

// BuildIPv4 wraps payload in an IPv4 header with a correct header checksum.
func BuildIPv4(src, dst net.IP, proto uint8, ttl uint8, id uint16, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(h[4:6], id)
	binary.BigEndian.PutUint16(h[6:8], 0x4000) // don't fragment
	h[8] = ttl
	h[9] = proto
	copy(h[12:16], src.To4())
	copy(h[16:20], dst.To4())
	binary.BigEndian.PutUint16(h[10:12], checksum(h))
	return append(h, payload...)
}

// BuildUDP wraps payload in a UDP header. The checksum is left zero, which is
// legal for IPv4 and keeps the builder free of pseudo-header bookkeeping.
func BuildUDP(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	return append(h, payload...)
}

// TCPFlags are the control bits, spelled out so callers read as intent.
const (
	TCPFin uint8 = 1 << 0
	TCPSyn uint8 = 1 << 1
	TCPRst uint8 = 1 << 2
	TCPPsh uint8 = 1 << 3
	TCPAck uint8 = 1 << 4
)

// BuildTCP wraps payload in a 20-byte TCP header.
func BuildTCP(sport, dport uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	binary.BigEndian.PutUint32(h[4:8], seq)
	binary.BigEndian.PutUint32(h[8:12], ack)
	h[12] = 5 << 4 // data offset: 5 words
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:16], 64240) // window
	return append(h, payload...)
}

// BuildDNSQuery builds a standard A-record query for domain.
func BuildDNSQuery(txid uint16, domain string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], txid)
	binary.BigEndian.PutUint16(b[2:4], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(b[4:6], 1)      // one question
	b = append(b, encodeDNSName(domain)...)
	b = append(b, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	return b
}

// BuildDNSResponse answers domain with the given A records. rcode 3 produces
// the NXDOMAIN replies the DGA detector keys on (F33).
func BuildDNSResponse(txid uint16, domain string, ips []net.IP, ttl uint32, rcode uint8) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], txid)
	binary.BigEndian.PutUint16(b[2:4], 0x8180|uint16(rcode&0x0F)) // response + RA
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(ips)))
	name := encodeDNSName(domain)
	b = append(b, name...)
	b = append(b, 0, 1, 0, 1)
	for _, ip := range ips {
		b = append(b, 0xC0, 0x0C) // pointer back to the question's name
		b = append(b, 0, 1, 0, 1) // TYPE=A CLASS=IN
		t := make([]byte, 4)
		binary.BigEndian.PutUint32(t, ttl)
		b = append(b, t...)
		b = append(b, 0, 4)
		b = append(b, ip.To4()...)
	}
	return b
}

func encodeDNSName(domain string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// BuildTLSClientHello builds a TLS 1.2-style ClientHello carrying an SNI and
// an ALPN list — the two extensions the analyzer reads without decrypting
// anything (F3, §3.4.3, §3.5.4 priority 2).
func BuildTLSClientHello(sni string, alpn []string, ciphers []uint16) []byte {
	var body []byte
	body = append(body, 0x03, 0x03) // client_version TLS 1.2
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = append(body, 32) // session id length
	sid := make([]byte, 32)
	rand.Read(sid)
	body = append(body, sid...)

	cs := make([]byte, 2+2*len(ciphers))
	binary.BigEndian.PutUint16(cs[0:2], uint16(2*len(ciphers)))
	for i, c := range ciphers {
		binary.BigEndian.PutUint16(cs[2+2*i:], c)
	}
	body = append(body, cs...)
	body = append(body, 1, 0) // one compression method: null

	var exts []byte
	// server_name (0x0000)
	if sni != "" {
		nameEntry := append([]byte{0}, uint16be(len(sni))...)
		nameEntry = append(nameEntry, sni...)
		snExt := append(uint16be(len(nameEntry)), nameEntry...)
		exts = append(exts, ext(0x0000, snExt)...)
	}
	// application_layer_protocol_negotiation (0x0010)
	if len(alpn) > 0 {
		var list []byte
		for _, p := range alpn {
			list = append(list, byte(len(p)))
			list = append(list, p...)
		}
		exts = append(exts, ext(0x0010, append(uint16be(len(list)), list...))...)
	}
	// supported_groups (0x000a) and ec_point_formats (0x000b) — JA3 inputs
	exts = append(exts, ext(0x000a, []byte{0, 4, 0x00, 0x1d, 0x00, 0x17})...)
	exts = append(exts, ext(0x000b, []byte{1, 0})...)
	// supported_versions (0x002b)
	exts = append(exts, ext(0x002b, []byte{2, 0x03, 0x04})...)

	body = append(body, uint16be(len(exts))...)
	body = append(body, exts...)

	// Handshake header: type 1 (ClientHello) + 3-byte length
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// TLS record header: handshake (0x16), TLS 1.0 for compatibility
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func ext(typ uint16, data []byte) []byte {
	h := make([]byte, 4)
	binary.BigEndian.PutUint16(h[0:2], typ)
	binary.BigEndian.PutUint16(h[2:4], uint16(len(data)))
	return append(h, data...)
}

func uint16be(v int) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

// BuildARPRequest builds a "who has tpa? tell spa" request — the shape a
// lateral scan takes on the wire (F34/F36).
func BuildARPRequest(sha net.HardwareAddr, spa, tpa net.IP) []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:2], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(b[2:4], 0x0800) // protocol type: IPv4
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], 1) // opcode: request
	copy(b[8:14], sha)
	copy(b[14:18], spa.To4())
	copy(b[24:28], tpa.To4())
	return b
}

// checksum is the standard one's-complement Internet checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
