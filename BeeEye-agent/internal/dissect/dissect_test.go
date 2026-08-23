package dissect

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"BeeEye/internal/dfilter"
	"BeeEye/internal/live"
	"BeeEye/internal/pcapfile"
)

// frame wraps builder output as a captured packet.
func frame(b []byte) live.Packet {
	return live.Packet{Index: 1, TS: time.Unix(1700000000, 0), Iface: "wlan0",
		Data: b, CapLen: len(b), OrigLen: len(b)}
}

var (
	devMAC = net.HardwareAddr{0x3c, 0x84, 0x6a, 0x11, 0x00, 0x02}
	gwMAC  = net.HardwareAddr{0x02, 0x42, 0xbe, 0xee, 0x00, 0x01}
	devIP  = net.IPv4(192, 168, 1, 11)
	dnsIP  = net.IPv4(192, 168, 1, 1)
	extIP  = net.IPv4(47, 98, 44, 10)
)

func TestDissectDNSQuery(t *testing.T) {
	q := live.BuildDNSQuery(0x1234, "ota.hikvision.com")
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, dnsIP, 17, 64, 1, live.BuildUDP(51000, 53, q)))

	r := New().Packet(frame(f))

	if r.Proto != "DNS" {
		t.Errorf("proto = %q, want DNS", r.Proto)
	}
	if got := r.FieldValues("dns.qry.name"); len(got) != 1 || got[0] != "ota.hikvision.com" {
		t.Errorf("dns.qry.name = %v, want [ota.hikvision.com]", got)
	}
	if got := r.FieldValues("udp.port"); len(got) != 2 {
		t.Errorf("udp.port = %v, want both endpoints", got)
	}
	if !strings.Contains(r.Info, "ota.hikvision.com") {
		t.Errorf("info = %q, should name the queried domain", r.Info)
	}
	// The tree must cover ethernet, ip, udp and dns.
	if len(r.Layers) != 4 {
		var labels []string
		for _, l := range r.Layers {
			labels = append(labels, l.Label)
		}
		t.Errorf("got %d layers (%v), want 4", len(r.Layers), labels)
	}
}

func TestDissectDNSResponseWithCompression(t *testing.T) {
	// BuildDNSResponse uses a 0xC00C compression pointer for the answer name,
	// which is exactly the case a naive name reader gets wrong.
	resp := live.BuildDNSResponse(0x1234, "mqtt.tuya.com",
		[]net.IP{net.IPv4(118, 31, 9, 4), net.IPv4(118, 31, 9, 5)}, 300, 0)
	f := live.BuildEthernet(devMAC, gwMAC, 0x0800,
		live.BuildIPv4(dnsIP, devIP, 17, 64, 2, live.BuildUDP(53, 51000, resp)))

	r := New().Packet(frame(f))

	got := r.FieldValues("dns.a")
	if len(got) != 2 || got[0] != "118.31.9.4" || got[1] != "118.31.9.5" {
		t.Errorf("dns.a = %v, want both answers", got)
	}
	// Both answers carry the same (compressed) name, and the field index
	// stores distinct values, so one entry is the correct result — an empty
	// list would mean the 0xC00C pointer was not followed.
	if names := r.FieldValues("dns.resp.name"); len(names) != 1 ||
		names[0] != "mqtt.tuya.com" {
		t.Errorf("dns.resp.name = %v, compression pointer not followed", names)
	}
}

func TestDissectNXDOMAIN(t *testing.T) {
	resp := live.BuildDNSResponse(9, "kq3vwxyzab.example.net", nil, 0, 3)
	f := live.BuildEthernet(devMAC, gwMAC, 0x0800,
		live.BuildIPv4(dnsIP, devIP, 17, 64, 3, live.BuildUDP(53, 51000, resp)))

	r := New().Packet(frame(f))
	if got := r.FieldValues("dns.flags.rcode"); len(got) != 1 || got[0] != "3" {
		t.Errorf("rcode = %v, want [3] so the DGA detector can key on it (F33)", got)
	}
}

func TestDissectTLSClientHello(t *testing.T) {
	hello := live.BuildTLSClientHello("ota.hikvision.com",
		[]string{"h2", "http/1.1"},
		[]uint16{0x1301, 0x1302, 0xc02b, 0xc02f})
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 4,
			live.BuildTCP(49555, 443, 100, 200, live.TCPPsh|live.TCPAck, hello)))

	r := New().Packet(frame(f))

	if r.SNI != "ota.hikvision.com" {
		t.Errorf("SNI = %q, want ota.hikvision.com", r.SNI)
	}
	if len(r.ALPN) != 2 || r.ALPN[0] != "h2" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", r.ALPN)
	}
	// ALPN outranks the port table when naming the protocol (§3.5.4).
	if r.Proto != "HTTP/2 (TLS)" {
		t.Errorf("proto = %q, want the ALPN-derived name", r.Proto)
	}
	if len(r.JA3) != 32 {
		t.Errorf("JA3 = %q, want a 32-char md5 hex digest", r.JA3)
	}
}

func TestJA3IsStableAcrossSessions(t *testing.T) {
	// Two hellos from the same client differ in random and session id but must
	// hash identically — that is the entire point of the fingerprint (F3).
	mk := func() *Result {
		hello := live.BuildTLSClientHello("cdn.apple.com", []string{"h2"},
			[]uint16{0x1301, 0xc02f})
		f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
			live.BuildIPv4(devIP, extIP, 6, 64, 5,
				live.BuildTCP(49556, 443, 1, 1, live.TCPPsh|live.TCPAck, hello)))
		return New().Packet(frame(f))
	}
	a, b := mk(), mk()
	if a.JA3 == "" || a.JA3 != b.JA3 {
		t.Errorf("JA3 not stable: %q vs %q", a.JA3, b.JA3)
	}

	// A different cipher list must produce a different fingerprint.
	hello := live.BuildTLSClientHello("cdn.apple.com", []string{"h2"},
		[]uint16{0x1301, 0xc02f, 0xc030, 0x009c})
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 6,
			live.BuildTCP(49557, 443, 1, 1, live.TCPPsh|live.TCPAck, hello)))
	if c := New().Packet(frame(f)); c.JA3 == a.JA3 {
		t.Error("JA3 identical for different cipher lists")
	}
}

func TestDissectHTTPAndMQTT(t *testing.T) {
	req := "GET /firmware/check HTTP/1.1\r\nHost: ota.hikvision.com\r\n" +
		"User-Agent: hikvision-cam/1.4.2\r\n\r\n"
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 7,
			live.BuildTCP(49558, 80, 1, 1, live.TCPPsh|live.TCPAck, []byte(req))))
	r := New().Packet(frame(f))
	if r.Proto != "HTTP" {
		t.Errorf("proto = %q, want HTTP", r.Proto)
	}
	if got := r.FieldValues("http.user_agent"); len(got) != 1 || got[0] != "hikvision-cam/1.4.2" {
		t.Errorf("http.user_agent = %v — needed as a fingerprint signal (F1)", got)
	}
	if got := r.FieldValues("http.host"); len(got) != 1 || got[0] != "ota.hikvision.com" {
		t.Errorf("http.host = %v", got)
	}
}

func TestDissectSIPInvite(t *testing.T) {
	msg := "INVITE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.11:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: Alice <sip:alice@example.com>;tag=1928301774\r\n" +
		"To: Bob <sip:bob@example.com>\r\n" +
		"Call-ID: a84b4c76e66710@192.168.1.11\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:alice@192.168.1.11>\r\n\r\n"
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 17, 64, 8,
			live.BuildUDP(5060, 5060, []byte(msg))))
	r := New().Packet(frame(f))
	if r.Proto != "SIP" {
		t.Fatalf("proto = %q, want SIP", r.Proto)
	}
	if r.Info != "INVITE sip:bob@example.com" {
		t.Errorf("Info = %q", r.Info)
	}
	if got := r.FieldValues("sip.from"); len(got) != 1 || got[0] != "Alice <sip:alice@example.com>;tag=1928301774" {
		t.Errorf("sip.from = %v", got)
	}
	if got := r.FieldValues("sip.call_id"); len(got) != 1 || got[0] != "a84b4c76e66710@192.168.1.11" {
		t.Errorf("sip.call_id = %v", got)
	}
	if got := r.FieldValues("sip.method"); len(got) != 1 || got[0] != "INVITE" {
		t.Errorf("sip.method = %v", got)
	}
}

// TestDissectSIPCompactHeaders guards the RFC 3261 §7.3.3 single-letter
// header forms — "f:"/"t:"/"i:" instead of "From:"/"To:"/"Call-ID:" — landing
// in the exact same filterable fields as their spelled-out forms, since a
// real phone/softswitch is free to send either.
func TestDissectSIPCompactHeaders(t *testing.T) {
	msg := "REGISTER sip:example.com SIP/2.0\r\n" +
		"f: sip:alice@example.com\r\n" +
		"t: sip:alice@example.com\r\n" +
		"i: reg-1928301774\r\n\r\n"
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 17, 64, 9,
			live.BuildUDP(5060, 5060, []byte(msg))))
	r := New().Packet(frame(f))
	if got := r.FieldValues("sip.from"); len(got) != 1 || got[0] != "sip:alice@example.com" {
		t.Errorf("sip.from (compact f:) = %v", got)
	}
	if got := r.FieldValues("sip.call_id"); len(got) != 1 || got[0] != "reg-1928301774" {
		t.Errorf("sip.call_id (compact i:) = %v", got)
	}
}

// TestDissectSIPNotConfusedWithHTTPOptions is the case that made "OPTIONS "
// alone unsafe as an HTTP/SIP discriminator: both protocols have an OPTIONS
// method, and only the trailing " SIP/2.0" vs " HTTP/1.1" tells them apart.
func TestDissectSIPNotConfusedWithHTTPOptions(t *testing.T) {
	sipMsg := "OPTIONS sip:carol@chicago.com SIP/2.0\r\nCall-ID: abc\r\n\r\n"
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 10,
			live.BuildTCP(49560, 5060, 1, 1, live.TCPPsh|live.TCPAck, []byte(sipMsg))))
	r := New().Packet(frame(f))
	if r.Proto != "SIP" {
		t.Errorf("SIP OPTIONS proto = %q, want SIP", r.Proto)
	}

	httpMsg := "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"
	f2 := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 11,
			live.BuildTCP(49561, 80, 1, 1, live.TCPPsh|live.TCPAck, []byte(httpMsg))))
	r2 := New().Packet(frame(f2))
	if r2.Proto != "HTTP" {
		t.Errorf("HTTP OPTIONS proto = %q, want HTTP", r2.Proto)
	}
}

// buildSCTP hand-assembles a minimal association: the 12-byte common header
// plus however many chunks are given, each padded to a 4-byte boundary per
// RFC 4960 §3.2 — there is no live.BuildSCTP helper, SCTP being a much
// rarer guest in this codebase's test fixtures than TCP/UDP.
func buildSCTP(sport, dport uint16, vtag uint32, chunks ...[]byte) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], sport)
	binary.BigEndian.PutUint16(out[2:4], dport)
	binary.BigEndian.PutUint32(out[4:8], vtag)
	// checksum (out[8:12]) is left zero — the dissector does not verify it
	for _, c := range chunks {
		out = append(out, c...)
		if pad := (4 - len(c)%4) % 4; pad > 0 {
			out = append(out, make([]byte, pad)...)
		}
	}
	return out
}

func sctpChunk(typ, flags byte, value []byte) []byte {
	c := make([]byte, 4+len(value))
	c[0], c[1] = typ, flags
	binary.BigEndian.PutUint16(c[2:4], uint16(4+len(value)))
	copy(c[4:], value)
	return c
}

func TestDissectSCTPInit(t *testing.T) {
	initBody := make([]byte, 16)                                              // initiate tag, a_rwnd, outbound/inbound streams, init TSN — contents unchecked here
	payload := buildSCTP(38412, 38412, 0x12345678, sctpChunk(1, 0, initBody)) // 1 = INIT
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 132, 64, 12, payload))
	r := New().Packet(frame(f))
	if r.Proto != "SCTP" {
		t.Fatalf("proto = %q, want SCTP", r.Proto)
	}
	if r.Info != "INIT" {
		t.Errorf("Info = %q, want INIT", r.Info)
	}
	if r.SrcPort != 38412 || r.DstPort != 38412 {
		t.Errorf("ports = %d/%d, want 38412/38412 (so this becomes a connection, not just an L2 curiosity)", r.SrcPort, r.DstPort)
	}
	if got := r.FieldValues("sctp.verification_tag"); len(got) != 1 || got[0] != "0x12345678" {
		t.Errorf("sctp.verification_tag = %v", got)
	}
}

// TestDissectSCTPDataBundledWithSack covers two things real SIGTRAN/S1AP
// traffic actually does: bundling more than one chunk in a single SCTP
// packet, and a DATA chunk's own header (stream ID, payload protocol id)
// being extracted rather than left as opaque bytes.
func TestDissectSCTPDataBundledWithSack(t *testing.T) {
	sackBody := make([]byte, 12) // cumulative TSN ack, a_rwnd, 0 gap-acks, 0 dup-TSNs
	dataHdr := make([]byte, 16)
	binary.BigEndian.PutUint32(dataHdr[0:4], 42)  // TSN
	binary.BigEndian.PutUint16(dataHdr[4:6], 3)   // stream ID
	binary.BigEndian.PutUint32(dataHdr[8:12], 18) // PPID 18 = S1AP, per 3GPP TS 36.412 — used here only as an arbitrary distinct number, not asserted by name (see dissectSCTP's doc comment on why PPIDs are not name-resolved)
	dataChunk := sctpChunk(0, 0, dataHdr)         // 0 = DATA
	sackChunk := sctpChunk(3, 0, sackBody)        // 3 = SACK
	payload := buildSCTP(38412, 38412, 0xaabbccdd, sackChunk, dataChunk)
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 132, 64, 13, payload))
	r := New().Packet(frame(f))
	if r.Info != "SACK, DATA" {
		t.Errorf("Info = %q, want %q — both bundled chunks should be listed", r.Info, "SACK, DATA")
	}
	if got := r.FieldValues("sctp.data_sid"); len(got) != 1 || got[0] != "3" {
		t.Errorf("sctp.data_sid = %v", got)
	}
	if got := r.FieldValues("sctp.data_ppid"); len(got) != 1 || got[0] != "18" {
		t.Errorf("sctp.data_ppid = %v", got)
	}
}

// TestDissectRawIPLinkType guards against the bug an imported vti/tunnel
// capture triggered: a frame with LINKTYPE_RAW has no link-layer header at
// all — Data starts with the IP header itself — and dissecting it as
// Ethernet misread the IP header's own bytes as a bogus 12-byte MAC pair,
// leaving everything past that (real src/dst, transport, app layer)
// unparsed. LinkType has to steer Packet away from dissectEthernet.
func TestDissectRawIPLinkType(t *testing.T) {
	req := "GET /firmware/check HTTP/1.1\r\nHost: ota.hikvision.com\r\n\r\n"
	raw := live.BuildIPv4(devIP, extIP, 6, 64, 7,
		live.BuildTCP(49558, 80, 1, 1, live.TCPPsh|live.TCPAck, []byte(req)))
	p := live.Packet{Index: 1, TS: time.Unix(1700000000, 0), Iface: "vti0",
		Data: raw, LinkType: pcapfile.LinkRaw, CapLen: len(raw), OrigLen: len(raw)}
	r := New().Packet(p)
	if r.Proto != "HTTP" {
		t.Fatalf("proto = %q, want HTTP — LinkRaw framing was not honored", r.Proto)
	}
	if r.Src != devIP.String() || r.Dst != extIP.String() {
		t.Errorf("src/dst = %s/%s, want %s/%s (real IPs, not bytes misread as MACs)",
			r.Src, r.Dst, devIP, extIP)
	}
	if got := r.FieldValues("http.host"); len(got) != 1 || got[0] != "ota.hikvision.com" {
		t.Errorf("http.host = %v", got)
	}
	// The DLT_RAW=12 spelling (see pcapfile.LinkRawBSD's comment) must behave
	// identically — same framing, different historical numeric assignment.
	p.LinkType = pcapfile.LinkRawBSD
	r2 := New().Packet(p)
	if r2.Proto != "HTTP" {
		t.Errorf("proto with LinkRawBSD = %q, want HTTP", r2.Proto)
	}
}

func TestDissectARP(t *testing.T) {
	f := live.BuildEthernet(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		devMAC, 0x0806,
		live.BuildARPRequest(devMAC, devIP, net.IPv4(192, 168, 1, 55)))
	r := New().Packet(frame(f))
	if r.Proto != "ARP" {
		t.Errorf("proto = %q, want ARP", r.Proto)
	}
	if got := r.FieldValues("arp.dst.proto_ipv4"); len(got) != 1 || got[0] != "192.168.1.55" {
		t.Errorf("arp target = %v — the lateral-scan signal (F34/F36)", got)
	}
}

func TestDissectCoAP(t *testing.T) {
	// GET /sensors/temp, token 0xABCD, MID 7 — hand-built per RFC 7252 §3
	// since there is no CoAP frame builder in internal/live yet.
	coap := []byte{
		0x42, 0x01, 0x00, 0x07, // ver=1 type=CON tkl=2 | code=0.01 GET | MID=7
		0xAB, 0xCD, // token
		0xB7, 's', 'e', 'n', 's', 'o', 'r', 's', // Uri-Path delta=11 len=7
		0x04, 't', 'e', 'm', 'p', // Uri-Path delta=0 len=4
	}
	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, dnsIP, 17, 64, 9, live.BuildUDP(51000, 5683, coap)))
	r := New().Packet(frame(f))
	if r.Proto != "CoAP" {
		t.Fatalf("proto = %q, want CoAP", r.Proto)
	}
	if r.Info != "GET /sensors/temp" {
		t.Errorf("Info = %q, want %q", r.Info, "GET /sensors/temp")
	}
	if got := r.FieldValues("coap.opt.uri_path"); len(got) != 2 || got[0] != "sensors" || got[1] != "temp" {
		t.Errorf("coap.opt.uri_path = %v, want [sensors temp]", got)
	}
	if got := r.FieldValues("coap.token"); len(got) != 1 || got[0] != "abcd" {
		t.Errorf("coap.token = %v, want [abcd]", got)
	}
	if got := r.FieldValues("coap.code"); len(got) != 1 || got[0] != "0.01" {
		t.Errorf("coap.code = %v, want [0.01]", got)
	}
}

func TestTruncatedPacketsDoNotPanic(t *testing.T) {
	// A snaplen-truncated ClientHello is completely ordinary on a real capture.
	hello := live.BuildTLSClientHello("example.com", []string{"h2"}, []uint16{0x1301})
	full := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 8,
			live.BuildTCP(49559, 443, 1, 1, live.TCPPsh|live.TCPAck, hello)))
	for n := 0; n <= len(full); n++ {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic dissecting a %d-byte truncated frame: %v", n, p)
				}
			}()
			New().Packet(frame(full[:n]))
		}()
	}

	coap := []byte{0x42, 0x01, 0x00, 0x07, 0xAB, 0xCD,
		0xB7, 's', 'e', 'n', 's', 'o', 'r', 's', 0x04, 't', 'e', 'm', 'p'}
	fullCoAP := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, dnsIP, 17, 64, 10, live.BuildUDP(51000, 5683, coap)))
	for n := 0; n <= len(fullCoAP); n++ {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic dissecting a %d-byte truncated CoAP frame: %v", n, p)
				}
			}()
			New().Packet(frame(fullCoAP[:n]))
		}()
	}
}

func TestDisplayFilterAgainstDissectedPackets(t *testing.T) {
	hello := live.BuildTLSClientHello("ota.hikvision.com", []string{"h2"},
		[]uint16{0x1301, 0xc02f})
	tlsPkt := New().Packet(frame(live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, extIP, 6, 64, 9,
			live.BuildTCP(49560, 443, 1, 1, live.TCPPsh|live.TCPAck, hello)))))

	dnsPkt := New().Packet(frame(live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, dnsIP, 17, 64, 10,
			live.BuildUDP(51000, 53, live.BuildDNSQuery(1, "mqtt.tuya.com"))))))

	cases := []struct {
		filter             string
		matchTLS, matchDNS bool
	}{
		{"", true, true},
		{"tls", true, false},
		{"dns", false, true},
		{"tcp.port == 443", true, false},
		{"udp.port == 53", false, true},
		{"tcp.port == 443 && tls", true, false},
		{"tls || dns", true, true},
		{"!dns", true, false},
		{"not tls", false, true},
		{"ip.addr == 192.168.1.0/24", true, true},
		{"ip.addr == 10.0.0.0/8", false, false},
		{"dns.qry.name contains tuya", false, true},
		{`tls.handshake.extensions_server_name matches "^ota\."`, true, false},
		{"ip.ttl >= 64", true, true},
		{"ip.ttl > 200", false, false},
		{"tcp.port != 443", false, false}, // absent field never matches
		{"(dns || tls) && ip.addr == 192.168.1.11", true, true},
	}
	for _, tc := range cases {
		e, err := dfilter.Compile(tc.filter)
		if err != nil {
			t.Errorf("Compile(%q): %v", tc.filter, err)
			continue
		}
		if got := e.Match(tlsPkt); got != tc.matchTLS {
			t.Errorf("filter %q on TLS packet = %v, want %v", tc.filter, got, tc.matchTLS)
		}
		if got := e.Match(dnsPkt); got != tc.matchDNS {
			t.Errorf("filter %q on DNS packet = %v, want %v", tc.filter, got, tc.matchDNS)
		}
	}
}

func TestFilterSyntaxErrors(t *testing.T) {
	for _, bad := range []string{"ip.src ==", "(tls", "tls &&", `dns.qry.name matches "([")`, "== 443"} {
		if _, err := dfilter.Compile(bad); err == nil {
			t.Errorf("Compile(%q) accepted invalid syntax", bad)
		}
	}
}

// TestDissectGTPUnwrapsInnerIP guards the reason "SIP over GTP" or "TLS over
// GTP" showed up as bare "UDP 2152" before this existed: a mobile core
// capture's actual phone traffic (TLS/HTTP/SIP/DNS/…) rides inside a GTP-U
// G-PDU wrapping a second, complete IP packet, and dissectGTP has to peel
// that back rather than stopping at the tunnel.
func TestDissectGTPUnwrapsInnerIP(t *testing.T) {
	innerHTTP := "GET /ping HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
	inner := live.BuildIPv4(devIP, extIP, 6, 64, 21,
		live.BuildTCP(51000, 80, 1, 1, live.TCPPsh|live.TCPAck, []byte(innerHTTP)))

	gtpHdr := []byte{
		0x30,       // flags: version=1, PT=1, no E/S/PN
		0xff,       // message type 255 = G-PDU
		0x00, 0x00, // length (unchecked by the dissector)
		0x00, 0x00, 0x00, 0x2a, // TEID = 0x2a
	}
	outer := append(append([]byte{}, gtpHdr...), inner...)

	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 17, 64, 30,
			live.BuildUDP(2152, 2152, outer)))
	r := New().Packet(frame(f))

	if !r.HasProtocol("gtp") {
		t.Fatalf("protocols = %v, want gtp present", r.Protocols)
	}
	if r.Proto != "HTTP" {
		t.Errorf("proto = %q, want HTTP (the inner packet's own protocol)", r.Proto)
	}
	if r.Src != devIP.String() || r.Dst != extIP.String() {
		t.Errorf("src/dst = %s/%s, want the INNER packet's %s/%s, not the GTP tunnel's own endpoints",
			r.Src, r.Dst, devIP, extIP)
	}
	if got := r.FieldValues("http.host"); len(got) != 1 || got[0] != "api.example.com" {
		t.Errorf("http.host = %v — inner HTTP was not reached", got)
	}
	if got := r.FieldValues("gtp.teid"); len(got) != 1 || got[0] != "0x0000002a" {
		t.Errorf("gtp.teid = %v", got)
	}
}

// TestDissectGSMTAPSIMSelect covers a full command+response frame the way
// SIMtrace-family capture tools commonly report one: a SELECT command
// immediately followed by the card's SW1/SW2, matching the real capture
// shape this dissector was written against.
func TestDissectGSMTAPSIMSelect(t *testing.T) {
	gsmtapHdr := []byte{
		0x02,       // version
		0x04,       // hdr_len (4 words = 16 bytes)
		0x04,       // type = SIM
		0x00,       // timeslot
		0x00, 0x00, // arfcn
		0x00,                   // signal_dbm
		0x00,                   // snr_db
		0x00, 0x00, 0x00, 0x00, // frame_number
		0x01, // sub_type
		0x00, // antenna_nr
		0x00, // sub_slot
		0x00, // res
	}
	// SELECT MF (CLA=00 INS=A4 P1=00 P2=04 Lc=02 Data=3F00), then SW=9000.
	apdu := []byte{0x00, 0xa4, 0x00, 0x04, 0x02, 0x3f, 0x00, 0x90, 0x00}
	payload := append(append([]byte{}, gsmtapHdr...), apdu...)

	f := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), 17, 64, 40,
			live.BuildUDP(47672, 4729, payload)))
	r := New().Packet(frame(f))

	if !r.HasProtocol("gsmtap") || !r.HasProtocol("sim") {
		t.Fatalf("protocols = %v, want gsmtap and sim", r.Protocols)
	}
	if r.Proto != "SIM" {
		t.Errorf("proto = %q, want SIM", r.Proto)
	}
	if r.Info != "SELECT MF : normal ending" {
		t.Errorf("Info = %q", r.Info)
	}
	if got := r.FieldValues("gsm_sim.file_id"); len(got) != 1 || got[0] != "MF" {
		t.Errorf("gsm_sim.file_id = %v", got)
	}
	if got := r.FieldValues("gsm_sim.apdu.sw"); len(got) != 1 || got[0] != "normal ending" {
		t.Errorf("gsm_sim.apdu.sw = %v", got)
	}
}

// TestSIMFileNameFallsBackToHex guards the "not exhaustive" honesty promise:
// an unrecognized file ID must not silently resolve to a guessed name.
func TestSIMFileNameFallsBackToHex(t *testing.T) {
	if got := simFileName(0x9999); got != "0x9999" {
		t.Errorf("simFileName(0x9999) = %q, want the raw hex fallback", got)
	}
	if got := simFileName(0x6f07); got != "EF.IMSI" {
		t.Errorf("simFileName(0x6f07) = %q, want EF.IMSI", got)
	}
}

// TestDissectGSMTAPSIMSelectByPathVsAID guards a real accuracy bug: a
// SELECT-by-path (P1=0x08, a sequence of 2-byte file IDs, e.g. ADF/EF.ECC)
// and a genuine SELECT-by-AID (P1=0x04, an arbitrary-length application
// identifier) can both carry a data field longer than 2 bytes — length
// alone cannot tell them apart, only P1 (ETSI TS 102.221 §11.1.1 Table
// 11.3) can. An earlier version of this labeled every multi-byte SELECT
// "AID=…", which is simply wrong for a path.
func TestDissectGSMTAPSIMSelectByPathVsAID(t *testing.T) {
	gsmtapHdr := []byte{0x02, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}

	// SELECT by path (P1=0x08): ADF (0x7fff) then EF.ECC (0x6fb7).
	pathAPDU := []byte{0x00, 0xa4, 0x08, 0x04, 0x04, 0x7f, 0xff, 0x6f, 0xb7, 0x61, 0x21}
	f1 := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), 17, 64, 41,
			live.BuildUDP(47672, 4729, append(append([]byte{}, gsmtapHdr...), pathAPDU...))))
	r1 := New().Packet(frame(f1))
	if r1.Info != "SELECT ADF/EF.ECC : 33 byte(s) of response data available (GET RESPONSE)" {
		t.Errorf("path select Info = %q", r1.Info)
	}
	if got := r1.FieldValues("gsm_sim.aid"); len(got) != 0 {
		t.Errorf("path select should not populate gsm_sim.aid, got %v", got)
	}

	// SELECT by AID (P1=0x04): the standard 3GPP USIM AID.
	aidBytes := []byte{0xa0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xff, 0x86, 0xff, 0xff, 0x89, 0xff, 0xff, 0xff, 0xff}
	aidAPDU := append([]byte{0x00, 0xa4, 0x04, 0x04, byte(len(aidBytes))}, aidBytes...)
	aidAPDU = append(aidAPDU, 0x61, 0x35)
	f2 := live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1), 17, 64, 42,
			live.BuildUDP(47672, 4729, append(append([]byte{}, gsmtapHdr...), aidAPDU...))))
	r2 := New().Packet(frame(f2))
	wantAID := "a0000000871002ff86ffff89ffffffff"
	if got := r2.FieldValues("gsm_sim.aid"); len(got) != 1 || got[0] != wantAID {
		t.Errorf("gsm_sim.aid = %v, want [%s]", got, wantAID)
	}
	if got := r2.FieldValues("gsm_sim.file_id"); len(got) != 0 {
		t.Errorf("AID select should not populate gsm_sim.file_id, got %v", got)
	}
}
