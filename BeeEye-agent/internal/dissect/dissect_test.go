package dissect

import (
	"net"
	"strings"
	"testing"
	"time"

	"BeeEye/internal/dfilter"
	"BeeEye/internal/live"
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
