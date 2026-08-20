package namemap

import (
	"net"
	"testing"
	"time"

	"BeeEye/internal/dissect"
	"BeeEye/internal/live"
)

func dissectFrame(b []byte) *dissect.Result {
	return dissect.New().Packet(live.Packet{
		Index: 1, TS: time.Unix(1700000000, 0), Iface: "test",
		Data: b, CapLen: len(b), OrigLen: len(b),
	})
}

var (
	devMAC = net.HardwareAddr{0x3c, 0x84, 0x6a, 0x11, 0x00, 0x02}
	gwMAC  = net.HardwareAddr{0x02, 0x42, 0xbe, 0xee, 0x00, 0x01}
	devIP  = net.IPv4(192, 168, 1, 11)
	dnsIP  = net.IPv4(192, 168, 1, 1)
	cdnIP  = net.IPv4(104, 16, 20, 5)
)

func TestLearnsFromDNSAnswer(t *testing.T) {
	m := New(0)
	resp := live.BuildDNSResponse(1, "ota.hikvision.com", []net.IP{cdnIP}, 300, 0)
	m.Learn(dissectFrame(live.BuildEthernet(devMAC, gwMAC, 0x0800,
		live.BuildIPv4(dnsIP, devIP, 17, 64, 1, live.BuildUDP(53, 51000, resp)))))

	name, src := m.Lookup("104.16.20.5")
	if name != "ota.hikvision.com" {
		t.Errorf("name = %q, want ota.hikvision.com", name)
	}
	if src != SourceDNS {
		t.Errorf("source = %q, want dns", src)
	}
}

func TestLearnsFromSNIWhenDNSWasMissed(t *testing.T) {
	// The common real case: the capture started after the device had already
	// resolved the name, so DNS is not in the trace but the SNI is.
	m := New(0)
	hello := live.BuildTLSClientHello("mqtt.tuya.com", []string{"h2"}, []uint16{0x1301})
	m.Learn(dissectFrame(live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, net.IPv4(118, 31, 9, 4), 6, 64, 2,
			live.BuildTCP(49555, 443, 1, 1, live.TCPPsh|live.TCPAck, hello)))))

	name, src := m.Lookup("118.31.9.4")
	if name != "mqtt.tuya.com" || src != SourceSNI {
		t.Errorf("got %q via %q, want mqtt.tuya.com via sni", name, src)
	}
}

func TestDNSOutranksHTTPHost(t *testing.T) {
	m := New(0)
	req := "GET / HTTP/1.1\r\nHost: cdn.example.net:8080\r\n\r\n"
	m.Learn(dissectFrame(live.BuildEthernet(gwMAC, devMAC, 0x0800,
		live.BuildIPv4(devIP, cdnIP, 6, 64, 3,
			live.BuildTCP(49556, 80, 1, 1, live.TCPPsh|live.TCPAck, []byte(req))))))

	if name, src := m.Lookup("104.16.20.5"); name != "cdn.example.net" || src != SourceHTTP {
		t.Fatalf("http host not learned: %q via %q", name, src)
	}

	resp := live.BuildDNSResponse(2, "assets.example.net", []net.IP{cdnIP}, 300, 0)
	m.Learn(dissectFrame(live.BuildEthernet(devMAC, gwMAC, 0x0800,
		live.BuildIPv4(dnsIP, devIP, 17, 64, 4, live.BuildUDP(53, 51001, resp)))))

	name, src := m.Lookup("104.16.20.5")
	if src != SourceDNS || name != "assets.example.net" {
		t.Errorf("got %q via %q; a DNS answer must outrank a Host header", name, src)
	}
	// Both names must still be visible — one address commonly serves many.
	if all := m.All("104.16.20.5"); len(all) != 2 {
		t.Errorf("All returned %d names, want both", len(all))
	}
}

func TestUnknownAddressStaysNameless(t *testing.T) {
	m := New(0)
	if name, _ := m.Lookup("8.8.4.4"); name != "" {
		t.Errorf("invented the name %q for an address no traffic named", name)
	}
}
