//go:build darwin

package procmap

import (
	"net/netip"
	"testing"
)

func TestParseLsof(t *testing.T) {
	in := []byte("p123\ncchrome\nLalice\nPTCP\nn192.168.1.5:50000->1.1.1.1:443\nn*:8080\n" +
		"p456\ncmDNSResponder\nLroot\nPUDP\nn*:5353\nn[fe80::1%en0]:123\nn*:*\n")
	socks, owners := parseLsof(in)

	get := func(proto, ap string) (Process, bool) {
		id, ok := socks[socketKey{proto, netip.MustParseAddrPort(ap)}]
		return owners[id], ok
	}
	if p, ok := get("tcp", "192.168.1.5:50000"); !ok || p.PID != 123 || p.Comm != "chrome" || p.User != "alice" {
		t.Errorf("tcp conn: %+v %v", p, ok)
	}
	if p, ok := get("tcp", "[::]:8080"); !ok || p.PID != 123 {
		t.Errorf("tcp wildcard: %+v %v", p, ok)
	}
	if p, ok := get("udp", "[::]:5353"); !ok || p.PID != 456 || p.Comm != "mDNSResponder" {
		t.Errorf("udp wildcard: %+v %v", p, ok)
	}
	if p, ok := get("udp", "[fe80::1]:123"); !ok || p.PID != 456 {
		t.Errorf("udp v6 zone: %+v %v", p, ok)
	}
	if len(socks) != 4 { // "*:*" 必须被忽略
		t.Errorf("got %d sockets, want 4", len(socks))
	}
}
