package procmap

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestParseHexAddrPort pins the byte order. /proc renders addresses as
// host-byte-order 32-bit words in hex, so reading them big-endian yields a
// plausible-looking but completely wrong address (127.0.0.1 becomes 1.0.0.127)
// — a bug that would silently attribute traffic to the wrong socket.
func TestParseHexAddrPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0100007F:0035", "127.0.0.1:53"},
		{"0101A8C0:01BB", "192.168.1.1:443"},
		{"00000000:1F90", "0.0.0.0:8080"},
		{"00000000000000000000000001000000:0050", "[::1]:80"},
		{"00000000000000000000000000000000:0016", "[::]:22"},
	}
	for _, c := range cases {
		got, err := parseHexAddrPort(c.in)
		if err != nil {
			t.Errorf("parseHexAddrPort(%q): %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("parseHexAddrPort(%q) = %s, want %s", c.in, got, c.want)
		}
	}

	for _, bad := range []string{"", "zzzz:0035", "0100007F", "0100007F:zz"} {
		if _, err := parseHexAddrPort(bad); err == nil {
			t.Errorf("parseHexAddrPort(%q) accepted malformed input", bad)
		}
	}
}

// TestLookupFindsOurOwnListener is the end-to-end check: open a real listener,
// then ask the resolver who owns it. The answer must be this test binary.
func TestLookupFindsOurOwnListener(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("no /proc/net/tcp on this system")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := netip.MustParseAddrPort(ln.Addr().String())
	r := New(10 * time.Millisecond)

	proc, ok := r.Lookup("tcp", addr)
	if !ok {
		t.Fatalf("did not resolve our own listener on %s", addr)
	}
	if proc.PID != os.Getpid() {
		t.Errorf("pid = %d, want this process (%d)", proc.PID, os.Getpid())
	}
	if proc.Comm == "" {
		t.Error("comm is empty")
	}
}

// TestRemoteAddressIsNotAttributed guards the boundary that matters most: a
// flow belonging to some other device must come back unattributed, not with a
// coincidental local process attached to it.
func TestRemoteAddressIsNotAttributed(t *testing.T) {
	r := New(time.Second)

	camera := netip.MustParseAddrPort("192.168.77.42:51234")
	if r.IsLocal(camera.Addr()) {
		t.Skip("192.168.77.42 is configured on this host; pick another fixture")
	}
	if _, _, ok := r.LookupFlow("tcp", camera, netip.MustParseAddrPort("104.16.20.5:443")); ok {
		t.Error("attributed another device's flow to a local process")
	}
}

func TestIsLocalRecognisesLoopback(t *testing.T) {
	r := New(time.Second)
	if !r.IsLocal(netip.MustParseAddr("127.0.0.1")) {
		t.Error("127.0.0.1 not recognised as local")
	}
	if r.IsLocal(netip.MustParseAddr("8.8.8.8")) {
		t.Error("8.8.8.8 reported as local")
	}
}
