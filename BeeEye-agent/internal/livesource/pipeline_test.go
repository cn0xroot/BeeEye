package livesource

import (
	"net/netip"
	"os"
	"testing"

	"BeeEye/internal/detect"
	"BeeEye/internal/dissect"
	"BeeEye/internal/live"
	"BeeEye/internal/model"
)

// TestIsWirelessAsksTheKernelNotTheName checks against this machine's own
// real /sys/class/net rather than synthetic names: an oddly-named interface
// (a custom udev rule, a driver's own legacy convention like ath0/ra0) would
// still correctly report as wired/wireless with a kernel-backed check, which
// a naming heuristic ("starts with wl") cannot promise for a name it has
// never seen. Skips gracefully on a machine with no live wireless adapter
// rather than asserting a name pattern that would just reintroduce the bug
// this guards against.
func TestIsWirelessAsksTheKernelNotTheName(t *testing.T) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		t.Skip("no /sys/class/net on this host")
	}
	var sawWireless, sawWired bool
	for _, e := range entries {
		name := e.Name()
		_, err := os.Stat("/sys/class/net/" + name + "/phy80211")
		wireless := err == nil
		if got := isWireless(name); got != wireless {
			t.Errorf("isWireless(%q) = %v, want %v (per /sys/class/net/%s/phy80211)", name, got, wireless, name)
		}
		if wireless {
			sawWireless = true
		} else {
			sawWired = true
		}
	}
	if !sawWireless && !sawWired {
		t.Skip("no interfaces under /sys/class/net to check")
	}
	t.Logf("checked %d interfaces (saw wireless=%v, saw non-wireless=%v)", len(entries), sawWireless, sawWired)
}

// TestIsWirelessIgnoresName is the regression this whole change is for: a
// name that would have fooled the old "starts with wl" heuristic (or its
// opposite — a real wireless card that does NOT start with "wl") must not
// change the answer isWireless gives for a name that plainly does not exist
// on this machine at all, since a nonexistent path never has phy80211.
func TestIsWirelessIgnoresName(t *testing.T) {
	for _, name := range []string{"wlan-this-does-not-exist", "eth-also-fake", "ath0-fake", "ra0-fake"} {
		if isWireless(name) {
			t.Errorf("isWireless(%q) = true for an interface that does not exist", name)
		}
	}
}

// fakeSource is the minimal live.Source newPipeline needs just to construct
// a Pipeline for testing ingest/drainEvents directly — nothing here ever
// produces or consumes a packet.
type fakeSource struct{}

func (fakeSource) Name() string                { return "fake" }
func (fakeSource) Iface() string               { return "fake0" }
func (fakeSource) Packets() <-chan live.Packet { return nil }
func (fakeSource) Stats() live.Stats           { return live.Stats{} }
func (fakeSource) Close() error                { return nil }

// TestIsDeviceRejectsGroupAddresses is the guard on the bug that first shipped
// this pipeline: multicast IPs (224.0.0.251, ff02::fb) reached via group MACs
// (01:00:5e…, 33:33…) were landing in the device table as if they were real
// machines. A device is a unicast host on the LAN reached by a unicast MAC.
func TestIsDeviceRejectsGroupAddresses(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		mac  string
		want bool
	}{
		{"real host", "192.168.50.73", "f8:3d:c6:ec:67:3a", true},
		{"gateway", "192.168.50.1", "3c:7c:3f:6b:34:90", true},
		{"link-local unicast", "fe80::88c:9b0d:fba4:fd0d", "7c:ec:b1:e0:ea:2f", true},
		{"ipv4 multicast", "224.0.0.251", "01:00:5e:00:00:fb", false},
		{"ipv6 multicast", "ff02::fb", "33:33:00:00:00:fb", false},
		{"ipv4 mcast MAC on igmp", "224.0.0.22", "01:00:5e:00:00:16", false},
		{"broadcast MAC", "192.168.50.255", "ff:ff:ff:ff:ff:ff", false},
		{"public IP is not a device", "8.8.8.8", "f8:3d:c6:ec:67:3a", false},
		{"unicast host, group MAC", "192.168.50.9", "01:00:5e:00:00:09", false},
		{"empty MAC", "192.168.50.9", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := netip.ParseAddr(c.ip)
			if err != nil {
				t.Fatalf("bad test IP %q: %v", c.ip, err)
			}
			if got := isDevice(a, c.mac); got != c.want {
				t.Errorf("isDevice(%s, %s) = %v, want %v", c.ip, c.mac, got, c.want)
			}
		})
	}
}

func TestIsUnicastMAC(t *testing.T) {
	unicast := []string{"f8:3d:c6:ec:67:3a", "00:11:22:33:44:55", "3c:7c:3f:6b:34:90"}
	group := []string{"01:00:5e:00:00:fb", "33:33:00:00:00:fb", "ff:ff:ff:ff:ff:ff"}
	for _, m := range unicast {
		if !isUnicastMAC(m) {
			t.Errorf("%s should be unicast", m)
		}
	}
	for _, m := range group {
		if isUnicastMAC(m) {
			t.Errorf("%s should be a group address", m)
		}
	}
}

// TestFlowKeyIsDirectionless is what makes both halves of a conversation
// aggregate into one connection instead of two.
func TestFlowKeyIsDirectionless(t *testing.T) {
	a := &fakeResult{transport: "tcp", src: "192.168.50.73", sp: 51000, dst: "1.1.1.1", dp: 443}
	b := &fakeResult{transport: "tcp", src: "1.1.1.1", sp: 443, dst: "192.168.50.73", dp: 51000}
	if flowKey(a.result()) != flowKey(b.result()) {
		t.Error("the two directions of one flow produced different keys")
	}
}

type fakeResult struct {
	transport, src, dst string
	sp, dp              int
}

func (f *fakeResult) result() *dissect.Result {
	return &dissect.Result{
		Transport: f.transport, Src: f.src, Dst: f.dst,
		SrcPort: f.sp, DstPort: f.dp,
	}
}

// result builds a minimal dissect.Result for flowKey, which only reads the
// transport, addresses and ports.

// TestTieredDeviceFlowReportsImmediately is the AF_PACKET-path counterpart of
// the eBPF kernel's "lock/camera get every connection event, everything else
// gets aggregated" behavior (F5, bpf/BeeEye.bpf.c). A high-sensitivity
// device's very first packet on a new flow must be queued as its own event
// rather than only surfacing at the next flush.
func TestTieredDeviceFlowReportsImmediately(t *testing.T) {
	p := newPipeline(nil, fakeSource{}, true, nil, detect.ThreatIntel{})
	p.cats["c0:97:2f:aa:bb:cc"] = model.CatLock

	r := &dissect.Result{
		Transport: "tcp", Src: "192.168.50.9", Dst: "1.1.1.1",
		SrcPort: 51000, DstPort: 443, Length: 60,
		Fields: map[string][]string{
			"eth.src": {"c0:97:2f:aa:bb:cc"},
			"eth.dst": {"aa:bb:cc:dd:ee:ff"},
		},
	}
	p.ingest(r)

	evs := p.drainEvents()
	if len(evs) != 1 {
		t.Fatalf("got %d pending events, want 1", len(evs))
	}
	if evs[0].MAC != "c0:97:2f:aa:bb:cc" || evs[0].Packets != 1 || evs[0].Bytes != 60 {
		t.Errorf("unexpected event: %+v", evs[0])
	}

	key := flowKey(r)
	c := p.flows[key]
	if c == nil {
		t.Fatal("flow missing from p.flows after ingest")
	}
	if c.Packets != 0 || c.Bytes != 0 {
		t.Errorf("running totals not zeroed after firing event: packets=%d bytes=%d", c.Packets, c.Bytes)
	}

	// A second packet on the same flow accumulates normally and does not
	// fire another event — F5 wants the *event*, not every packet, logged
	// immediately.
	p.ingest(r)
	if evs := p.drainEvents(); len(evs) != 0 {
		t.Errorf("second packet on an already-open flow queued %d more events, want 0", len(evs))
	}
	if c.Packets != 1 || c.Bytes != 60 {
		t.Errorf("second packet not accumulated into running totals: packets=%d bytes=%d", c.Packets, c.Bytes)
	}
}

// TestUntieredDeviceFlowOnlyAggregates is the control: an ordinary device's
// new flow must not produce an immediate event, matching the kernel's
// "everything else goes into the aggregated snapshot" behavior.
func TestUntieredDeviceFlowOnlyAggregates(t *testing.T) {
	p := newPipeline(nil, fakeSource{}, true, nil, detect.ThreatIntel{})
	p.cats["2c:54:9a:aa:bb:cc"] = model.CatPhone

	r := &dissect.Result{
		Transport: "tcp", Src: "192.168.50.10", Dst: "1.1.1.1",
		SrcPort: 51001, DstPort: 443, Length: 60,
		Fields: map[string][]string{
			"eth.src": {"2c:54:9a:aa:bb:cc"},
			"eth.dst": {"aa:bb:cc:dd:ee:ff"},
		},
	}
	p.ingest(r)

	if evs := p.drainEvents(); len(evs) != 0 {
		t.Errorf("untiered device queued %d events, want 0", len(evs))
	}
	c := p.flows[flowKey(r)]
	if c == nil || c.Packets != 1 || c.Bytes != 60 {
		t.Errorf("flow not aggregated normally: %+v", c)
	}
}
