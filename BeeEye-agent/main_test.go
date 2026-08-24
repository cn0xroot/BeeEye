package main

import (
	"net"
	"os/exec"
	"testing"
	"time"

	"BeeEye/internal/config"
	"BeeEye/internal/livesource"
)

// requireIPTool skips the test outright when the ip(8) tool or the
// permission to add a dummy interface is unavailable (e.g. an unprivileged
// CI sandbox), rather than failing a test that legitimately cannot run there.
func requireIPTool(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip(8) not available")
	}
}

func addDummy(t *testing.T, name string) {
	t.Helper()
	if out, err := exec.Command("ip", "link", "add", name, "type", "dummy").CombinedOutput(); err != nil {
		t.Skipf("cannot create dummy interface %s (%v): %s", name, err, out)
	}
	t.Cleanup(func() { exec.Command("ip", "link", "del", name).Run() })
	if out, err := exec.Command("ip", "link", "set", "dev", name, "up").CombinedOutput(); err != nil {
		t.Fatalf("bring up %s: %v: %s", name, err, out)
	}
}

// TestCaptureIfaceReactsToHotplug is the real-kernel counterpart to
// internal/live's netlink parsing tests: it proves captureIface itself — not
// just the netlink message parser — sees a configured interface the moment
// it exists, which is the other half of F20 (the WatchLinks event only tells
// the supervisor *when* to re-call captureIface; this is what makes that
// re-call actually pick the new NIC up).
func TestCaptureIfaceReactsToHotplug(t *testing.T) {
	requireIPTool(t)
	const name = "beeeye-texp0" // Linux interface names cap at IFNAMSIZ-1 = 15 chars

	cfg := config.Default()
	cfg.Interfaces.Mode = "explicit"
	cfg.Interfaces.ExplicitList = []config.Interface{{Name: name, Role: "test"}}

	before := captureIface(cfg)
	if before == name {
		t.Fatalf("captureIface returned %q before the interface exists — test setup is wrong", name)
	}

	addDummy(t, name)
	// ip link add is synchronous by the time CombinedOutput returns, but give
	// the kernel a moment to settle before re-checking via net.InterfaceByName.
	time.Sleep(50 * time.Millisecond)

	after := captureIface(cfg)
	if after != name {
		t.Errorf("captureIface after hotplug = %q, want %q", after, name)
	}
}

// TestAutoDiscoverIfaceHonorsExcludePatterns proves auto_discover.exclude_patterns
// (present in config.yaml since the start but never actually consulted until
// F20) really does keep a matching interface out of consideration, using a
// real dummy NIC rather than a synthetic net.Interface value.
func TestAutoDiscoverIfaceHonorsExcludePatterns(t *testing.T) {
	requireIPTool(t)
	const name = "beeeye-t-veth0"
	addDummy(t, name)
	time.Sleep(50 * time.Millisecond)

	cfg := config.Default()
	cfg.Interfaces.Mode = "auto"
	cfg.Interfaces.AutoDiscover.ExcludePatterns = []string{"beeeye-t-*"}

	if got := autoDiscoverIface(cfg); got == name {
		t.Errorf("autoDiscoverIface returned %q, which matches an exclude pattern", name)
	}

	cfg.Interfaces.AutoDiscover.ExcludePatterns = nil
	if got := autoDiscoverIface(cfg); got != name {
		// Only meaningful when there is no other up, non-excluded interface
		// racing for the pick (default route, real Wi-Fi, etc.) — on a
		// developer machine there usually is, so this half is a soft check.
		t.Logf("autoDiscoverIface without exclusions = %q (informational: other real interfaces may legitimately win)", got)
	}
}

// TestResolveExplicitInterfaceExactNameWins is the non-regression half of the
// F16 name-compatibility fix: an operator who already configured the right
// name for their hardware must never be second-guessed by role-based
// substitution, even if the role looks wrong for that interface.
func TestResolveExplicitInterfaceExactNameWins(t *testing.T) {
	requireIPTool(t)
	const name = "beeeye-t-exact0"
	addDummy(t, name)
	time.Sleep(50 * time.Millisecond)

	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	// Role deliberately mismatched (a dummy interface is never wireless) to
	// prove the exact-name branch returns before role is even consulted.
	got := resolveExplicitInterface(config.Interface{Name: name, Role: "wifi_ap"}, ifs)
	if got != name {
		t.Errorf("resolveExplicitInterface = %q, want exact configured name %q", got, name)
	}
}

// TestResolveExplicitInterfaceRoleFallbackWanUplink is the regression case
// this whole change is for: a configured name that does not exist on this
// host (every machine's kernel names interfaces differently) must still
// resolve to a real interface, chosen by Role rather than by guessing at a
// name pattern. wan_uplink is checked against a real dummy NIC, which
// IsWireless always reports non-wireless for (no phy80211), so this needs no
// real hardware and cannot flake on a machine without Wi-Fi.
func TestResolveExplicitInterfaceRoleFallbackWanUplink(t *testing.T) {
	requireIPTool(t)
	const name = "beeeye-t-wan0"
	addDummy(t, name)
	time.Sleep(50 * time.Millisecond)

	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	got := resolveExplicitInterface(config.Interface{Name: "this-name-does-not-exist-on-this-host", Role: "wan_uplink"}, ifs)
	if got == "" {
		t.Fatal("resolveExplicitInterface returned \"\" — want it to fall back to a real non-wireless interface")
	}
	if livesource.IsWireless(got) {
		t.Errorf("resolveExplicitInterface picked %q for role wan_uplink, but it is wireless", got)
	}
}

// TestResolveExplicitInterfaceRoleFallbackWifiAp is the Wi-Fi half of the
// same fallback, exercised against this host's own real wireless adapter (if
// any) rather than a synthetic interface — a dummy NIC cannot be made to
// report phy80211, so there is no portable way to fake this one. Skips
// gracefully on a machine with no live wireless adapter, same convention as
// internal/livesource's TestIsWirelessAsksTheKernelNotTheName.
func TestResolveExplicitInterfaceRoleFallbackWifiAp(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	haveWireless := false
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && livesource.IsWireless(i.Name) {
			haveWireless = true
			break
		}
	}
	if !haveWireless {
		t.Skip("no up wireless interface on this host")
	}

	got := resolveExplicitInterface(config.Interface{Name: "this-name-does-not-exist-on-this-host", Role: "wifi_ap"}, ifs)
	if got == "" {
		t.Fatal("resolveExplicitInterface returned \"\" — want it to fall back to a real wireless interface")
	}
	if !livesource.IsWireless(got) {
		t.Errorf("resolveExplicitInterface picked %q for role wifi_ap, but it is not wireless", got)
	}
}

// TestResolveExplicitInterfaceUnknownRoleReturnsEmpty proves an unrecognized
// or empty Role never falls through to an arbitrary interface — silently
// capturing the wrong NIC would be worse than the caller's own further
// fallback (defaultRouteIface, then "any").
func TestResolveExplicitInterfaceUnknownRoleReturnsEmpty(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	got := resolveExplicitInterface(config.Interface{Name: "this-name-does-not-exist-on-this-host", Role: "some-made-up-role"}, ifs)
	if got != "" {
		t.Errorf("resolveExplicitInterface = %q, want \"\" for an unrecognized role", got)
	}
}
