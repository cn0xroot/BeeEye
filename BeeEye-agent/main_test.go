package main

import (
	"os/exec"
	"testing"
	"time"

	"BeeEye/internal/config"
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
