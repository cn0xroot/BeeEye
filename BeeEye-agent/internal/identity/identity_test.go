package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"BeeEye/internal/model"
)

func TestIdentifyBuiltinOUI(t *testing.T) {
	r := Identify("b8:27:eb:11:22:33", "", Fingerprint{})
	if r.Vendor != "Raspberry Pi Foundation" || r.Category != model.CatNAS {
		t.Fatalf("got %+v", r)
	}
}

func TestIdentifyUnknownStaysUnknown(t *testing.T) {
	r := Identify("aa:bb:cc:dd:ee:ff", "", Fingerprint{})
	if r.Vendor != "Unknown" || r.Category != model.CatUnknown {
		t.Fatalf("got %+v", r)
	}
}

// TestLoadOUICSV covers the IEEE registry parser directly: a matching MA-L
// row is kept, a non-MA-L row (MA-M/MA-S — see loadOUICSV's doc comment for
// why those are out of scope) is skipped, and a short/malformed row does not
// abort the rest of the file.
func TestLoadOUICSV(t *testing.T) {
	csv := "Registry,Assignment,Organization Name,Organization Address\n" +
		"MA-L,AABBCC,Acme IoT Corp,1 Fake St\n" +
		"MA-M,AABBCCD,Small Block Co,2 Fake St\n" +
		"MA-L,,Empty Assignment Co,3 Fake St\n"
	vendors, err := loadOUICSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("loadOUICSV: %v", err)
	}
	if len(vendors) != 1 {
		t.Fatalf("want 1 entry, got %d: %+v", len(vendors), vendors)
	}
	if vendors["aabbcc"] != "Acme IoT Corp" {
		t.Fatalf("got %+v", vendors)
	}
}

// TestLoadOUIFileOverridesBuiltin verifies the file-backed table wins over
// the built-in one for a prefix present in both, and that an unrelated
// prefix still falls back to the built-in table (tiering, like geoip's
// mmdb-then-builtin chain).
func TestLoadOUIFileOverridesBuiltin(t *testing.T) {
	orig, origPath := ouiDB.vendors, ouiDB.path
	t.Cleanup(func() {
		ouiDB.mu.Lock()
		ouiDB.vendors, ouiDB.path = orig, origPath
		ouiDB.mu.Unlock()
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "oui.csv")
	// b827eb collides with the built-in Raspberry Pi entry on purpose, to
	// prove the loaded file takes priority.
	content := "Registry,Assignment,Organization Name,Organization Address\n" +
		"MA-L,B827EB,Overridden Vendor Inc,1 Fake St\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	LoadOUI(path)

	st := GetOUIStatus()
	if !st.Loaded || st.Entries != 1 || st.Source != "ieee-registry" {
		t.Fatalf("got status %+v", st)
	}
	if v, ok := lookupVendor("b827eb"); !ok || v != "Overridden Vendor Inc" {
		t.Fatalf("want overridden vendor, got %q ok=%v", v, ok)
	}
	// f0272d (Synology) only exists in the built-in table — must still resolve.
	if v, ok := lookupVendor("f0272d"); !ok || v != "Synology" {
		t.Fatalf("want builtin fallback, got %q ok=%v", v, ok)
	}
}

// TestLoadHintsFile verifies a device-fingerprints.yaml file's hostname
// section replaces the built-in hostnameHints and actually changes what
// Identify() returns, while an empty vendor_class section in the same file
// leaves vendorClassHints untouched (partial-override contract, so a user
// extending one section doesn't have to copy out the other three).
func TestLoadHintsFile(t *testing.T) {
	origHost, origVC, origUA, origSSDP := hostnameHints, vendorClassHints, userAgentHints, ssdpServerHints
	origStatus := hintStatus
	t.Cleanup(func() {
		hostnameHints, vendorClassHints, userAgentHints, ssdpServerHints = origHost, origVC, origUA, origSSDP
		hintStatus = origStatus
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "device-fingerprints.yaml")
	content := "hostname:\n  - { match: \"widget\", category: fridge }\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := LoadHints(path); err != nil {
		t.Fatalf("LoadHints: %v", err)
	}

	st := GetHintStatus()
	if !st.Loaded || st.Source != "config-file" {
		t.Fatalf("got status %+v", st)
	}

	r := Identify("aa:bb:cc:dd:ee:ff", "my-widget-9000", Fingerprint{})
	if r.Category != model.CatFridge {
		t.Fatalf("want fridge from loaded hint, got %+v", r)
	}
	if len(vendorClassHints) != len(origVC) {
		t.Fatalf("empty vendor_class section must leave vendorClassHints untouched")
	}
}

// TestLoadHintsMissingFileIsNotError mirrors config.LoadPortServiceMap's
// contract: a configured-but-absent path is not fatal, defaults stay active.
func TestLoadHintsMissingFileIsNotError(t *testing.T) {
	if err := LoadHints(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err != nil {
		t.Fatalf("missing file must not error, got %v", err)
	}
}
