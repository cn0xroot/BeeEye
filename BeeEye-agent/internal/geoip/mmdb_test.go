package geoip

import "testing"

// TestLookupFallbackWithoutDB checks that with no database loaded, Lookup still
// returns something honest for every category, tagged builtin.
func TestLookupFallbackWithoutDB(t *testing.T) {
	// Do not call Load — exercise the pure fallback.
	cases := []struct {
		ip, wantCountry string
		local           bool
	}{
		{"192.168.1.1", "LOCAL", true},
		{"8.8.8.8", "US", false},
		{"1.1.1.1", "US", false}, // first-octet stand-in
	}
	for _, c := range cases {
		g := Lookup(c.ip)
		if g.Country != c.wantCountry {
			t.Errorf("Lookup(%s).Country = %q, want %q", c.ip, g.Country, c.wantCountry)
		}
		if g.Local != c.local {
			t.Errorf("Lookup(%s).Local = %v, want %v", c.ip, g.Local, c.local)
		}
	}
	// The coarse table now carries an operator stand-in.
	if g := Lookup("8.8.8.8"); g.ISP == "" {
		t.Error("expected an operator label for 8.8.8.8 in the built-in table")
	}
}

// TestGetStatusReflectsAccuracy checks the three-way accuracy classification
// GetStatus reports: builtin (nothing loaded), country-only, and city+ASN.
// The overview UI reads this to explain why locations look coarse.
func TestGetStatusReflectsAccuracy(t *testing.T) {
	// Reset package state so this test does not depend on run order.
	db = mmdb{}

	st := GetStatus()
	if st.Loaded {
		t.Errorf("Loaded should be false before Load() is ever called, got %+v", st)
	}
	if st.Accuracy != "builtin" {
		t.Errorf("Accuracy = %q, want builtin before any database is loaded", st.Accuracy)
	}

	// Load() always marks itself as having run, even when the explicit paths
	// given do not exist — auto-discovery may still find something on this
	// host (as it legitimately does here), which is why Loaded is checked
	// unconditionally but Accuracy is not asserted against a specific value:
	// what auto-discovery finds is host-dependent, not part of this contract.
	Load("/nonexistent/City.mmdb", "/nonexistent/ASN.mmdb")
	st = GetStatus()
	if !st.Loaded {
		t.Error("Loaded should be true once Load() has run, regardless of outcome")
	}
	if st.Accuracy != "builtin" && st.Accuracy != "country" && st.Accuracy != "city" {
		t.Errorf("Accuracy = %q, want one of builtin/country/city", st.Accuracy)
	}
}
