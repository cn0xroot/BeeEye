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
