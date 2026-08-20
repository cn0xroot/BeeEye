package geoip

import "testing"

// TestCountryCentroidSane guards against a typo'd coordinate (e.g. lat/lon
// swapped, or a stray zero) slipping into the static table — this is what
// backfills Lat/Lon when a Country-tier mmdb resolves the country correctly
// but carries no Location record at all (see Lookup's doc comment).
func TestCountryCentroidSane(t *testing.T) {
	if len(countryCentroid) < 20 {
		t.Fatalf("countryCentroid has only %d entries, expected a broad table", len(countryCentroid))
	}
	for code, c := range countryCentroid {
		if len(code) != 2 {
			t.Errorf("country code %q is not 2 letters", code)
		}
		lat, lon := c[0], c[1]
		if lat < -90 || lat > 90 {
			t.Errorf("%s: lat %v out of range", code, lat)
		}
		if lon < -180 || lon > 180 {
			t.Errorf("%s: lon %v out of range", code, lon)
		}
		if lat == 0 && lon == 0 {
			t.Errorf("%s: centroid is 0,0 — Lookup treats that as \"no coordinate\" and would keep falling back", code)
		}
	}
	// A few real entries a caller is likely to rely on.
	for _, code := range []string{"US", "CN", "GB", "JP", "DE"} {
		if _, ok := countryCentroid[code]; !ok {
			t.Errorf("expected %s in countryCentroid", code)
		}
	}
}

func TestFirstOctetLatLon(t *testing.T) {
	if lat, lon, ok := firstOctetLatLon(8); !ok || lat == 0 || lon == 0 {
		t.Errorf("firstOctetLatLon(8) = %v,%v,%v — want a real Google coordinate", lat, lon, ok)
	}
	if _, _, ok := firstOctetLatLon(250); ok {
		t.Error("firstOctetLatLon(250) should not match any known range")
	}
}
