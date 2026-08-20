package geoip

// countryCentroid gives a representative lat/lon for an ISO 3166-1 alpha-2
// country code. It exists for one reason: a Country-tier MaxMind database
// (as opposed to City-tier) resolves the country correctly but carries no
// Location record at all — Lat/Lon come back zero. Snapping to the country's
// centroid when that happens is the standard, expected behavior for a
// country-level GeoIP map (the alternative is no point on the map at all,
// which is worse for a country BeeEye positively identified). Coordinates
// are deliberately coarse — capital-city-ish, not a precise centroid.
var countryCentroid = map[string][2]float64{
	"US": {39.8, -98.6}, "CA": {56.1, -106.3}, "MX": {23.6, -102.5},
	"BR": {-14.2, -51.9}, "AR": {-38.4, -63.6}, "CL": {-35.7, -71.5},
	"GB": {55.4, -3.4}, "IE": {53.4, -8.2}, "FR": {46.6, 2.2}, "DE": {51.2, 10.4},
	"NL": {52.1, 5.3}, "BE": {50.5, 4.5}, "CH": {46.8, 8.2}, "AT": {47.5, 14.6},
	"ES": {40.5, -3.7}, "PT": {39.4, -8.2}, "IT": {41.9, 12.6}, "PL": {51.9, 19.1},
	"SE": {60.1, 18.6}, "NO": {60.5, 8.5}, "DK": {56.3, 9.5}, "FI": {61.9, 25.7},
	"RU": {61.5, 105.3}, "UA": {48.4, 31.2}, "TR": {38.9, 35.2},
	"CN": {35.9, 104.2}, "HK": {22.3, 114.2}, "TW": {23.7, 121.0}, "MO": {22.2, 113.6},
	"JP": {36.2, 138.3}, "KR": {35.9, 127.8}, "KP": {40.3, 127.5},
	"IN": {20.6, 79.0}, "PK": {30.4, 69.3}, "BD": {23.7, 90.4}, "SG": {1.35, 103.8},
	"MY": {4.2, 108.0}, "TH": {15.9, 101.0}, "VN": {14.1, 108.3}, "PH": {12.9, 121.8},
	"ID": {-0.8, 113.9}, "AU": {-25.3, 133.8}, "NZ": {-41.5, 174.9},
	"SA": {23.9, 45.1}, "AE": {23.4, 53.8}, "IL": {31.0, 34.9}, "IR": {32.4, 53.7},
	"EG": {26.8, 30.8}, "ZA": {-30.6, 22.9}, "NG": {9.1, 8.7}, "KE": {-0.02, 37.9},
	"GR": {39.1, 21.8}, "RO": {45.9, 24.97}, "CZ": {49.8, 15.5}, "HU": {47.2, 19.5},
	"IS": {64.9, -19.0}, "LU": {49.8, 6.1}, "EE": {58.6, 25.0}, "LV": {56.9, 24.6},
	"LT": {55.2, 23.9}, "SK": {48.7, 19.7}, "SI": {46.1, 14.995}, "HR": {45.1, 15.2},
	"BG": {42.7, 25.5}, "RS": {44.0, 21.0}, "CO": {4.6, -74.3}, "PE": {-9.19, -75.0},
	"VE": {6.4, -66.6}, "EC": {-1.8, -78.2}, "CU": {21.5, -77.8},
	"NP": {28.4, 84.1}, "LK": {7.9, 80.7}, "MM": {21.9, 95.96}, "KH": {12.6, 104.9},
	"KZ": {48.0, 66.9}, "UZ": {41.4, 64.6}, "MN": {46.9, 103.8},
}

// firstOctetLatLon returns a coarse lat/lon for a range known to belong to a
// specific cloud/CDN operator, keyed by the same firstOctetTable used when no
// mmdb at all is loaded. Kept separate from the country-centroid path
// because these entries key off known infrastructure ranges rather than a
// country code, and stay useful even when a database returns a pseudo-country
// label instead of an ISO code (see the doc comment on lookupMMDBWithFallback).
func firstOctetLatLon(v4 byte) (float64, float64, bool) {
	if e, ok := firstOctetTable[int(v4)]; ok {
		return e.lat, e.lon, true
	}
	return 0, 0, false
}
