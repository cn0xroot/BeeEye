// Package geoip provides offline IP geolocation (program.md §3.5.5, F22).
//
// Per the privacy requirement (§3.9, non-functional "地理位置查询隐私"), lookups
// are 100% local — no per-IP calls to any third-party online API. A production
// build would load a MaxMind GeoLite2 .mmdb; here we ship a compact built-in
// table keyed by the first octet, which is sufficient for the demo dataset and
// keeps the binary self-contained. Private / CGNAT ranges are labeled LOCAL.
package geoip

import (
	"net"

	"BeeEye/internal/model"
)

type entry struct {
	country, region, city, isp string
	lat, lon                   float64
}

// firstOctetTable maps a leading octet to a representative geolocation. This is
// deliberately coarse — a stand-in for the offline mmdb database.
var firstOctetTable = map[int]entry{
	1:   {"US", "California", "Los Angeles", "Cloudflare", 34.05, -118.24}, // 1.1.1.1 style
	8:   {"US", "California", "Mountain View", "Google", 37.39, -122.08},   // 8.8.8.8
	13:  {"IE", "Leinster", "Dublin", "Microsoft", 53.33, -6.25},
	20:  {"US", "Virginia", "Ashburn", "Microsoft", 39.04, -77.49},
	23:  {"US", "Massachusetts", "Cambridge", "Akamai", 42.36, -71.10},
	34:  {"US", "Iowa", "Council Bluffs", "Google", 41.26, -95.86},
	35:  {"US", "Iowa", "Council Bluffs", "Google", 41.26, -95.86},
	45:  {"RU", "Moscow", "Moscow", "Selectel", 55.75, 37.61},
	47:  {"CN", "Zhejiang", "Hangzhou", "Alibaba", 30.29, 120.16},
	52:  {"US", "Oregon", "Boardman", "Amazon", 45.84, -119.70},
	101: {"CN", "Guangdong", "Shenzhen", "Tencent", 22.54, 114.06},
	103: {"HK", "Hong Kong", "Hong Kong", "Cloudflare", 22.32, 114.17},
	104: {"US", "California", "San Francisco", "Cloudflare", 37.77, -122.42},
	114: {"CN", "Beijing", "Beijing", "China Unicom", 39.90, 116.40},
	118: {"CN", "Shanghai", "Shanghai", "China Telecom", 31.23, 121.47},
	151: {"IT", "Lombardy", "Milan", "Fastweb", 45.46, 9.19},
	185: {"NL", "North Holland", "Amsterdam", "Various (EU)", 52.37, 4.90},
	193: {"DE", "Hesse", "Frankfurt", "Various (DE)", 50.11, 8.68},
	203: {"SG", "Singapore", "Singapore", "Various (SG)", 1.35, 103.82},
	216: {"US", "California", "San Jose", "Google", 37.34, -121.89},
}

// Lookup resolves ip to a GeoInfo entirely offline. Unknown public IPs get a
// best-effort "??" country so the UI never shows a fabricated location.
func Lookup(ip string) model.GeoInfo {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return model.GeoInfo{IP: ip, Country: "??"}
	}
	if IsPrivate(parsed) {
		return model.GeoInfo{IP: ip, Country: "LOCAL", Region: "Intranet", City: "Local", Local: true, Source: "builtin"}
	}
	// A real mmdb database wins when one is loaded: accurate country, province,
	// city and network operator (F22).
	if g, ok := lookupMMDB(parsed); ok {
		return g
	}
	if v4 := parsed.To4(); v4 != nil {
		if e, ok := firstOctetTable[int(v4[0])]; ok {
			return model.GeoInfo{IP: ip, Country: e.country, Region: e.region, City: e.city,
				ISP: e.isp, Lat: e.lat, Lon: e.lon, Source: "builtin"}
		}
	}
	return model.GeoInfo{IP: ip, Country: "??", Region: "Unknown", City: "Unknown", Source: "builtin"}
}

// IsPrivate reports whether ip is in a private, loopback, link-local or CGNAT
// (100.64.0.0/10) range — labeled "本地/内网" and skipped for geo lookup (§3.5.5).
func IsPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
	}
	return false
}

// IsPrivateStr is a string convenience wrapper.
func IsPrivateStr(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && IsPrivate(p)
}
