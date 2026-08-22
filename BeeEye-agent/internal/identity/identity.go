// Package identity performs passive device identification (program.md §3.5.2).
//
// Signals combined here: MAC OUI prefix (vendor), plus DHCP/mDNS/SSDP hints
// passed in as a hostname string. The full Fingerbank dataset is out of scope
// for the slice; a compact built-in OUI table demonstrates the mechanism.
package identity

import (
	"strings"

	"BeeEye/internal/model"
)

type ouiInfo struct {
	vendor   string
	category model.DeviceCategory
	model    string
}

// ouiTable maps a normalized 6-hex OUI prefix to vendor + a category guess.
// Prefixes here are illustrative (well-known IoT vendors).
var ouiTable = map[string]ouiInfo{
	"b827eb": {"Raspberry Pi Foundation", model.CatNAS, "Raspberry Pi"},
	"dca632": {"Raspberry Pi Trading", model.CatNAS, "Raspberry Pi 4"},
	"001788": {"Philips Lighting (Hue)", model.CatSpeaker, "Hue Bridge"},
	"ec71db": {"Shenzhen Reecam (IPCam)", model.CatCamera, "IP Camera"},
	"3c8427": {"Hangzhou Hikvision", model.CatCamera, "Hikvision Cam"},
	"a4da22": {"Dahua Technology", model.CatCamera, "Dahua Cam"},
	"c0972f": {"August Home (Smart Lock)", model.CatLock, "August Lock"},
	"d83134": {"Yale / ASSA ABLOY", model.CatLock, "Yale Lock"},
	"f0272d": {"Synology", model.CatNAS, "Synology NAS"},
	"0011d8": {"ASUSTek (Router)", model.CatRouter, "ASUS Router"},
	"7c2ebd": {"TP-Link", model.CatRouter, "TP-Link Router"},
	"606bff": {"Samsung Electronics", model.CatTV, "Samsung TV"},
	"8c79f5": {"LG Electronics", model.CatTV, "LG TV"},
	"a45e60": {"Apple", model.CatPhone, "iPhone"},
	"f0189e": {"Apple", model.CatLaptop, "MacBook"},
	"2c549a": {"Xiaomi", model.CatPhone, "Xiaomi Phone"},
	"04d3b0": {"Intel (PC)", model.CatLaptop, "Windows PC"},
	"b0e5ed": {"Haier (Smart Fridge)", model.CatFridge, "Smart Fridge"},
	"18b430": {"Nest Labs (Google)", model.CatSpeaker, "Nest Speaker"},
	"44650d": {"Amazon (Echo)", model.CatSpeaker, "Echo Dot"},
}

// catHint maps a substring of some passively-observed string (hostname,
// User-Agent, SSDP Server header, ...) to a device category guess.
type catHint struct {
	sub string
	cat model.DeviceCategory
}

// hostnameHints refine the category using DHCP hostname / mDNS names (§3.5.2).
var hostnameHints = []catHint{
	{"cam", model.CatCamera},
	{"ipc", model.CatCamera},
	{"lock", model.CatLock},
	{"door", model.CatLock},
	{"nas", model.CatNAS},
	{"synology", model.CatNAS},
	{"router", model.CatRouter},
	{"gateway", model.CatRouter},
	{"tv", model.CatTV},
	{"iphone", model.CatPhone},
	{"android", model.CatPhone},
	{"macbook", model.CatLaptop},
	{"pc", model.CatLaptop},
	{"echo", model.CatSpeaker},
	{"nest", model.CatSpeaker},
	{"fridge", model.CatFridge},
}

// vendorClassHints refine the category (and, when still unknown, the vendor)
// from DHCP option 60 — many device families self-report a distinctive
// prefix here (Android's DHCP client, embedded camera/NVR firmware, Windows'
// "MSFT" string, busybox udhcpc used by most embedded Linux routers/APs).
// Illustrative examples, not a full Fingerbank dataset (see package doc).
var vendorClassHints = []struct {
	sub    string
	vendor string
	cat    model.DeviceCategory
}{
	{"android-dhcp", "", model.CatPhone},
	{"msft 5.0", "Microsoft", model.CatLaptop},
	{"udhcp", "", model.CatRouter},
	{"hikvision", "Hangzhou Hikvision", model.CatCamera},
	{"dahua", "Dahua Technology", model.CatCamera},
}

// userAgentHints refine the category from an HTTP User-Agent a device sent
// (a camera's web-UI heartbeat, a phone's browser, an NVR's firmware update
// check, ...).
var userAgentHints = []catHint{
	{"iphone", model.CatPhone},
	{"ipad", model.CatPhone},
	{"android", model.CatPhone},
	{"macintosh", model.CatLaptop},
	{"windows nt", model.CatLaptop},
	{"hikvision", model.CatCamera},
	{"dahua", model.CatCamera},
	{"dvrip", model.CatCamera},
}

// ssdpServerHints refine the category from SSDP's Server: header, which most
// UPnP-capable devices (NAS boxes, TVs, speakers, routers) send verbatim in
// their discovery responses.
var ssdpServerHints = []catHint{
	{"synology", model.CatNAS},
	{"dlna", model.CatTV},
	{"sonos", model.CatSpeaker},
	{"roku", model.CatTV},
}

// Result is the outcome of a passive identification pass.
type Result struct {
	Vendor     string
	ModelGuess string
	Category   model.DeviceCategory
}

// Fingerprint carries the passive signals a device's own traffic exposes —
// the same data a real Fingerbank-style matcher keys on (F1's gap). Every
// field is optional; Identify only uses what is non-empty, so a device that
// never sent DHCP/HTTP/SSDP traffic is identified exactly as before, from
// MAC OUI and hostname alone.
type Fingerprint struct {
	// DHCPParams is DHCP option 55 (parameter request list), e.g.
	// "1,3,6,15,119,252". It is carried through but not yet matched against
	// a signature table: unlike VendorClass/UserAgent/SSDPServer, which are
	// vendor-chosen human-readable strings, option 55's request-list values
	// only distinguish device *stacks* against a large vetted reference
	// database (what Fingerbank actually sells) — fabricating one here would
	// misattribute devices with false confidence, so this field is a
	// documented extension point rather than guessed at.
	DHCPParams  string
	VendorClass string // DHCP option 60
	UserAgent   string
	SSDPServer  string
}

// Identify infers vendor/model/category from a MAC, optional hostname, and
// whatever passive Fingerprint fields were observed. Signals are applied
// most-specific-first and only ever refine an unknown category — an OUI hit
// is never second-guessed by a weaker signal.
func Identify(mac, hostname string, fp Fingerprint) Result {
	r := Result{Vendor: "Unknown", ModelGuess: "", Category: model.CatUnknown}
	prefix := normalizeOUI(mac)
	if info, ok := ouiTable[prefix]; ok {
		r.Vendor = info.vendor
		r.ModelGuess = info.model
		r.Category = info.category
	}
	applyCatHint(&r, strings.ToLower(hostname), hostnameHints)
	if r.Category == model.CatUnknown && fp.VendorClass != "" {
		vc := strings.ToLower(fp.VendorClass)
		for _, h := range vendorClassHints {
			if strings.Contains(vc, h.sub) {
				r.Category = h.cat
				if h.vendor != "" && r.Vendor == "Unknown" {
					r.Vendor = h.vendor
				}
				break
			}
		}
	}
	applyCatHint(&r, strings.ToLower(fp.UserAgent), userAgentHints)
	applyCatHint(&r, strings.ToLower(fp.SSDPServer), ssdpServerHints)
	return r
}

// applyCatHint sets r.Category from the first matching hint, but only while
// the category is still unknown — a later, weaker signal must never override
// an earlier, more specific one.
func applyCatHint(r *Result, s string, hints []catHint) {
	if r.Category != model.CatUnknown || s == "" {
		return
	}
	for _, h := range hints {
		if strings.Contains(s, h.sub) {
			r.Category = h.cat
			return
		}
	}
}

// normalizeOUI extracts the lowercased first 3 bytes (6 hex chars) of a MAC.
func normalizeOUI(mac string) string {
	s := strings.ToLower(mac)
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(s) >= 6 {
		return s[:6]
	}
	return s
}
