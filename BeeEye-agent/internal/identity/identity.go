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

// hostnameHints refine the category using DHCP hostname / mDNS names (§3.5.2).
var hostnameHints = []struct {
	sub string
	cat model.DeviceCategory
}{
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

// Result is the outcome of a passive identification pass.
type Result struct {
	Vendor     string
	ModelGuess string
	Category   model.DeviceCategory
}

// Identify infers vendor/model/category from a MAC and optional hostname.
func Identify(mac, hostname string) Result {
	r := Result{Vendor: "Unknown", ModelGuess: "", Category: model.CatUnknown}
	prefix := normalizeOUI(mac)
	if info, ok := ouiTable[prefix]; ok {
		r.Vendor = info.vendor
		r.ModelGuess = info.model
		r.Category = info.category
	}
	// Hostname hint overrides an unknown/ambiguous OUI category.
	h := strings.ToLower(hostname)
	for _, hint := range hostnameHints {
		if strings.Contains(h, hint.sub) {
			if r.Category == model.CatUnknown {
				r.Category = hint.cat
			}
			break
		}
	}
	return r
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
