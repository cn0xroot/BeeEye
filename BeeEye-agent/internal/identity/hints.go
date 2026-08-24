// Optional user-editable device-fingerprint hint table (F1 gap: the built-in
// hostnameHints/vendorClassHints/userAgentHints/ssdpServerHints in
// identity.go are a small illustrative set). Mirrors
// config.LoadPortServiceMap / protocol.SetPortServiceMap exactly (see
// internal/protocol/protocol.go) — a local YAML file the user extends with
// vendor-specific strings they've observed on their own network, no
// recompile, no network call.
package identity

import (
	"os"

	"gopkg.in/yaml.v3"

	"BeeEye/internal/model"
)

// hintRule is one row of config/device-fingerprints.yaml. Vendor is only
// meaningful under vendor_class (DHCP option 60 sometimes self-identifies the
// vendor, e.g. "hikvision"); the other three sections only ever refine
// category, matching hostnameHints/userAgentHints/ssdpServerHints's shape.
type hintRule struct {
	Match    string `yaml:"match"`
	Category string `yaml:"category"`
	Vendor   string `yaml:"vendor,omitempty"`
}

// hintFile is config/device-fingerprints.yaml's top-level shape.
type hintFile struct {
	Hostname    []hintRule `yaml:"hostname"`
	VendorClass []hintRule `yaml:"vendor_class"`
	UserAgent   []hintRule `yaml:"user_agent"`
	SSDPServer  []hintRule `yaml:"ssdp_server"`
}

var hintStatus struct {
	loaded bool
	path   string
	count  int
}

// HintStatus reports whether the curated hint table is the built-in
// ~40-entry set or a loaded file, and how many rules are active.
type HintStatus struct {
	Loaded  bool   `json:"loaded"`
	Path    string `json:"path,omitempty"`
	Entries int    `json:"entries"`
	Source  string `json:"source"` // "config-file" | "builtin"
}

// GetHintStatus reports the current hint-table configuration for display.
func GetHintStatus() HintStatus {
	if hintStatus.loaded {
		return HintStatus{Loaded: true, Path: hintStatus.path, Entries: hintStatus.count, Source: "config-file"}
	}
	n := len(hostnameHints) + len(vendorClassHints) + len(userAgentHints) + len(ssdpServerHints)
	return HintStatus{Loaded: false, Entries: n, Source: "builtin"}
}

// LoadHints reads the user-editable fingerprint hint table at path. A
// missing file is not an error — the built-in hint slices in identity.go
// stay in effect, same as config.LoadPortServiceMap's contract. An empty
// section in the file leaves that section's built-in rules untouched, so a
// user extending only "hostname" doesn't have to also copy out the other
// three.
func LoadHints(path string) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var hf hintFile
	if err := yaml.Unmarshal(b, &hf); err != nil {
		return err
	}
	n := 0
	if rules := toCatHints(hf.Hostname); len(rules) > 0 {
		hostnameHints = rules
		n += len(rules)
	}
	if rules := toVendorClassHints(hf.VendorClass); len(rules) > 0 {
		vendorClassHints = rules
		n += len(rules)
	}
	if rules := toCatHints(hf.UserAgent); len(rules) > 0 {
		userAgentHints = rules
		n += len(rules)
	}
	if rules := toCatHints(hf.SSDPServer); len(rules) > 0 {
		ssdpServerHints = rules
		n += len(rules)
	}
	hintStatus.loaded = true
	hintStatus.path = path
	hintStatus.count = n
	return nil
}

func toCatHints(rules []hintRule) []catHint {
	if len(rules) == 0 {
		return nil
	}
	out := make([]catHint, 0, len(rules))
	for _, r := range rules {
		if r.Match == "" || r.Category == "" {
			continue
		}
		out = append(out, catHint{sub: r.Match, cat: model.DeviceCategory(r.Category)})
	}
	return out
}

func toVendorClassHints(rules []hintRule) []struct {
	sub    string
	vendor string
	cat    model.DeviceCategory
} {
	if len(rules) == 0 {
		return nil
	}
	out := make([]struct {
		sub    string
		vendor string
		cat    model.DeviceCategory
	}, 0, len(rules))
	for _, r := range rules {
		if r.Match == "" || r.Category == "" {
			continue
		}
		out = append(out, struct {
			sub    string
			vendor string
			cat    model.DeviceCategory
		}{sub: r.Match, vendor: r.Vendor, cat: model.DeviceCategory(r.Category)})
	}
	return out
}
