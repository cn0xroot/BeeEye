// Package config loads BeeEye runtime configuration (program.md §3.4.5).
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Interface describes one capture interface. Names are never hardcoded — any
// interface (wlan0/eth0/wlx*) may be declared (F16).
type Interface struct {
	Name string `yaml:"name"`
	Role string `yaml:"role"` // wifi_ap | wan_uplink | bridge ...
}

type Interfaces struct {
	Mode         string      `yaml:"mode"` // explicit | auto
	ExplicitList []Interface `yaml:"explicit_list"`
	AutoDiscover struct {
		ExcludePatterns []string `yaml:"exclude_patterns"`
	} `yaml:"auto_discover"`
}

// Detection thresholds (program.md §3.11). All tunable, not hardcoded (§3.11.3).
type Detection struct {
	Beacon struct {
		MinSamples   int     `yaml:"min_samples"`    // N_min, default 6
		CVThreshold  float64 `yaml:"cv_threshold"`   // default 0.15
		MinIntervalS float64 `yaml:"min_interval_s"` // 10
		MaxIntervalS float64 `yaml:"max_interval_s"` // 3600
		WindowMin    int     `yaml:"window_min"`     // 120
	} `yaml:"beacon"`
	RiskThresholds struct {
		High   int `yaml:"high"`   // 50
		Medium int `yaml:"medium"` // 30
		Low    int `yaml:"low"`    // 15
	} `yaml:"risk_thresholds"`
	AutoBlock bool `yaml:"auto_block"` // F38, default false
	Baseline  struct {
		MinDays     int     `yaml:"min_days"`      // history required in an hour-bucket before it can fire
		ZThreshold  float64 `yaml:"z_threshold"`   // |z| at or above this is an outlier
		MinStdDevKB float64 `yaml:"min_stddev_kb"` // floor for stddev, guards near-constant traffic
	} `yaml:"baseline"`
}

// ThreatIntel configures the public blocklist feed(s) merged into the
// detection engine's ThreatIntel (F29, internal/threatintel). Disabled
// entirely with enabled: false — the engine then runs on injected/demo
// entries only, exactly as before this existed.
type ThreatIntelConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Feeds        []string `yaml:"feeds"`         // names from threatintel.KnownFeeds
	RefreshHours int      `yaml:"refresh_hours"` // how often to re-fetch
	CacheDir     string   `yaml:"cache_dir"`     // last-good copy, survives a restart with no network
}

// MITMConfig configures F45's user-installed-certificate TLS interception
// (internal/mitm). On by default as of 2026-08-20 (explicit user decision,
// see CHANGELOG) — but "on" here only means the proxy is listening and a CA
// exists on disk. It decrypts nothing by itself: a device only becomes
// visible in plaintext once ITS owner installs BeeEye's CA and points that
// device's own proxy setting at this listener. No device is opted in by
// turning this flag on; each device opts itself in by trusting the cert.
type MITMConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`  // CONNECT proxy address, e.g. ":8443"
	CADir   string `yaml:"ca_dir"`  // where ca.pem / ca.key are read from and written to
	MaxLog  int    `yaml:"max_log"` // in-memory decrypted-exchange history depth, oldest evicted first
}

type Config struct {
	ListenAddr  string            `yaml:"listen_addr"`
	DBPath      string            `yaml:"db_path"`
	WebDir      string            `yaml:"web_dir"`
	Interfaces  Interfaces        `yaml:"interfaces"`
	Detection   Detection         `yaml:"detection"`
	ThreatIntel ThreatIntelConfig `yaml:"threat_intel"`
	MITM        MITMConfig        `yaml:"mitm"`
	// PortServiceMapFile points at the user-editable port→service table (F24,
	// §3.5.4). Empty means "use the built-in defaults".
	PortServiceMapFile string `yaml:"port_service_map_file"`
}

// Default returns a config populated with the program.md baseline values.
func Default() *Config {
	c := &Config{
		ListenAddr: ":8080",
		DBPath:     "./data/BeeEye.db",
		WebDir:     "./BeeEye-web/dist",
	}
	c.Interfaces.Mode = "explicit"
	c.Interfaces.ExplicitList = []Interface{
		{Name: "wlan0", Role: "wifi_ap"},
		{Name: "eth0", Role: "wan_uplink"},
	}
	c.Interfaces.AutoDiscover.ExcludePatterns = []string{"lo", "docker*", "veth*", "br-*"}
	c.Detection.Beacon.MinSamples = 6
	c.Detection.Beacon.CVThreshold = 0.15
	c.Detection.Beacon.MinIntervalS = 10
	c.Detection.Beacon.MaxIntervalS = 3600
	c.Detection.Beacon.WindowMin = 120
	c.Detection.RiskThresholds.High = 50
	c.Detection.RiskThresholds.Medium = 30
	c.Detection.RiskThresholds.Low = 15
	c.Detection.AutoBlock = false
	c.Detection.Baseline.MinDays = 5
	c.Detection.Baseline.ZThreshold = 3.0
	c.Detection.Baseline.MinStdDevKB = 8
	c.ThreatIntel.Enabled = true
	c.ThreatIntel.Feeds = []string{"spamhaus_drop"}
	c.ThreatIntel.RefreshHours = 24
	c.ThreatIntel.CacheDir = "./data/threatintel"
	c.MITM.Enabled = true
	c.MITM.Listen = ":8443"
	c.MITM.CADir = "./data/mitm"
	c.MITM.MaxLog = 500
	return c
}

// Load reads YAML config, overlaying defaults for any unset field.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil // fall back to defaults
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadPortServiceMap reads the user-editable port→service table (§3.5.4, F24).
// A missing file is not an error — the built-in table stays in effect.
func LoadPortServiceMap(path string) (map[int]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	m := map[int]string{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
