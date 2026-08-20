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
}

type Config struct {
	ListenAddr string     `yaml:"listen_addr"`
	DBPath     string     `yaml:"db_path"`
	WebDir     string     `yaml:"web_dir"`
	Interfaces Interfaces `yaml:"interfaces"`
	Detection  Detection  `yaml:"detection"`
	// SimulateSeed drives the built-in simulated capture source used when no
	// eBPF-capable kernel is attached (dev / demo mode).
	SimulateSeed int64 `yaml:"simulate_seed"`
	// PortServiceMapFile points at the user-editable port→service table (F24,
	// §3.5.4). Empty means "use the built-in defaults".
	PortServiceMapFile string `yaml:"port_service_map_file"`
}

// Default returns a config populated with the program.md baseline values.
func Default() *Config {
	c := &Config{
		ListenAddr:   ":8080",
		DBPath:       "./data/BeeEye.db",
		WebDir:       "./BeeEye-web/dist",
		SimulateSeed: 42,
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
