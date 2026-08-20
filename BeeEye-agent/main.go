// Command BeeEye-agent is the BeeEye (蜂眼) capture+analysis+API core.
//
// It loads config, opens SQLite, and captures live traffic — the same
// AF_PACKET capture the analyzer uses (internal/livesource) — folding it into
// devices, connections and DNS records, running the detection engine
// (program.md §3.11) over the rolling window, and serving the REST API the
// overview UI reads. When the kernel refuses a raw socket, or -simulate is
// given, it falls back to the built-in simulated scenario and says so, so the
// data is never passed off as real (F43).
package main

import (
	"bufio"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"BeeEye/internal/api"
	"BeeEye/internal/capture"
	"BeeEye/internal/config"
	"BeeEye/internal/detect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/live"
	"BeeEye/internal/livesource"
	"BeeEye/internal/protocol"
	"BeeEye/internal/store"
)

// captureIface picks the interface to capture on. Names are never hardcoded
// (F16): it takes the first configured interface that actually exists on this
// host, and when none do — the shipped config lists wlan0/eth0, which many
// machines do not have — it falls back to the interface carrying the default
// route, and finally to "any". Without this, a config that does not match the
// hardware would silently drop the agent back to simulated data.
func captureIface(cfg *config.Config) string {
	if cfg.Interfaces.Mode == "explicit" {
		for _, e := range cfg.Interfaces.ExplicitList {
			if _, err := net.InterfaceByName(e.Name); err == nil {
				return e.Name
			}
		}
	}
	if dev := defaultRouteIface(); dev != "" {
		return dev
	}
	return live.AnyInterface
}

// defaultRouteIface returns the interface with the default route, read from
// /proc/net/route, so a laptop or gateway captures its real uplink rather than
// a loopback. Empty if it cannot be determined.
func defaultRouteIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway ... — destination 00000000 is the default.
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func main() {
	cfgPath := flag.String("config", "config/config.yaml", "path to config.yaml")
	forceSim := flag.Bool("simulate", false, "always use the built-in simulated scenario instead of live capture")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if v := os.Getenv("BEEEYE_LISTEN"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("BEEEYE_DB"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("BEEEYE_WEBDIR"); v != "" {
		cfg.WebDir = v
	}

	// user-editable port→service table (F24); missing file keeps the defaults
	if m, err := config.LoadPortServiceMap(cfg.PortServiceMapFile); err != nil {
		log.Fatalf("load port map: %v", err)
	} else if len(m) > 0 {
		protocol.SetPortServiceMap(m)
		log.Printf("port→service map: %d entries from %s", len(m), cfg.PortServiceMapFile)
	}

	// Load an offline GeoIP database if one is present, for accurate country /
	// province / city / operator (F22). Falls back to the built-in table.
	geoip.Load("", "")

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		log.Fatalf("mkdir data: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	badIP, badDomain, badJA3 := capture.DemoIntel()
	intel := detect.ThreatIntel{BadIPs: badIP, BadDomains: badDomain, BadJA3: badJA3}

	// --- capture: real traffic first, simulated only as a labelled fallback.
	//
	// The agent used to always run the simulated scenario, which is why the
	// overview and the analyzer disagreed. Now it captures the same live
	// traffic the analyzer does; the simulator is reserved for -simulate or
	// for a kernel that refuses a raw socket, and either way it is announced
	// so the data is never passed off as real (F43).
	var pipeline *livesource.Pipeline
	if !*forceSim {
		iface := captureIface(cfg)
		p, err := livesource.Open(st, iface, &cfg.Detection, intel)
		if err != nil {
			log.Printf("live capture unavailable (%v) — falling back to the simulated scenario", err)
		} else if !p.Live() {
			log.Printf("蜂眼 BeeEye: no raw-capture permission; SIMULATED traffic on %s. "+
				"Grant it with: sudo setcap cap_net_raw,cap_net_admin+ep ./BeeEye-agent/bin/BeeEye-agent", p.Iface())
			pipeline = p
		} else {
			log.Printf("蜂眼 BeeEye: capturing live on %s", p.Iface())
			pipeline = p
		}
	}
	if pipeline != nil {
		defer pipeline.Close()
	} else {
		// -simulate, or live.Open itself errored: seed the one-shot scenario.
		log.Printf("蜂眼 BeeEye: generating simulated scenario (seed=%d)…", cfg.SimulateSeed)
		sc, err := capture.GenerateSimulated(st, cfg.SimulateSeed)
		if err != nil {
			log.Fatalf("simulate: %v", err)
		}
		eng := &detect.Engine{Cfg: &cfg.Detection, Intel: intel, Cats: sc.Categories}
		conns, _ := st.Connections(store.ConnFilter{Limit: 100000})
		dnsRecs, _ := st.DNSRecords("", 100000)
		events := eng.Analyze(conns, dnsRecs, sc.BaselinePairs)
		for i := range events {
			if err := st.InsertEvent(&events[i]); err != nil {
				log.Printf("insert event: %v", err)
			}
		}
		log.Printf("detection complete: %d connections, %d dns records, %d risk events",
			len(conns), len(dnsRecs), len(events))
	}

	// --- serve API + SPA ---
	srv := api.New(st, cfg)
	if pipeline != nil && pipeline.Live() {
		srv.SetSource(true, pipeline.Iface(), "af_packet")
	} else if pipeline != nil {
		srv.SetSource(false, pipeline.Iface(), "simulated")
	} else {
		srv.SetSource(false, "", "simulated")
	}
	log.Printf("BeeEye API listening on %s  (web dir: %s)", cfg.ListenAddr, cfg.WebDir)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Routes()); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
