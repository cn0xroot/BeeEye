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
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"BeeEye/internal/api"
	"BeeEye/internal/capture"
	"BeeEye/internal/config"
	"BeeEye/internal/detect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/live"
	"BeeEye/internal/livesource"
	"BeeEye/internal/mitm"
	"BeeEye/internal/pcapfile"
	"BeeEye/internal/protocol"
	"BeeEye/internal/store"
	"BeeEye/internal/tcapture"
	"BeeEye/internal/threatintel"
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
	} else if cfg.Interfaces.Mode == "auto" {
		if dev := autoDiscoverIface(cfg); dev != "" {
			return dev
		}
	}
	if dev := defaultRouteIface(); dev != "" {
		return dev
	}
	return live.AnyInterface
}

// autoDiscoverIface implements interfaces.mode: auto (F16/F20): the interface
// carrying the default route wins if it isn't excluded, otherwise the first
// up, non-loopback interface not matching auto_discover.exclude_patterns.
// Never returns a name the exclude list matches — that list exists precisely
// so container/VPN/bridge interfaces (docker0, veth*, br-*) are never picked.
func autoDiscoverIface(cfg *config.Config) string {
	if dev := defaultRouteIface(); dev != "" && !excludedIface(cfg, dev) {
		return dev
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		if excludedIface(cfg, i.Name) {
			continue
		}
		return i.Name
	}
	return ""
}

func excludedIface(cfg *config.Config, name string) bool {
	for _, pat := range cfg.Interfaces.AutoDiscover.ExcludePatterns {
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
	}
	return false
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

// hotplugSupervisor keeps the running capture pipeline pointed at the best
// available interface under interfaces.mode: auto (F20), swapping it when a
// netlink hot-plug event changes what "best" means — a USB Wi-Fi dongle
// appearing, or the interface currently being captured disappearing.
type hotplugSupervisor struct {
	mu       sync.Mutex
	pipeline *livesource.Pipeline
	st       *store.Store
	cfg      *config.Config
	intel    detect.ThreatIntel
	ti       *threatintel.Store
	srv      *api.Server
	tcap     *tcapture.Manager // F11, shared across every pipeline this supervisor opens
}

func (h *hotplugSupervisor) current() *livesource.Pipeline {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pipeline
}

// swapTo closes the running pipeline (if any) and opens a new one on iface,
// updating the API server's source badge and re-wiring the threat-intel
// refresh callback onto the new pipeline. Errors are logged, not fatal —
// failing to switch interfaces must not take the whole agent down.
func (h *hotplugSupervisor) swapTo(iface string) {
	p, err := livesource.Open(h.st, iface, &h.cfg.Detection, h.intel)
	if err != nil {
		log.Printf("hotplug: cannot open capture on %s: %v", iface, err)
		return
	}
	p.SetByteSampler(h.srv.AddTrafficBytes)
	h.mu.Lock()
	old := h.pipeline
	h.pipeline = p
	h.mu.Unlock()
	if old != nil {
		old.Close()
	}
	if h.ti != nil {
		h.ti.OnUpdate(p.SetIntel)
	}
	if h.tcap != nil {
		p.SetTargetedCapture(h.tcap)
		h.srv.SetTargetedCapture(h.tcap) // covers the "started with no pipeline" case: F11 was off until now
	}
	if p.Live() {
		h.srv.SetSource(true, p.Iface(), p.Source())
		log.Printf("蜂眼 BeeEye: hotplug switched capture to %s (live, %s)", p.Iface(), p.Source())
	} else {
		h.srv.SetSource(false, p.Iface(), p.Source())
		log.Printf("蜂眼 BeeEye: hotplug switched to %s, but it has no raw-capture permission; SIMULATED traffic", p.Iface())
	}
}

// watch reacts to netlink link add/remove notifications: every event
// re-evaluates captureIface, and if that now names a different interface
// than what is currently running, swaps to it. Runs until the process exits
// — there is no graceful-stop path for it, matching every other background
// goroutine started from main.
func (h *hotplugSupervisor) watch() {
	events, err := live.WatchLinks(nil)
	if err != nil {
		log.Printf("hotplug: netlink watch unavailable (%v) — auto mode will not react to interface changes until restarted", err)
		return
	}
	for ev := range events {
		want := captureIface(h.cfg)
		cur := h.current()
		if cur != nil && cur.Iface() == want {
			continue // already on the best interface, nothing to do
		}
		log.Printf("hotplug: %s %s -> switching capture to %s", ev.Name, hotplugVerb(ev), want)
		h.swapTo(want)
	}
}

func hotplugVerb(ev live.LinkEvent) string {
	if ev.Removed {
		return "removed"
	}
	return "appeared"
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

	// Threat intel (F29): merge in a real public blocklist on top of the
	// hand-injected demo entries. Loads any cached copy synchronously (no
	// network wait on startup), then refreshes in the background — a feed
	// outage never blocks capture, it just means using yesterday's list.
	var tiStore *threatintel.Store
	if cfg.ThreatIntel.Enabled {
		feeds := threatintel.FeedsByName(cfg.ThreatIntel.Feeds)
		tiStore = threatintel.NewStore(cfg.ThreatIntel.CacheDir, feeds,
			time.Duration(cfg.ThreatIntel.RefreshHours)*time.Hour, intel)
		tiStore.Start()
		intel = tiStore.Snapshot()
	}

	// F11: on-demand targeted capture writes into data/targeted-captures/,
	// alongside the main SQLite DB. The manager itself has no dependency on
	// which pipeline is running — it's the pipeline that pushes packets into
	// it via SetTargetedCapture, so one Manager instance survives every
	// hot-plug interface swap unchanged.
	tcapMgr := tcapture.NewManager(filepath.Join(filepath.Dir(cfg.DBPath), "targeted-captures"),
		pcapfile.LinkEthernet, uint32(live.DefaultSnapLen))

	sup := &hotplugSupervisor{st: st, cfg: cfg, intel: intel, ti: tiStore, tcap: tcapMgr}
	// Deliberately closes whatever sup.current() is at exit, not a variable
	// captured up front: a hot-plug swap (F20) may replace the pipeline any
	// number of times before the process exits, including going from "none"
	// (started on the simulated fallback) to "one" after a NIC appears, and
	// Pipeline.Close is not safe to call twice (it closes a channel).
	defer func() {
		if p := sup.current(); p != nil {
			p.Close()
		}
	}()

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
		if pipeline != nil && tiStore != nil {
			tiStore.OnUpdate(pipeline.SetIntel)
		}
		if pipeline != nil {
			pipeline.SetTargetedCapture(tcapMgr)
		}
		sup.pipeline = pipeline
	}
	if pipeline == nil {
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
	sup.srv = srv
	// Importing a capture file (from the analyzer's "open file" feature, or
	// the overview's own upload) folds it into the same store the overview
	// reads — independent of whether a live pipeline is currently running,
	// so this is wired unconditionally rather than inside the pipeline-nil
	// checks below.
	srv.SetPcapImporter(func(r io.Reader, name string) error {
		_, err := livesource.ImportFile(st, r, name, &cfg.Detection, intel)
		return err
	})
	if pipeline != nil {
		// Feeds the overview's GPU-rendered traffic-trend curve (F7). Wired
		// here rather than where pipeline was opened above because srv (and
		// so AddTrafficBytes) does not exist yet at that point — this is the
		// first moment both are alive. hotplugSupervisor.swapTo wires the
		// same thing for every pipeline it opens after this one.
		pipeline.SetByteSampler(srv.AddTrafficBytes)
		// Only meaningful with a running pipeline actually feeding it packets
		// (F11) — otherwise the endpoint stays off and answers with a clear
		// "no live pipeline" error rather than accepting a request that can
		// never capture anything.
		srv.SetTargetedCapture(tcapMgr)
	}
	if pipeline != nil {
		srv.SetSource(pipeline.Live(), pipeline.Iface(), pipeline.Source())
	} else {
		srv.SetSource(false, "", "simulated")
	}

	// MITM decryption (F45), on by default as of 2026-08-20: the proxy starts
	// listening and a CA is generated, but that alone decrypts nothing — a
	// device only becomes visible once its owner installs the CA and points
	// that device's own proxy setting here (see MITMConfig's doc comment).
	// mitm.enabled: false in config.yaml turns the listener off entirely.
	// Failing to start it is logged, not fatal — the rest of BeeEye has
	// nothing to do with this feature and must not go down because of it.
	if cfg.MITM.Enabled {
		ca, err := mitm.LoadOrCreate(cfg.MITM.CADir)
		if err != nil {
			log.Printf("mitm: cannot load/create CA (%v) — MITM decryption disabled this run", err)
		} else {
			proxy := mitm.New(ca, cfg.MITM.MaxLog)
			srv.SetMITM(proxy)
			go func() {
				if err := proxy.ListenAndServe(cfg.MITM.Listen); err != nil {
					log.Printf("mitm: proxy stopped (%v)", err)
				}
			}()
			log.Printf("蜂眼 BeeEye: MITM decryption listening on %s (CA fingerprint %s) — download the CA at /api/mitm/ca.pem",
				cfg.MITM.Listen, ca.Fingerprint())
		}
	}

	// Interface hot-plug (F20): react to a NIC appearing or disappearing
	// instead of requiring a restart. -simulate opts out deliberately — the
	// user asked for the simulated scenario specifically, so a real NIC
	// showing up must not silently switch away from it.
	if !*forceSim {
		go sup.watch()
	}

	log.Printf("BeeEye API listening on %s  (web dir: %s)", cfg.ListenAddr, cfg.WebDir)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Routes()); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
