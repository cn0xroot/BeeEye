// Command BeeEye-agent is the BeeEye (蜂眼) capture+analysis+API core.
//
// It loads config, opens SQLite, and captures live traffic — the same
// AF_PACKET capture the analyzer uses (internal/livesource) — folding it into
// devices, connections and DNS records, running the detection engine
// (program.md §3.11) over the rolling window, and serving the REST API the
// overview UI reads. When the kernel refuses a raw socket, there is no
// simulated fallback (F43 taken to its conclusion: this project shows what
// is actually on the network, or honestly says it cannot right now — never a
// synthetic stand-in indistinguishable from the real thing once it is
// sitting in the same database tables). The overview runs with no live data
// until real capture becomes possible — see internal/live's doc comment for
// the reasoning and internal/capture's git history for what the old fallback
// used to cost.
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
	"BeeEye/internal/config"
	"BeeEye/internal/detect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/identity"
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
// host, or — when its exact name does not (see resolveExplicitInterface) — a
// real interface on this host matching its configured role, and when neither
// finds anything it falls back to the interface carrying the default route,
// and finally to "any". Without this, a config that does not match the
// hardware would silently drop the agent back to simulated data.
func captureIface(cfg *config.Config) string {
	if cfg.Interfaces.Mode == "explicit" {
		ifs, _ := net.Interfaces() // nil on error: the loop below just finds nothing, same as today
		for _, e := range cfg.Interfaces.ExplicitList {
			if dev := resolveExplicitInterface(e, ifs); dev != "" {
				return dev
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

// resolveExplicitInterface finds a real host interface for one configured
// explicit_list entry (F16/F20). Every machine's kernel names its interfaces
// differently — wlan0 vs wlp3s0 vs wlp14s0u2, eth0 vs enp2s0 vs eno1, an old
// driver's own ath0/ra0 — which is exactly why config.yaml has needed
// hand-editing per machine before this (see v1.3.2's Arch-specific fix).
//
// The configured Name wins outright when it exists on this host: an operator
// who has already set the right name for their hardware is never
// second-guessed. When it does not, Role narrows the search to a real
// candidate: wifi_ap must be an actual 802.11 device — asked of the kernel via
// livesource.IsWireless (/sys/class/net/<iface>/phy80211), not guessed from
// the name — and wan_uplink must not be. An empty Role, an unrecognized one,
// or no matching interface at all returns "", the same "try the next
// configured entry, then fall back further" contract captureIface already had.
func resolveExplicitInterface(e config.Interface, ifs []net.Interface) string {
	for _, i := range ifs {
		if i.Name == e.Name {
			return i.Name
		}
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		wireless := livesource.IsWireless(i.Name)
		switch e.Role {
		case "wifi_ap":
			if wireless {
				return i.Name
			}
		case "wan_uplink":
			if !wireless {
				return i.Name
			}
		}
	}
	return ""
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
	// livesource.Open only ever returns a Pipeline on success, and both
	// capsource's eBPF and AF_PACKET tiers report real=true — so p.Live() is
	// always true here. The false branch is kept only as a guard against a
	// future capsource tier being added that doesn't hold that contract.
	if p.Live() {
		h.srv.SetSource(true, p.Iface(), p.Source())
		log.Printf("蜂眼 BeeEye: hotplug switched capture to %s (live, %s)", p.Iface(), p.Source())
	} else {
		h.srv.SetSource(false, p.Iface(), p.Source())
		log.Printf("蜂眼 BeeEye: hotplug switched to %s, but it reported a non-live source", p.Iface())
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

// legacySimulatedMACs are the ten fixed device MACs an older build of this
// agent's now-removed simulated-scenario fallback (internal/capture,
// deleted — see git history) used to write into device_registry/
// connections/dns_records/events whenever it could not open a real capture
// source. Nothing at rest ever marked those rows as fabricated, so an
// on-disk database from before this fallback was removed can still have
// them sitting alongside real devices. Kept here, not in a package, purely
// so st.PurgeByMAC below has something to clean an old database with — this
// is a one-time migration concern, not a live feature; a fresh database
// never gets these rows in the first place.
var legacySimulatedMACs = []string{
	"00:11:d8:aa:00:01", "3c:84:27:bb:00:11", "a4:da:22:bb:00:12",
	"c0:97:2f:cc:00:13", "f0:27:2d:dd:00:14", "60:6b:ff:ee:00:15",
	"a4:5e:60:ff:00:16", "f0:18:9e:11:00:17", "44:65:0d:22:00:18",
	"b0:e5:ed:33:00:19",
}

func main() {
	cfgPath := flag.String("config", "config/config.yaml", "path to config.yaml")
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

	// user-editable device-category hint table (F1); missing file keeps the
	// built-in defaults, same contract as LoadPortServiceMap above.
	if err := identity.LoadHints(cfg.DeviceFingerprintFile); err != nil {
		log.Fatalf("load device fingerprint hints: %v", err)
	}
	// Optional full IEEE OUI registry (F1); missing file keeps the built-in
	// ~19-entry vendor table. Never a network call — see internal/identity/oui.go.
	identity.LoadOUI(cfg.OUIDatabaseFile)

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		log.Fatalf("mkdir data: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Empty until the real feed below populates it — no hand-injected demo
	// entries (a fake C2 IP, a "malware-c2.example" domain) seeded into
	// every run regardless of whether capture is real: those are exactly
	// the kind of fabricated-but-indistinguishable-from-real data this
	// project no longer ships (see main's own doc comment).
	intel := detect.ThreatIntel{}

	// Threat intel (F29): a real public blocklist. Loads any cached copy
	// synchronously (no network wait on startup), then refreshes in the
	// background — a feed outage never blocks capture, it just means using
	// yesterday's list.
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

	// --- capture: real traffic only (F43 taken to its conclusion — see
	// internal/live's doc comment for why there is no simulated fallback).
	// If the kernel refuses a raw socket, the agent runs with no pipeline:
	// the API and every existing row in the store are still served, but
	// nothing new comes in until real capture becomes possible (a hot-plug
	// interface swap, permissions granted and the process restarted, ...).
	var pipeline *livesource.Pipeline
	iface := captureIface(cfg)
	p, err := livesource.Open(st, iface, &cfg.Detection, intel)
	if err != nil {
		log.Printf("蜂眼 BeeEye: live capture unavailable on %s (%v). "+
			"Grant it with: sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./BeeEye-agent/bin/BeeEye-agent "+
			"(or cap_net_raw,cap_net_admin+ep for the AF_PACKET-only fallback). "+
			"Running with no live data until then — the overview will not show fabricated traffic in its place.", iface, err)
	} else {
		log.Printf("蜂眼 BeeEye: capturing live on %s", p.Iface())
		pipeline = p
		// Historical cleanup, not a live feature: an on-disk database that
		// ever ran an older build of this agent (before the simulated
		// fallback was removed entirely) may still have the fixed ten
		// fabricated devices that fallback used to write — see
		// legacySimulatedMACs' own comment. Safe to always attempt: a MAC
		// that was never inserted deletes zero rows.
		if err := st.PurgeByMAC(legacySimulatedMACs); err != nil {
			log.Printf("purge stale simulated devices: %v", err)
		}
	}
	if pipeline != nil && tiStore != nil {
		tiStore.OnUpdate(pipeline.SetIntel)
	}
	if pipeline != nil {
		pipeline.SetTargetedCapture(tcapMgr)
	}
	sup.pipeline = pipeline

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
		srv.SetSource(false, "", "unavailable")
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
	// instead of requiring a restart.
	go sup.watch()

	log.Printf("BeeEye API listening on %s  (web dir: %s)", cfg.ListenAddr, cfg.WebDir)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Routes()); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
