// Command BeeEye-gui is the BeeEye live capture analyzer (program.md §3.12).
//
// It is a separate process from BeeEye-agent by design (F42): its own port, its
// own frontend bundle, and no database at all. Killing or restarting either
// binary leaves the other one working.
//
// Privileges: real capture needs CAP_NET_RAW. Without it the process still
// starts, but Start (and -autostart) fail outright rather than falling back
// to a synthetic source — there is none (F43). Grant the capability without
// running as root with:
//
//	sudo setcap cap_net_raw,cap_net_admin+ep ./bin/BeeEye-gui
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"BeeEye/internal/geoip"
	"BeeEye/internal/gui"
	"BeeEye/internal/live"
)

func main() {
	addr := flag.String("listen", ":8081", "address to listen on")
	webDir := flag.String("web", "./BeeEye-gui/dist", "directory holding the built analyzer UI")
	iface := flag.String("iface", "", "interface to preselect in the UI (default: none — the UI picks a sensible default on its own)")
	autostart := flag.Bool("autostart", false, "start capturing on -iface immediately at launch, instead of waiting for the UI's Start button")
	filter := flag.String("filter", "", "initial display filter")
	promisc := flag.Bool("promisc", true, "put the interface into promiscuous mode")
	ring := flag.Int("ring", gui.DefaultRingSize, "how many dissected packets to retain in memory")
	captureDir := flag.String("capture-dir", "/tmp/BeeEye", "directory to save the live capture to (pcap); empty disables persistence")
	captureMaxMB := flag.Int("capture-max-mb", 512, "max size of each saved capture file in MiB (two are kept)")
	decrypt := flag.Bool("decrypt", true, "decrypt the gateway's own HTTPS by attaching uprobes to its OpenSSL libraries (F14)")
	flag.Parse()

	if v := os.Getenv("BEEEYE_GUI_LISTEN"); v != "" {
		*addr = v
	}
	if v := os.Getenv("BEEEYE_GUI_WEBDIR"); v != "" {
		*webDir = v
	}

	geoip.Load("", "")
	sess := gui.NewSession(*ring)

	// Persist the live capture to disk so a packet's detail survives eviction
	// from the in-memory ring — clicking an old packet reads its bytes back
	// from here instead of failing with "no longer buffered". Off with
	// -capture-dir "".
	if v := os.Getenv("BEEEYE_CAPTURE_DIR"); v != "" {
		*captureDir = v
	}
	if *captureDir != "" {
		sess.EnablePersistence(*captureDir, int64(*captureMaxMB)<<20)
	}

	if *iface != "" && *autostart {
		opt := gui.StartOptions{Iface: *iface, Promisc: *promisc,
			SnapLen: live.DefaultSnapLen, Filter: *filter}
		// Start returns live.Open's error directly (F43 — no synthetic source
		// to fall back to), so reaching past this point means real capture.
		if err := sess.Start(opt); err != nil {
			log.Fatalf("start capture on %s: %v", *iface, err)
		}
		st := sess.Status()
		log.Printf("capturing on %s via %s", st.Iface, st.Source)
	} else {
		// Idle by default (even with -iface set): opening the analyzer used
		// to start capturing traffic before anyone asked it to, which is a
		// surprising thing for an app to do on launch — the UI already picks
		// -iface's interface as its own default selection (see Toolbar.jsx),
		// so nothing is lost by waiting for an explicit Start click except
		// the surprise. Pass -autostart for the old immediate-capture
		// behaviour (e.g. a scripted/headless deployment with no one at the UI).
		log.Printf("idle; press Start in the UI to begin capturing")
	}

	srv := &http.Server{
		Addr:    *addr,
		Handler: gui.NewServer(sess, *webDir, *decrypt).Routes(),
		// No write timeout: the SSE stream is a long-lived response and any
		// deadline here would cut the live packet feed at that interval.
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("BeeEye analyzer listening on %s  (UI dir: %s)", *addr, *webDir)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
