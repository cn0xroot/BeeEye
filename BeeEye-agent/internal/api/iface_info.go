package api

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ifaceRate turns the kernel's own cumulative rx/tx counters for one NIC
// (/sys/class/net/<iface>/statistics/…) into a bytes/sec rate — the same
// numbers `ip -s link` and conky read, so what this shows always agrees with
// what the OS itself reports for that interface, not just what BeeEye's own
// dissector happened to see (which a promiscuous-mode capture can under-count
// relative to the NIC's real total, e.g. hardware-offloaded traffic).
type ifaceRate struct {
	mu       sync.Mutex
	iface    string
	lastRx   int64
	lastTx   int64
	lastTS   time.Time
	rxPerSec float64
	txPerSec float64
}

// sample reads the current counters and folds them into the running rate.
// Called once per /api/iface/info request — cheap (two small file reads) and
// self-throttling: two requests less than ~200ms apart would divide by too
// small an interval for a stable rate, so the previous rate is kept instead
// of being recomputed from noise.
func (ir *ifaceRate) sample(iface string, rx, tx int64) (rxPerSec, txPerSec float64) {
	ir.mu.Lock()
	defer ir.mu.Unlock()
	now := time.Now()
	if ir.iface != iface {
		// Switched interface (or first sample ever) — nothing to diff
		// against yet; this read establishes the new baseline.
		ir.iface, ir.lastRx, ir.lastTx, ir.lastTS = iface, rx, tx, now
		ir.rxPerSec, ir.txPerSec = 0, 0
		return 0, 0
	}
	elapsed := now.Sub(ir.lastTS).Seconds()
	if elapsed >= 0.2 {
		if d := rx - ir.lastRx; d >= 0 {
			ir.rxPerSec = float64(d) / elapsed
		}
		if d := tx - ir.lastTx; d >= 0 {
			ir.txPerSec = float64(d) / elapsed
		}
		ir.lastRx, ir.lastTx, ir.lastTS = rx, tx, now
	}
	return ir.rxPerSec, ir.txPerSec
}

// IfaceInfo is what the overview's colored NIC card shows.
type IfaceInfo struct {
	Name      string  `json:"name"`
	IP        string  `json:"ip,omitempty"`
	MAC       string  `json:"mac,omitempty"`
	RxBytes   int64   `json:"rx_bytes"`
	TxBytes   int64   `json:"tx_bytes"`
	RxPerSec  float64 `json:"rx_per_sec"`
	TxPerSec  float64 `json:"tx_per_sec"`
	Wireless  bool    `json:"wireless"`
	SSID      string  `json:"ssid,omitempty"`
	Channel   int     `json:"channel,omitempty"`
	FreqMHz   float64 `json:"freq_mhz,omitempty"`
	SignalDBm int     `json:"signal_dbm,omitempty"`
	HasSignal bool    `json:"has_signal,omitempty"`
}

func readSysfsCounter(iface, name string) int64 {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/" + name)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// primaryIPv4 picks the interface's LAN-facing address for display — the
// first IPv4 it has. IPv6 is left out here (a card meant for an "IP address"
// glance is more useful showing the one address someone would actually type
// into another device than a link-local IPv6 nobody uses that way).
func primaryIPv4(iface string) string {
	nif, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := nif.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil || ip.To4() == nil {
			continue
		}
		return ip.String()
	}
	return ""
}

// wirelessInfo shells out to `iw dev <iface> info` — the modern nl80211
// tool (iwconfig is deprecated/often absent) — for SSID and channel. Absent
// entirely, or the interface simply is not wireless: this returns a zero
// value and the card just omits those fields, never a guessed/blank-looking
// row.
func wirelessInfo(iface string) (ssid string, channel int, freqMHz float64, ok bool) {
	out, err := exec.Command("iw", "dev", iface, "info").Output()
	if err != nil {
		return "", 0, 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "ssid "):
			ssid = strings.TrimPrefix(line, "ssid ")
			ok = true
		case strings.HasPrefix(line, "channel "):
			// e.g. "channel 149 (5745 MHz), width: 80 MHz, center1: 5775 MHz"
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				channel, _ = strconv.Atoi(fields[1])
			}
			if i := strings.Index(line, "("); i >= 0 {
				if j := strings.Index(line[i:], " MHz"); j >= 0 {
					freqMHz, _ = strconv.ParseFloat(line[i+1:i+j], 64)
				}
			}
			ok = true
		}
	}
	return ssid, channel, freqMHz, ok
}

// wirelessSignal reads the current RSSI from `iw dev <iface> link` — a
// separate call from wirelessInfo's `info` because only `link` (an active
// association) carries the live signal number; `info` alone would still
// report ssid/channel for an interface that briefly has neither.
func wirelessSignal(iface string) (dbm int, ok bool) {
	out, err := exec.Command("iw", "dev", iface, "link").Output()
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "signal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				dbm, _ = strconv.Atoi(strings.TrimSuffix(fields[1], "dBm"))
				return dbm, true
			}
		}
	}
	return 0, false
}

// ifaceInfo answers the overview's NIC card (F17 extended): which interface
// is actually being captured on right now, its addresses, live throughput
// off the kernel's own counters, and — when it is a WiFi adapter — the SSID
// and channel it is associated to, the same facts a conky bar would show.
func (s *Server) ifaceInfo(w http.ResponseWriter, r *http.Request) {
	src := s.src.Load()
	if src == nil || src.iface == "" {
		writeJSON(w, map[string]any{"available": false})
		return
	}
	iface := src.iface

	rx := readSysfsCounter(iface, "rx_bytes")
	tx := readSysfsCounter(iface, "tx_bytes")
	rxPerSec, txPerSec := s.ifaceRateState.sample(iface, rx, tx)

	info := IfaceInfo{
		Name: iface, IP: primaryIPv4(iface), RxBytes: rx, TxBytes: tx,
		RxPerSec: rxPerSec, TxPerSec: txPerSec,
	}
	if nif, err := net.InterfaceByName(iface); err == nil {
		info.MAC = nif.HardwareAddr.String()
	}
	if ssid, ch, freq, ok := wirelessInfo(iface); ok {
		info.Wireless = true
		info.SSID, info.Channel, info.FreqMHz = ssid, ch, freq
		if dbm, ok := wirelessSignal(iface); ok {
			info.SignalDBm, info.HasSignal = dbm, true
		}
	}
	writeJSON(w, map[string]any{"available": true, "iface": info})
}
