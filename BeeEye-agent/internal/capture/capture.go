// Package capture provides traffic sources for the BeeEye agent.
//
// The real system attaches eBPF/TC programs to LAN interfaces (program.md §3.4)
// and reads events from a ringbuf. That requires a kernel >=5.8 with BTF, which
// is not available in every dev/demo environment. This package therefore ships
// a deterministic *simulated* source that fabricates a realistic household
// scenario — normal device traffic plus three injected intrusions (a C2 beacon,
// a LAN port-scan, and DGA-style DNS) — so the storage, detection and UI layers
// can be exercised end-to-end. Swap this for a real ringbuf reader to go live.
package capture

import (
	"fmt"
	"math/rand"
	"time"

	"BeeEye/internal/geoip"
	"BeeEye/internal/identity"
	"BeeEye/internal/model"
	"BeeEye/internal/protocol"
	"BeeEye/internal/store"
)

// Scenario is everything the detection engine needs after a capture batch.
type Scenario struct {
	BaselinePairs map[string]bool                 // known (mac|dstIP) for first-target
	Categories    map[string]model.DeviceCategory // mac → category
}

type dev struct {
	mac, ip, host, iface, access string
}

// legit external endpoints with domains, chosen so geoip returns varied places.
var legit = []struct {
	domain string
	ip     string
}{
	{"cdn.apple.com", "104.16.20.5"},
	{"dns.google", "8.8.8.8"},
	{"gateway.icloud.com", "23.45.12.9"},
	{"api.amazonalexa.com", "52.94.10.3"},
	{"ota.hikvision.com", "47.98.44.10"},
	{"time.windows.com", "20.101.5.7"},
	{"samsungcloud.tv", "35.190.22.8"},
	{"mqtt.tuya.com", "118.31.9.4"},
	{"registry.npmjs.org", "104.16.30.34"},
	{"update.synology.com", "13.107.4.50"},
}

// GenerateSimulated fabricates and persists a full scenario into the store,
// returning the metadata the detection engine consumes. Deterministic per seed.
func GenerateSimulated(st *store.Store, seed int64) (*Scenario, error) {
	rng := rand.New(rand.NewSource(seed))
	now := time.Now()
	start := now.Add(-3 * time.Hour)

	sc := &Scenario{BaselinePairs: map[string]bool{}, Categories: map[string]model.DeviceCategory{}}

	devices := []dev{
		{"00:11:d8:aa:00:01", "192.168.1.1", "home-router", "eth0", "wired"},
		{"3c:84:27:bb:00:11", "192.168.1.20", "livingroom-ipcam", "wlan0", "wireless"}, // camera (infected)
		{"a4:da:22:bb:00:12", "192.168.1.21", "door-cam", "wlan0", "wireless"},         // camera
		{"c0:97:2f:cc:00:13", "192.168.1.22", "front-door-lock", "wlan0", "wireless"},  // lock
		{"f0:27:2d:dd:00:14", "192.168.1.30", "synology-nas", "eth0", "wired"},         // NAS
		{"60:6b:ff:ee:00:15", "192.168.1.40", "samsung-tv", "wlan0", "wireless"},       // tv
		{"a4:5e:60:ff:00:16", "192.168.1.50", "alice-iphone", "wlan0", "wireless"},     // phone
		{"f0:18:9e:11:00:17", "192.168.1.51", "bob-macbook", "wlan0", "wireless"},      // laptop (DGA host)
		{"44:65:0d:22:00:18", "192.168.1.60", "kitchen-echo", "wlan0", "wireless"},     // speaker
		{"b0:e5:ed:33:00:19", "192.168.1.61", "smart-fridge", "wlan0", "wireless"},     // fridge
	}

	byMAC := map[string]dev{}
	for _, d := range devices {
		byMAC[d.mac] = d
		info := identity.Identify(d.mac, d.host)
		firstSeen := start
		if d.host == "alice-iphone" {
			firstSeen = now.Add(-4 * time.Minute) // NEW device → F8 alert
		}
		md := &model.Device{
			MAC: d.mac, IP: d.ip, Vendor: info.Vendor, ModelGuess: info.ModelGuess,
			Category: info.Category, Hostname: d.host, Iface: d.iface, AccessType: d.access,
			FirstSeen: firstSeen, LastSeen: now,
		}
		if _, err := st.UpsertDevice(md); err != nil {
			return nil, err
		}
		sc.Categories[d.mac] = info.Category
	}

	// cache geo for every external IP we will reference
	for _, l := range legit {
		_ = st.CacheGeo(geoip.Lookup(l.ip))
	}
	_ = st.CacheGeo(geoip.Lookup(c2IP))

	// ---- normal background traffic ----
	for _, d := range devices {
		n := 4 + rng.Intn(4)
		for i := 0; i < n; i++ {
			l := legit[rng.Intn(len(legit))]
			ts := start.Add(time.Duration(rng.Intn(180)) * time.Minute)
			// DNS query then HTTPS connection
			_ = st.InsertDNS(&model.DNSRecord{
				TS: ts, MAC: d.mac, Domain: l.domain,
				ResolvedIPs: []string{l.ip}, TTL: 300, RCode: "NOERROR",
			})
			port := 443
			app := "HTTPS"
			if l.domain == "mqtt.tuya.com" {
				port, app = 8883, "MQTT-TLS"
			}
			insertConn(st, &model.Connection{
				TS: ts.Add(time.Second), MAC: d.mac, SrcIP: d.ip, SrcPort: 40000 + rng.Intn(20000),
				DstIP: l.ip, DstPort: port, Proto: "TCP", AppProtocol: app,
				Bytes: int64(2000 + rng.Intn(50000)), Packets: int64(10 + rng.Intn(80)),
				Iface: d.iface, SNI: l.domain, JA3: "769,47-53,0-11-10,23-24,0",
			})
			sc.BaselinePairs[d.mac+"|"+l.ip] = true // legit pairs are baseline
		}
	}

	// A few DoH connections (encrypted DNS) so the UI can show the DoH note (F21).
	_ = st.InsertDNS(&model.DNSRecord{TS: now.Add(-30 * time.Minute), MAC: "a4:5e:60:ff:00:16",
		Domain: "(encrypted DoH)", ResolvedIPs: []string{"1.1.1.1"}, RCode: "N/A", Encrypted: true})

	// ---- intrusion 1: C2 beacon from the infected IP camera (F35/F29/F28) ----
	injectBeacon(st, byMAC["3c:84:27:bb:00:11"], start, rng)

	// ---- intrusion 2: LAN port-scan from the same camera (F34/F36) ----
	injectLANScan(st, byMAC["3c:84:27:bb:00:11"], now.Add(-40*time.Minute), rng)

	// ---- intrusion 3: DGA-style DNS from the macbook (F33) ----
	injectDGA(st, byMAC["f0:18:9e:11:00:17"], now.Add(-25*time.Minute), rng)

	return sc, nil
}

const c2IP = "45.13.34.7" // Moscow (RU) — also on the demo threat-intel blocklist

// injectBeacon writes a fixed-interval callback (60s ± small jitter) for 2h.
func injectBeacon(st *store.Store, d dev, start time.Time, rng *rand.Rand) {
	t := start.Add(30 * time.Minute)
	for i := 0; i < 90; i++ {
		jitter := time.Duration(rng.Intn(6)-3) * time.Second // ±3s → CV well below 0.15
		ts := t.Add(time.Duration(i)*60*time.Second + jitter)
		insertConn(st, &model.Connection{
			TS: ts, MAC: d.mac, SrcIP: d.ip, SrcPort: 50000 + rng.Intn(10000),
			DstIP: c2IP, DstPort: 443, Proto: "TCP", AppProtocol: "HTTPS",
			Bytes: int64(400 + rng.Intn(120)), Packets: 6,
			Iface: d.iface, SNI: "", JA3: "771,4865-4866,0-51,29-23,0", // odd JA3 for a camera
		})
	}
}

// injectLANScan writes a burst of internal connections to management ports.
func injectLANScan(st *store.Store, d dev, at time.Time, rng *rand.Rand) {
	ports := []int{22, 23, 445, 80, 3389}
	for i := 20; i < 55; i++ { // 35 internal hosts in ~3 minutes
		dst := fmt.Sprintf("192.168.1.%d", i)
		for _, p := range ports[:1+rng.Intn(len(ports))] {
			ts := at.Add(time.Duration(rng.Intn(180)) * time.Second)
			insertConn(st, &model.Connection{
				TS: ts, MAC: d.mac, SrcIP: d.ip, SrcPort: 55000 + rng.Intn(5000),
				DstIP: dst, DstPort: p, Proto: "TCP", AppProtocol: protocol.ServiceName(p),
				Bytes: 60, Packets: 1, Iface: d.iface, Internal: true,
			})
		}
	}
}

// injectDGA writes many high-entropy domain queries, several NXDOMAIN.
func injectDGA(st *store.Store, d dev, at time.Time, rng *rand.Rand) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 18; i++ {
		label := make([]byte, 12+rng.Intn(6))
		for j := range label {
			label[j] = alphabet[rng.Intn(len(alphabet))]
		}
		rcode := "NOERROR"
		var ips []string
		if i%2 == 0 {
			rcode = "NXDOMAIN" // ~9 NXDOMAINs → well over threshold
		} else {
			ips = []string{fmt.Sprintf("185.%d.%d.%d", rng.Intn(255), rng.Intn(255), rng.Intn(255))}
		}
		_ = st.InsertDNS(&model.DNSRecord{
			TS: at.Add(time.Duration(i*8) * time.Second), MAC: d.mac,
			Domain: string(label) + ".com", ResolvedIPs: ips, TTL: 60, RCode: rcode,
		})
	}
}

// insertConn fills the port→service name if missing, then persists.
func insertConn(st *store.Store, c *model.Connection) {
	if c.Service == "" {
		c.Service = protocol.ServiceName(c.DstPort)
	}
	if !geoip.IsPrivateStr(c.DstIP) {
		c.Internal = false
	}
	_ = st.InsertConnection(c)
}

// DemoIntel returns the offline blocklists used by the demo (program.md F29).
func DemoIntel() (map[string]bool, map[string]bool, map[string]bool) {
	badIP := map[string]bool{c2IP: true}
	badDomain := map[string]bool{"malware-c2.example": true}
	badJA3 := map[string]bool{}
	return badIP, badDomain, badJA3
}
