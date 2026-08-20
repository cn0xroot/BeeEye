// Package livesource turns a real packet capture into the rows the overview
// UI reads: devices, connections, DNS records and, periodically, risk events.
//
// It exists to close the gap the project carried for a while — the agent used
// to populate its store from capture.GenerateSimulated, so the overview showed
// ten fictional devices while the analyzer showed the real network. This runs
// the same AF_PACKET capture the analyzer uses, dissects each frame, and
// aggregates the results into the model types the store already persists, so
// the two UIs finally describe the same traffic.
//
// The capture source falls back to the simulator when the kernel refuses a raw
// socket (no CAP_NET_RAW), and Pipeline.Live reports which happened, so the API
// can label the data honestly rather than presenting simulated flows as real
// (F43).
package livesource

import (
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"BeeEye/internal/capsource"
	"BeeEye/internal/config"
	"BeeEye/internal/detect"
	"BeeEye/internal/dissect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/identity"
	"BeeEye/internal/live"
	"BeeEye/internal/model"
	"BeeEye/internal/protocol"
	"BeeEye/internal/store"
	"BeeEye/internal/tcapture"
)

// FlushInterval is how often aggregated flows are written to the store and the
// detection engine is re-run. Frequent enough that the overview feels live,
// rare enough that the aggregation stays cheap.
const FlushInterval = 5 * time.Second

// Pipeline owns a live capture and the goroutines draining it into the store.
type Pipeline struct {
	st  *store.Store
	src live.Source
	eng *detect.Engine
	// intel is read fresh on every flush() and may be replaced at any time by
	// SetIntel from another goroutine (a periodic threat-feed refresh), so it
	// is an atomic pointer rather than a plain field guarded by mu — flush()
	// runs on p.run()'s goroutine and must never block on a feed fetch.
	intel atomic.Pointer[detect.ThreatIntel]
	// tcap is nil until SetTargetedCapture is called (F11), and every packet
	// on the hot path checks it, so an atomic pointer avoids taking a lock
	// per packet just to find out no session is running.
	tcap atomic.Pointer[tcapture.Manager]

	live  bool // true = real capture, false = simulator (F43)
	iface string

	mu      sync.Mutex
	flows   map[string]*model.Connection // 5-tuple key → accumulating flow
	devices map[string]*deviceSeen       // mac → what we know about it
	cats    map[string]model.DeviceCategory
	// seenEvents dedupes alerts across flushes. Detection is a batch design
	// re-run over the whole recent window every interval, so without this the
	// same "first contact with 1.1.1.1" would be re-inserted every 5s and the
	// alert list would be nothing but duplicates.
	seenEvents map[string]bool

	stop chan struct{}
	done chan struct{}
}

type deviceSeen struct {
	ip       string
	hostname string
	iface    string
	wireless bool
	firstTS  time.Time
	lastTS   time.Time
	dirty    bool
}

// Open starts a capture on iface and returns a running pipeline. snaplen and
// promisc mirror the analyzer's defaults. The returned Pipeline is already
// draining packets; call Close to stop it.
func Open(st *store.Store, iface string, cfg *config.Detection, intel detect.ThreatIntel) (*Pipeline, error) {
	src, real, err := capsource.Open(iface, live.DefaultSnapLen, true)
	if err != nil {
		return nil, err
	}
	p := &Pipeline{
		st:         st,
		src:        src,
		live:       real,
		iface:      src.Iface(),
		flows:      map[string]*model.Connection{},
		devices:    map[string]*deviceSeen{},
		cats:       map[string]model.DeviceCategory{},
		seenEvents: map[string]bool{},
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	p.eng = &detect.Engine{Cfg: cfg, Cats: p.cats}
	p.intel.Store(&intel)
	go p.run()
	return p, nil
}

// Live reports whether the capture is real (true) or the simulator (false).
func (p *Pipeline) Live() bool    { return p.live }
func (p *Pipeline) Iface() string { return p.iface }

// Source names which capture source is actually running: "ebpf" | "af_packet"
// | "simulator" (live.Source.Name()'s own values — see capsource.Open).
func (p *Pipeline) Source() string { return p.src.Name() }

// SetIntel replaces the threat-intel snapshot the detection engine uses on
// its next flush. Safe to call from another goroutine — see the intel field
// comment.
func (p *Pipeline) SetIntel(intel detect.ThreatIntel) { p.intel.Store(&intel) }

// SetTargetedCapture wires in the manager that F11's on-demand, MAC-filtered
// captures use. Every packet is offered to it on the hot path (a cheap
// atomic-pointer check when mgr is nil or has no active session for that
// packet's MAC), so a targeted session sees the same live packets the
// dissector does — not a replay of whatever the ring buffer retained.
func (p *Pipeline) SetTargetedCapture(mgr *tcapture.Manager) { p.tcap.Store(mgr) }

func (p *Pipeline) run() {
	defer close(p.done)
	dis := dissect.New()
	packets := p.src.Packets()
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			p.flush()
			return
		case <-ticker.C:
			p.flush()
		case pkt, ok := <-packets:
			if !ok {
				p.flush()
				return
			}
			if mgr := p.tcap.Load(); mgr != nil {
				mgr.Feed(pkt)
			}
			p.ingest(dis.Packet(pkt))
		}
	}
}

// ingest folds one dissected packet into the running aggregates. It never
// touches the store — that happens on flush, so the hot path stays cheap.
func (p *Pipeline) ingest(r *dissect.Result) {
	if r == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	srcIP, srcErr := netip.ParseAddr(r.Src)
	dstIP, dstErr := netip.ParseAddr(r.Dst)
	srcOK := srcErr == nil
	dstOK := dstErr == nil

	// Device discovery: a LAN device is the local endpoint of a frame. Both
	// ends can be local (east-west), so consider each.
	srcMAC := first(r.Fields["eth.src"])
	dstMAC := first(r.Fields["eth.dst"])
	if srcOK && isDevice(srcIP, srcMAC) {
		p.seeDevice(srcMAC, r.Src, r.Iface, r.TS)
	}
	if dstOK && isDevice(dstIP, dstMAC) {
		p.seeDevice(dstMAC, r.Dst, r.Iface, r.TS)
	}

	// DNS: record queries/answers so the DNS view and the anomaly detector
	// have something to work with.
	if r.HasProtocol("dns") || r.HasProtocol("mdns") {
		p.ingestDNS(r, srcMAC, dstMAC)
	}

	// Flows: only L4 conversations become connections. ARP, pure L2 and the
	// like are captured for device discovery above but are not "connections".
	if r.Transport == "" || (r.SrcPort == 0 && r.DstPort == 0) {
		return
	}
	key := flowKey(r)
	c := p.flows[key]
	if c == nil {
		mac := srcMAC
		if !(srcOK && isLocal(srcIP)) {
			mac = dstMAC // the local end is the device the flow belongs to
		}
		c = &model.Connection{
			TS:      r.TS,
			MAC:     mac,
			SrcIP:   r.Src,
			SrcPort: r.SrcPort,
			DstIP:   r.Dst,
			DstPort: r.DstPort,
			Proto:   strings.ToUpper(r.Transport),
			Iface:   r.Iface,
		}
		p.flows[key] = c
	}
	c.Packets++
	c.Bytes += int64(r.Length)
	if r.SNI != "" {
		c.SNI = r.SNI
	}
	if r.JA3 != "" {
		c.JA3 = r.JA3
	}
	// Application protocol + service name, best-effort from what was dissected.
	isTLS := r.HasProtocol("tls")
	alpn := strings.Join(r.ALPN, ",")
	if app := protocol.Identify(topAppProto(r), alpn, isTLS, r.DstPort); app != "" {
		c.AppProtocol = app
	}
	if dstOK {
		c.Internal = isLocal(dstIP)
	}
}

func (p *Pipeline) ingestDNS(r *dissect.Result, srcMAC, dstMAC string) {
	names := r.FieldValues("dns.qry.name")
	if len(names) == 0 {
		return
	}
	isResp := first(r.FieldValues("dns.flags.response")) == "1"
	rec := &model.DNSRecord{
		TS:     r.TS,
		Domain: names[0],
		RCode:  rcodeName(first(r.FieldValues("dns.flags.rcode"))),
	}
	// The querier is the local device: on a query it is the source, on a
	// response it is the destination.
	if isResp {
		rec.MAC = dstMAC
	} else {
		rec.MAC = srcMAC
	}
	rec.ResolvedIPs = append(rec.ResolvedIPs, r.FieldValues("dns.a")...)
	rec.ResolvedIPs = append(rec.ResolvedIPs, r.FieldValues("dns.aaaa")...)
	if err := p.st.InsertDNS(rec); err != nil {
		return
	}
	for _, ip := range rec.ResolvedIPs {
		if g := geoip.Lookup(ip); g.IP != "" {
			_ = p.st.CacheGeo(g)
		}
	}
}

func (p *Pipeline) seeDevice(mac, ip, iface string, ts time.Time) {
	d := p.devices[mac]
	if d == nil {
		d = &deviceSeen{ip: ip, iface: iface, firstTS: ts, wireless: isWireless(iface)}
		p.devices[mac] = d
	}
	if ip != "" {
		d.ip = ip
	}
	d.lastTS = ts
	d.dirty = true
}

// flush writes the accumulated flows, devices and a fresh detection pass to the
// store. Flows are cleared after writing: each becomes one connection row per
// interval, which is the same granularity the snapshot path uses.
func (p *Pipeline) flush() {
	p.mu.Lock()
	flows := p.flows
	p.flows = map[string]*model.Connection{}
	var devs []*model.Device
	for mac, d := range p.devices {
		if !d.dirty {
			continue
		}
		d.dirty = false
		id := identity.Identify(mac, d.hostname)
		p.cats[mac] = id.Category
		access := "wired"
		if d.wireless {
			access = "wireless"
		}
		devs = append(devs, &model.Device{
			MAC:        mac,
			IP:         d.ip,
			Vendor:     id.Vendor,
			ModelGuess: id.ModelGuess,
			Category:   id.Category,
			Hostname:   d.hostname,
			Iface:      d.iface,
			AccessType: access,
			FirstSeen:  d.firstTS,
			LastSeen:   d.lastTS,
		})
	}
	p.mu.Unlock()

	for _, d := range devs {
		if _, err := p.st.UpsertDevice(d); err != nil {
			log.Printf("livesource: upsert device %s: %v", d.MAC, err)
		}
	}
	for _, c := range flows {
		c.Service = protocol.ServiceName(c.DstPort)
		if g := geoip.Lookup(c.DstIP); g.IP != "" {
			_ = p.st.CacheGeo(g)
		}
		if err := p.st.InsertConnection(c); err != nil {
			log.Printf("livesource: insert connection: %v", err)
		}
	}

	// Detection over the full recent window, so a beacon or fan-out spanning
	// several flush intervals is still seen.
	conns, err := p.st.Connections(store.ConnFilter{Limit: 100000})
	if err != nil {
		return
	}
	dnsRecs, _ := p.st.DNSRecords("", 100000)
	if intel := p.intel.Load(); intel != nil {
		p.eng.Intel = *intel
	}
	for _, ev := range p.eng.Analyze(conns, dnsRecs, nil) {
		ev := ev
		key := ev.MAC + "|" + ev.EventType + "|" + detailKey(ev.Detail)
		p.mu.Lock()
		dup := p.seenEvents[key]
		p.seenEvents[key] = true
		p.mu.Unlock()
		if dup {
			continue
		}
		_ = p.st.InsertEvent(&ev)
	}
}

// Close stops the capture and waits for the final flush.
func (p *Pipeline) Close() error {
	close(p.stop)
	err := p.src.Close()
	<-p.done
	return err
}

// ------------------------------------------------------------------ helpers

func flowKey(r *dissect.Result) string {
	// Canonical order so both directions of one conversation share a key.
	a := r.Src + ":" + strconv.Itoa(r.SrcPort)
	b := r.Dst + ":" + strconv.Itoa(r.DstPort)
	if a > b {
		a, b = b, a
	}
	return r.Transport + "|" + a + "|" + b
}

func first(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

func topAppProto(r *dissect.Result) string {
	for i := len(r.Protocols) - 1; i >= 0; i-- {
		switch r.Protocols[i] {
		case "eth", "ip", "ipv6", "tcp", "udp", "vlan", "arp":
			continue
		}
		return r.Protocols[i]
	}
	return ""
}

func rcodeName(code string) string {
	switch code {
	case "", "0":
		return "NOERROR"
	case "3":
		return "NXDOMAIN"
	}
	return "RCODE" + code
}

// isLocal reports whether an address belongs to the monitored LAN, for the
// east-west flag. Multicast to 224.0.0.0/24 or ff02:: is LAN traffic, so it
// counts as internal here even though it is not a device.
func isLocal(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast()
}

// isDevice reports whether an (IP, MAC) pair identifies a real LAN device.
// A device is a unicast host on the local network reached via a unicast MAC:
// multicast and broadcast destinations (224.0.0.x / ff02:: / ff:ff:ff:ff:ff:ff)
// name a group, not a machine, and must never appear in the device table.
func isDevice(a netip.Addr, mac string) bool {
	if mac == "" || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
		return false
	}
	return isUnicastMAC(mac)
}

// isUnicastMAC reports whether a MAC is an individual address. The least
// significant bit of the first octet is the I/G bit: 1 means a group
// (multicast/broadcast) address, 0 means an individual station.
func isUnicastMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := strconv.ParseUint(mac[0:2], 16, 8)
	if err != nil {
		return false
	}
	return b&0x01 == 0
}

// detailKey turns an event's structured detail into a stable string, so the
// same (device, type, target) alert is recognised across flushes regardless of
// map iteration order.
func detailKey(d map[string]any) string {
	if len(d) == 0 {
		return ""
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(fmt.Sprint(d[k]))
		b.WriteByte(';')
	}
	return b.String()
}

func isWireless(iface string) bool {
	return strings.HasPrefix(iface, "wl") || strings.Contains(iface, "wlan")
}
