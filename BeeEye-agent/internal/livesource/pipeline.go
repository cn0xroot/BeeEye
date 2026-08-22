// Package livesource turns a real packet capture into the rows the overview
// UI reads: devices, connections, DNS records and, periodically, risk events.
//
// It exists to close the gap the project carried for a while — the agent used
// to populate its store from a one-shot fabricated scenario (since removed —
// see main.go's legacySimulatedMACs), so the overview showed ten fictional
// devices while the analyzer showed the real network. This runs the same
// AF_PACKET capture the analyzer uses, dissects each frame, and aggregates
// the results into the model types the store already persists, so the two
// UIs finally describe the same traffic.
//
// Open returns an error when the kernel refuses a raw socket (no
// CAP_NET_RAW) — there is no simulated fallback to hand the caller instead
// (F43 taken to its conclusion: see internal/live's own doc comment) — so a
// Pipeline this package hands back is always backed by real capture.
package livesource

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
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
	"BeeEye/internal/livefile"
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
	// byteSampler feeds the overview's GPU-rendered traffic-trend curve
	// (api.Server.AddTrafficBytes, via SetByteSampler) — nil until wired in,
	// same atomic-pointer-on-the-hot-path treatment as tcap above. Called
	// from ingest (post-dissection, not run's raw packet-receive case) since
	// it needs the same tx/rx direction classification c.TxBytes/RxBytes
	// below already computes — direction is not knowable from the raw bytes
	// alone.
	byteSampler atomic.Pointer[func(tx, rx int64)]

	// live is always true today — Open only ever returns a Pipeline when
	// capsource reported a real capture source, and there is no simulated
	// fallback left to set this false (F43). Kept as a field, not hardcoded,
	// so Live() stays a meaningful contract if a future source tier needs to
	// report otherwise, rather than every caller assuming success == live.
	live  bool
	iface string

	mu      sync.Mutex
	flows   map[string]*model.Connection // 5-tuple key → accumulating flow
	devices map[string]*deviceSeen       // mac → what we know about it
	cats    map[string]model.DeviceCategory
	// pendingEvents holds "connection opened" rows for high-sensitivity
	// devices (DeviceCategory.Sensitivity() == 3, i.e. locks/cameras, F5).
	// Everything else only ever appears as the aggregated per-interval row
	// flush() writes; these get drained and written by run() right after the
	// packet that created them, so a lock/camera's new connection shows up
	// within one packet rather than waiting up to FlushInterval.
	pendingEvents []*model.Connection
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

	// Passive fingerprint fields (F1): parsed by internal/dissect but, before
	// this, never threaded past the packet-detail tree — this is that wire.
	// Set opportunistically as matching packets arrive; identity.Identify
	// only uses whichever of these ended up non-empty.
	dhcpParams  string // DHCP option 55, parameter request list
	vendorClass string // DHCP option 60
	userAgent   string // HTTP User-Agent
	ssdpServer  string // SSDP's Server: header
}

// Open starts a capture on iface and returns a running pipeline. snaplen and
// promisc mirror the analyzer's defaults. The returned Pipeline is already
// draining packets; call Close to stop it.
func Open(st *store.Store, iface string, cfg *config.Detection, intel detect.ThreatIntel) (*Pipeline, error) {
	src, real, err := capsource.Open(iface, live.DefaultSnapLen, true)
	if err != nil {
		return nil, err
	}
	p := newPipeline(st, src, real, cfg, intel)
	go p.run()
	return p, nil
}

// ImportFile replays a previously-captured pcap/pcapng file through the same
// aggregation a live capture gets, writing devices/connections/DNS records
// into st. It exists so importing a historical capture (from the analyzer's
// "open file" feature, F-offline-analysis) makes the overview reflect that
// capture too, rather than only ever showing the live database — before this,
// the two could disagree about what "the data" even was.
//
// Unlike Open, the returned Pipeline drains to completion on its own (the
// packet channel closes at EOF, same as Session.OpenFile's replay) rather
// than running indefinitely; callers do not need to Close it, though doing so
// mid-replay is harmless. Call Wait to block until the import has finished
// writing to st.
func ImportFile(st *store.Store, r io.Reader, name string, cfg *config.Detection, intel detect.ThreatIntel) (*Pipeline, error) {
	rc, ok := r.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(r)
	}
	src, err := livefile.Open(rc, name)
	if err != nil {
		return nil, err
	}
	p := newPipeline(st, src, true, cfg, intel)
	go p.run()
	return p, nil
}

func newPipeline(st *store.Store, src live.Source, real bool, cfg *config.Detection, intel detect.ThreatIntel) *Pipeline {
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
	return p
}

// Wait blocks until the pipeline's run loop has exited — for a live capture
// that means after Close, for an ImportFile replay it means the file has been
// fully read and its final flush written to the store.
func (p *Pipeline) Wait() { <-p.done }

// Live reports whether the capture is real — always true today (F43, see the
// live field's own comment).
func (p *Pipeline) Live() bool    { return p.live }
func (p *Pipeline) Iface() string { return p.iface }

// Source names which capture source is actually running: "ebpf" | "af_packet"
// | "pcap-file" (live.Source.Name()'s own values — see capsource.Open).
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

// SetByteSampler wires in the callback fed each dissected packet's on-wire
// length, split into (tx, rx) by the same local-endpoint direction ingest
// itself uses — exactly one of the two is non-zero per call, both zero for
// routed traffic with no local endpoint. How the overview's traffic-trend
// curve (F7) stays live without a second capture loop of its own.
func (p *Pipeline) SetByteSampler(fn func(tx, rx int64)) { p.byteSampler.Store(&fn) }

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
			// Write any lock/camera "connection opened" events queued by
			// ingest. Done here rather than inside ingest so the hot path
			// stays store-free except for this deliberate, low-volume
			// exception (F5's whole point is that these events do not wait
			// for the batch flush).
			for _, ev := range p.drainEvents() {
				if err := p.st.InsertConnection(ev); err != nil {
					log.Printf("livesource: insert connection event: %v", err)
				}
			}
		}
	}
}

// drainEvents returns and clears any pending high-sensitivity connection
// events queued by ingest.
func (p *Pipeline) drainEvents() []*model.Connection {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pendingEvents) == 0 {
		return nil
	}
	evs := p.pendingEvents
	p.pendingEvents = nil
	return evs
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

	// Feed the overview's traffic-trend curve (F7) here rather than on
	// run()'s raw packet-receive case: direction (tx = this gateway
	// sending, rx = receiving) is not knowable before dissection, and this
	// is the same isLocal classification c.TxBytes/RxBytes uses below for
	// the packets that go on to become a flow — done ahead of the
	// non-flow-packet early return further down so ARP/ICMP/etc. still
	// count toward the curve, same as every packet did before the split.
	if sampler := p.byteSampler.Load(); sampler != nil {
		switch {
		case srcOK && isLocal(srcIP):
			(*sampler)(int64(r.Length), 0)
		case dstOK && isLocal(dstIP):
			(*sampler)(0, int64(r.Length))
		}
	}

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

	// Passive fingerprint fields (F1): DHCP's own chaddr is authoritative for
	// which device a DHCPDISCOVER/DHCPREQUEST's option 55/60/12 describe,
	// even across a relay; HTTP User-Agent and SSDP's Server header simply
	// describe whichever device sent this particular frame.
	fpMAC := first(r.Fields["dhcp.hw.mac_addr"])
	if fpMAC == "" {
		fpMAC = srcMAC
	}
	if fpMAC != "" {
		p.seeFingerprint(fpMAC, r)
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
	newFlow := c == nil
	var mac string
	if newFlow {
		mac = srcMAC
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
	// This one frame's own direction, independent of which end holds the
	// flow's canonical Src/Dst (see flowKey): local-as-source is this
	// device sending, local-as-destination is it receiving. A frame with
	// neither end local (routed traffic this gateway is not a party to)
	// credits neither counter, which is honest — Bytes still carries the
	// total, TxBytes+RxBytes just may not sum to it for that case.
	switch {
	case srcOK && isLocal(srcIP):
		c.TxBytes += int64(r.Length)
	case dstOK && isLocal(dstIP):
		c.RxBytes += int64(r.Length)
	}
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

	// F5: locks/cameras (Sensitivity 3) get every connection logged as its
	// own event instead of only appearing in the next aggregated flush, the
	// way the eBPF kernel path already treats them (bpf/BeeEye.bpf.c). Fire
	// once per flow, on the packet that opened it, then zero the running
	// totals so this first packet isn't counted twice when flush() later
	// writes the rest of the window's traffic on the same flow.
	if newFlow && p.cats[mac].Sensitivity() == 3 {
		ev := *c
		p.pendingEvents = append(p.pendingEvents, &ev)
		c.Packets, c.Bytes, c.TxBytes, c.RxBytes = 0, 0, 0, 0
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
		QType:  first(r.FieldValues("dns.qry.type")),
		Iface:  r.Iface,
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

// seeFingerprint records whichever passive-fingerprint fields (F1) this
// packet carries against mac. It deliberately does nothing — not even a
// p.devices lookup — for the overwhelming majority of packets that carry
// none of these fields, and only marks the device dirty (due for an
// UpsertDevice write at the next flush) when a field's value actually
// changes, so a chatty device does not force a write every single packet
// once its fingerprint has already been recorded once.
func (p *Pipeline) seeFingerprint(mac string, r *dissect.Result) {
	hostname := first(r.Fields["dhcp.option.hostname"])
	dhcpParams := first(r.Fields["dhcp.option.request_list_item"])
	vendorClass := first(r.Fields["dhcp.option.vendor_class_id"])
	userAgent := first(r.Fields["http.user_agent"])
	ssdpServer := first(r.Fields["ssdp.server"])
	if hostname == "" && dhcpParams == "" && vendorClass == "" && userAgent == "" && ssdpServer == "" {
		return
	}
	d := p.devices[mac]
	if d == nil {
		d = &deviceSeen{iface: r.Iface, firstTS: r.TS, wireless: isWireless(r.Iface)}
		p.devices[mac] = d
	}
	changed := false
	set := func(dst *string, v string) {
		if v != "" && *dst != v {
			*dst = v
			changed = true
		}
	}
	set(&d.hostname, hostname)
	set(&d.dhcpParams, dhcpParams)
	set(&d.vendorClass, vendorClass)
	set(&d.userAgent, userAgent)
	set(&d.ssdpServer, ssdpServer)
	if changed {
		d.lastTS = r.TS
		d.dirty = true
	}
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
		id := identity.Identify(mac, d.hostname, identity.Fingerprint{
			DHCPParams:  d.dhcpParams,
			VendorClass: d.vendorClass,
			UserAgent:   d.userAgent,
			SSDPServer:  d.ssdpServer,
		})
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

// isWireless asks the kernel, not the interface's own name. A name-based
// guess ("starts with wl", "contains wlan") only covers the common systemd
// predictable-naming and legacy wlanN cases — it misclassifies a renamed
// interface (a custom udev rule, a distro that never adopted predictable
// naming) or an older driver's own convention (ath0, ra0, ...) as wired, on
// hardware this project's own dev box never happens to exercise but a real
// user's very well might. /sys/class/net/<iface>/phy80211 is the same
// naming-agnostic signal `iw dev` itself uses to enumerate wireless
// interfaces — present for any 802.11 interface regardless of what it is
// called, absent for everything else.
func isWireless(iface string) bool {
	_, err := os.Stat("/sys/class/net/" + iface + "/phy80211")
	return err == nil
}
