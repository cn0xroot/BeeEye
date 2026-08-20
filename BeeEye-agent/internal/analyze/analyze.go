// Package analyze performs offline analysis of a capture file.
//
// This is the batch counterpart to the live analyzer: the same dissector runs
// over every packet, and the results are rolled up into the report the web UI
// renders — protocol and conversation statistics, reconstructed sessions,
// plaintext credentials, carved files, and attack indicators.
//
// Design note on honesty: everything here reports what was actually observed.
// Where a signal is a heuristic — an attack pattern in a URL, a suspected
// brute-force burst — it is labeled as a heuristic with the evidence attached,
// so a reader can judge it rather than take a verdict on faith.
package analyze

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"BeeEye/internal/dissect"
	"BeeEye/internal/geoip"
	"BeeEye/internal/live"
	"BeeEye/internal/model"
	"BeeEye/internal/pcapfile"
)

// Report is the complete result of analysing one capture file.
type Report struct {
	ID       string    `json:"id"`
	Filename string    `json:"filename"`
	Size     int64     `json:"size"`
	Uploaded time.Time `json:"uploaded"`

	Summary       Summary        `json:"summary"`
	Protocols     []ProtoStat    `json:"protocols"`
	Talkers       []TalkerStat   `json:"talkers"`
	Conversations []Conversation `json:"conversations"`
	Timeline      []Bucket       `json:"timeline"`
	DNS           []DNSQuery     `json:"dns"`
	HTTP          []HTTPRequest  `json:"http"`
	Sessions      []Session      `json:"sessions"`
	Credentials   []Credential   `json:"credentials"`
	Files         []CarvedFile   `json:"files"`
	Findings      []Finding      `json:"findings"`
	GeoPoints     []GeoPoint     `json:"geo_points"`

	// Warnings records anything that limited the analysis — a truncated file,
	// a link type we do not dissect. Silently returning a partial report would
	// let a reader mistake "we could not see it" for "it did not happen".
	Warnings []string `json:"warnings"`
}

// Summary is the header of the report.
type Summary struct {
	Packets     int       `json:"packets"`
	Bytes       int64     `json:"bytes"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	DurationSec float64   `json:"duration_sec"`
	LinkType    string    `json:"link_type"`
	SnapLen     uint32    `json:"snaplen"`
	Truncated   int       `json:"truncated"` // packets cut short by the snaplen
	IPv4        int       `json:"ipv4"`
	IPv6        int       `json:"ipv6"`
	TCP         int       `json:"tcp"`
	UDP         int       `json:"udp"`
	Other       int       `json:"other"`
	UniqueIPs   int       `json:"unique_ips"`
	UniqueMACs  int       `json:"unique_macs"`
}

type ProtoStat struct {
	Protocol string  `json:"protocol"`
	Packets  int     `json:"packets"`
	Bytes    int64   `json:"bytes"`
	Share    float64 `json:"share"` // fraction of total bytes
}

type TalkerStat struct {
	IP       string        `json:"ip"`
	Packets  int           `json:"packets"`
	Bytes    int64         `json:"bytes"`
	Sent     int64         `json:"sent"`
	Received int64         `json:"received"`
	Geo      model.GeoInfo `json:"geo"`
}

type Conversation struct {
	A        string    `json:"a"`
	BPeer    string    `json:"b"`
	Proto    string    `json:"proto"`
	APort    int       `json:"a_port"`
	BPort    int       `json:"b_port"`
	Packets  int       `json:"packets"`
	Bytes    int64     `json:"bytes"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	AppProto string    `json:"app_proto"`
}

type Bucket struct {
	TS      int64 `json:"ts"`
	Packets int   `json:"packets"`
	Bytes   int64 `json:"bytes"`
}

type DNSQuery struct {
	TS       time.Time `json:"ts"`
	Client   string    `json:"client"`
	Domain   string    `json:"domain"`
	Type     string    `json:"type"`
	Answers  []string  `json:"answers"`
	RCode    string    `json:"rcode"`
	Response bool      `json:"response"`
}

type HTTPRequest struct {
	TS        time.Time `json:"ts"`
	Client    string    `json:"client"`
	Server    string    `json:"server"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	URI       string    `json:"uri"`
	UserAgent string    `json:"user_agent"`
}

type GeoPoint struct {
	IP      string  `json:"ip"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Bytes   int64   `json:"bytes"`
}

// Collector accumulates dissected packets into a report.
//
// It is the shared core of both analysis paths: a capture file is read and fed
// through here, and so is the live analyzer's in-memory packet ring. One code
// path means an uploaded pcap and a live capture cannot disagree about what
// they found in the same traffic.
type Collector struct {
	agg     *aggregator
	streams *streamTable
	rep     *Report
}

// NewCollector returns an empty collector.
func NewCollector() *Collector {
	return &Collector{
		agg:     newAggregator(),
		streams: newStreamTable(),
		rep:     &Report{Uploaded: time.Now()},
	}
}

// Add feeds one dissected packet in.
func (c *Collector) Add(r *dissect.Result) {
	c.agg.add(r)
	c.streams.add(r)
}

// Warn records something that limited the analysis.
func (c *Collector) Warn(msg string) { c.rep.Warnings = append(c.rep.Warnings, msg) }

// Meta sets the descriptive header of the report.
func (c *Collector) Meta(filename string, size int64, linkType string, snapLen uint32) {
	c.rep.Filename = filename
	c.rep.Size = size
	c.rep.Summary.LinkType = linkType
	c.rep.Summary.SnapLen = snapLen
}

// Report finalises and returns the analysis. It is not reusable afterwards.
func (c *Collector) Report() *Report {
	rep := c.rep
	c.agg.finish(rep)

	sessions, creds, files, findings := c.streams.finish()
	rep.Sessions = sessions
	rep.Credentials = creds
	rep.Files = files
	rep.Findings = append(rep.Findings, findings...)
	rep.Findings = append(rep.Findings, detectBruteForce(rep.Sessions)...)
	rep.Findings = append(rep.Findings, detectScanning(rep.Conversations)...)

	sort.Slice(rep.Findings, func(i, j int) bool {
		return severityRank(rep.Findings[i].Severity) > severityRank(rep.Findings[j].Severity)
	})
	return rep
}

// Analyze reads a capture file and produces the full report.
func Analyze(r io.Reader, filename string, size int64) (*Report, error) {
	pr, err := pcapfile.NewReader(r)
	if err != nil {
		return nil, err
	}
	hdr := pr.Header()

	c := NewCollector()
	c.Meta(filename, size, pcapfile.LinkTypeName(hdr.LinkType), hdr.SnapLen)
	if hdr.LinkType != pcapfile.LinkEthernet {
		c.Warn(fmt.Sprintf(
			"link type is %s; this build dissects Ethernet frames, so layers above the link header may not be decoded",
			pcapfile.LinkTypeName(hdr.LinkType)))
	}

	dis := dissect.New()
	for {
		p, err := pr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A truncated file still yields everything read so far — that is
			// usually the interesting part, and refusing to report it would
			// help nobody.
			c.Warn(err.Error())
			break
		}
		c.Add(dis.Packet(live.Packet{
			Index:   p.Index,
			TS:      p.TS,
			Iface:   "file",
			Data:    p.Data,
			CapLen:  p.CapLen,
			OrigLen: p.OrigLen,
		}))
	}
	return c.Report(), nil
}

// ------------------------------------------------------------- aggregation

type aggregator struct {
	protoPkts  map[string]int
	protoBytes map[string]int64
	ipPkts     map[string]int
	ipBytes    map[string]int64
	ipSent     map[string]int64
	ipRecv     map[string]int64
	macs       map[string]bool
	convs      map[string]*Conversation
	buckets    map[int64]*Bucket
	dns        []DNSQuery
	http       []HTTPRequest
	first      time.Time
	last       time.Time
	total      int64
	bucketSec  int64
}

func newAggregator() *aggregator {
	return &aggregator{
		protoPkts: map[string]int{}, protoBytes: map[string]int64{},
		ipPkts: map[string]int{}, ipBytes: map[string]int64{},
		ipSent: map[string]int64{}, ipRecv: map[string]int64{},
		macs: map[string]bool{}, convs: map[string]*Conversation{},
		buckets: map[int64]*Bucket{}, bucketSec: 1,
	}
}

func (a *aggregator) add(r *dissect.Result) {
	n := int64(r.Length)
	a.total += n

	if a.first.IsZero() || r.TS.Before(a.first) {
		a.first = r.TS
	}
	if r.TS.After(a.last) {
		a.last = r.TS
	}

	a.protoPkts[r.Proto]++
	a.protoBytes[r.Proto] += n

	if r.HasProtocol("eth") {
		if v := r.FieldValues("eth.src"); len(v) > 0 {
			a.macs[v[0]] = true
		}
		if v := r.FieldValues("eth.dst"); len(v) > 0 {
			a.macs[v[0]] = true
		}
	}

	if r.HasProtocol("ip") || r.HasProtocol("ipv6") {
		a.ipPkts[r.Src]++
		a.ipPkts[r.Dst]++
		a.ipBytes[r.Src] += n
		a.ipBytes[r.Dst] += n
		a.ipSent[r.Src] += n
		a.ipRecv[r.Dst] += n

		if r.Transport != "" {
			key, aIP, bIP, aPort, bPort := convKey(r)
			c := a.convs[key]
			if c == nil {
				c = &Conversation{A: aIP, BPeer: bIP, Proto: strings.ToUpper(r.Transport),
					APort: aPort, BPort: bPort, First: r.TS, AppProto: r.Proto}
				a.convs[key] = c
			}
			c.Packets++
			c.Bytes += n
			c.Last = r.TS
			// The most specific protocol seen on a conversation wins: a flow
			// whose first packet was a bare ACK is still an HTTPS conversation.
			if c.AppProto == "TCP" || c.AppProto == "UDP" {
				c.AppProto = r.Proto
			}
		}
	}

	b := r.TS.Unix() / a.bucketSec * a.bucketSec
	bk := a.buckets[b]
	if bk == nil {
		bk = &Bucket{TS: b}
		a.buckets[b] = bk
	}
	bk.Packets++
	bk.Bytes += n

	a.collectDNS(r)
	a.collectHTTP(r)
}

// convKey orders the endpoints so both directions land on one conversation.
func convKey(r *dissect.Result) (key, aIP, bIP string, aPort, bPort int) {
	if r.Src < r.Dst || (r.Src == r.Dst && r.SrcPort <= r.DstPort) {
		return fmt.Sprintf("%s|%s:%d|%s:%d", r.Transport, r.Src, r.SrcPort, r.Dst, r.DstPort),
			r.Src, r.Dst, r.SrcPort, r.DstPort
	}
	return fmt.Sprintf("%s|%s:%d|%s:%d", r.Transport, r.Dst, r.DstPort, r.Src, r.SrcPort),
		r.Dst, r.Src, r.DstPort, r.SrcPort
}

func (a *aggregator) collectDNS(r *dissect.Result) {
	if !r.HasProtocol("dns") && !r.HasProtocol("mdns") {
		return
	}
	names := r.FieldValues("dns.qry.name")
	if len(names) == 0 {
		return
	}
	isResp := false
	if v := r.FieldValues("dns.flags.response"); len(v) > 0 && v[0] == "1" {
		isResp = true
	}
	q := DNSQuery{TS: r.TS, Client: r.Src, Domain: names[0], Response: isResp, RCode: "0"}
	if v := r.FieldValues("dns.qry.type"); len(v) > 0 {
		q.Type = v[0]
	}
	if v := r.FieldValues("dns.flags.rcode"); len(v) > 0 {
		q.RCode = v[0]
	}
	q.Answers = append(q.Answers, r.FieldValues("dns.a")...)
	q.Answers = append(q.Answers, r.FieldValues("dns.aaaa")...)
	if isResp {
		q.Client = r.Dst // the querier is the one receiving the answer
	}
	a.dns = append(a.dns, q)
}

func (a *aggregator) collectHTTP(r *dissect.Result) {
	m := r.FieldValues("http.request.method")
	if len(m) == 0 {
		return
	}
	req := HTTPRequest{TS: r.TS, Client: r.Src, Server: r.Dst, Method: m[0]}
	if v := r.FieldValues("http.request.uri"); len(v) > 0 {
		req.URI = v[0]
	}
	if v := r.FieldValues("http.host"); len(v) > 0 {
		req.Host = v[0]
	}
	if v := r.FieldValues("http.user_agent"); len(v) > 0 {
		req.UserAgent = v[0]
	}
	a.http = append(a.http, req)
}

func (a *aggregator) finish(rep *Report) {
	s := &rep.Summary
	s.First, s.Last = a.first, a.last
	if !a.first.IsZero() {
		s.DurationSec = a.last.Sub(a.first).Seconds()
	}
	s.Bytes = a.total
	s.UniqueMACs = len(a.macs)
	s.UniqueIPs = len(a.ipBytes)

	for proto, pkts := range a.protoPkts {
		s.Packets += pkts
		share := 0.0
		if a.total > 0 {
			share = float64(a.protoBytes[proto]) / float64(a.total)
		}
		rep.Protocols = append(rep.Protocols, ProtoStat{
			Protocol: proto, Packets: pkts, Bytes: a.protoBytes[proto], Share: share,
		})
	}
	sort.Slice(rep.Protocols, func(i, j int) bool { return rep.Protocols[i].Bytes > rep.Protocols[j].Bytes })

	for ip, b := range a.ipBytes {
		g := geoip.Lookup(ip)
		rep.Talkers = append(rep.Talkers, TalkerStat{
			IP: ip, Packets: a.ipPkts[ip], Bytes: b,
			Sent: a.ipSent[ip], Received: a.ipRecv[ip], Geo: g,
		})
		if !g.Local && g.Lat != 0 && g.Lon != 0 {
			rep.GeoPoints = append(rep.GeoPoints, GeoPoint{
				IP: ip, Country: g.Country, City: g.City, Lat: g.Lat, Lon: g.Lon, Bytes: b,
			})
		}
	}
	sort.Slice(rep.Talkers, func(i, j int) bool { return rep.Talkers[i].Bytes > rep.Talkers[j].Bytes })
	if len(rep.Talkers) > 200 {
		rep.Talkers = rep.Talkers[:200]
	}
	sort.Slice(rep.GeoPoints, func(i, j int) bool { return rep.GeoPoints[i].Bytes > rep.GeoPoints[j].Bytes })

	for _, c := range a.convs {
		rep.Conversations = append(rep.Conversations, *c)
	}
	sort.Slice(rep.Conversations, func(i, j int) bool {
		return rep.Conversations[i].Bytes > rep.Conversations[j].Bytes
	})

	var keys []int64
	for k := range a.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		rep.Timeline = append(rep.Timeline, *a.buckets[k])
	}

	rep.DNS = a.dns
	rep.HTTP = a.http

	for _, p := range rep.Protocols {
		switch {
		case strings.EqualFold(p.Protocol, "TCP"):
			s.TCP += p.Packets
		case strings.EqualFold(p.Protocol, "UDP"):
			s.UDP += p.Packets
		}
	}
}
