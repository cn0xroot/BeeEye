package detect

import (
	"net"
	"testing"
	"time"

	"BeeEye/internal/config"
	"BeeEye/internal/model"
)

func testEngine() *Engine {
	c := config.Default()
	return &Engine{
		Cfg:   &c.Detection,
		Intel: ThreatIntel{BadIPs: map[string]bool{"45.13.34.7": true}, BadDomains: map[string]bool{}, BadJA3: map[string]bool{}},
		Cats:  map[string]model.DeviceCategory{"cam": model.CatCamera, "nas": model.CatNAS, "pc": model.CatLaptop},
	}
}

// Fixed-interval callbacks must be flagged as a beacon; NTP must not.
func TestBeacon(t *testing.T) {
	e := testEngine()
	base := time.Now().Add(-2 * time.Hour)
	var conns []model.Connection
	for i := 0; i < 10; i++ {
		jitter := time.Duration((i%3)-1) * time.Second // ±1s → CV tiny
		conns = append(conns, model.Connection{
			MAC: "cam", DstIP: "45.13.34.7", DstPort: 443,
			TS: base.Add(time.Duration(i)*60*time.Second + jitter),
		})
	}
	hits := e.Beacon(conns)
	if len(hits) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(hits))
	}
	for _, h := range hits {
		if h.CV >= e.Cfg.Beacon.CVThreshold {
			t.Errorf("CV %.3f should be below threshold", h.CV)
		}
	}
}

func TestBeaconIgnoresNTP(t *testing.T) {
	e := testEngine()
	base := time.Now().Add(-2 * time.Hour)
	var conns []model.Connection
	for i := 0; i < 10; i++ {
		conns = append(conns, model.Connection{
			MAC: "cam", DstIP: "1.2.3.4", DstPort: 123, Service: "NTP",
			TS: base.Add(time.Duration(i) * 60 * time.Second),
		})
	}
	if len(e.Beacon(conns)) != 0 {
		t.Error("NTP traffic must be whitelisted from beacon detection")
	}
}

// A camera hitting many internal hosts on mgmt ports = fanout + lateral.
func TestFanoutAndLateral(t *testing.T) {
	e := testEngine()
	base := time.Now()
	var conns []model.Connection
	for i := 20; i < 40; i++ { // 20 unique internal IPs, camera threshold is 5
		conns = append(conns, model.Connection{
			MAC: "cam", SrcIP: "192.168.1.20", DstIP: ip("192.168.1.", i),
			DstPort: 445, Proto: "TCP", Internal: true,
			TS: base.Add(time.Duration(i) * time.Second),
		})
	}
	if len(e.Fanout(conns)) == 0 {
		t.Error("expected fanout detection for 20 unique dst IPs on a camera")
	}
	if len(e.Lateral(conns)) == 0 {
		t.Error("expected lateral detection for camera→intranet:445")
	}
}

// End-to-end: the C2 beacon subject should score High (beacon+intel+first_target...).
func TestWeightedScoringHigh(t *testing.T) {
	e := testEngine()
	base := time.Now().Add(-2 * time.Hour)
	var conns []model.Connection
	for i := 0; i < 10; i++ {
		conns = append(conns, model.Connection{
			MAC: "cam", DstIP: "45.13.34.7", DstPort: 443, JA3: "x",
			TS: base.Add(time.Duration(i) * 60 * time.Second),
		})
	}
	events := e.Analyze(conns, nil, map[string]bool{})
	var high bool
	for _, ev := range events {
		if ev.MAC == "cam" && ev.Severity == model.SevHigh {
			high = true
		}
	}
	if !high {
		t.Errorf("expected a High-severity event for the C2 subject; got %+v", events)
	}
}

func TestDNSAnomalyDGA(t *testing.T) {
	e := testEngine()
	var recs []model.DNSRecord
	dga := []string{"x7f3q9z2k1.com", "9zk2m4p8w1.com", "q1w2e3r4t5.com", "z9x8c7v6b5.com", "m1n2b3v4c5.com", "p0o9i8u7y6.com"}
	for i, d := range dga {
		rc := "NXDOMAIN"
		recs = append(recs, model.DNSRecord{MAC: "pc", Domain: d, RCode: rc, TS: time.Now().Add(time.Duration(i) * time.Second)})
	}
	hits := e.DNSAnomaly(recs)
	if _, ok := hits["pc"]; !ok {
		t.Error("expected DGA/NXDOMAIN anomaly for pc")
	}
}

func ip(prefix string, i int) string { return prefix + itoa(i) }

// A device with a steady ~10KB/hour history at 03:00 that suddenly moves
// 50MB in that same hour today must be flagged; a device whose today value
// sits inside its normal range must not be.
func TestBaselineFlagsVolumeOutlier(t *testing.T) {
	e := testEngine()
	now := time.Date(2026, 8, 19, 3, 30, 0, 0, time.UTC) // "now" is inside the 03:00 bucket
	var conns []model.Connection
	for d := 1; d <= 6; d++ {
		day := time.Date(2026, 8, d, 3, 0, 0, 0, time.UTC)
		bytes := int64(10 * 1024) // steady 10KB baseline
		if d == 6 {
			day = now // today's sample, in the current hour bucket
			bytes = 50 * 1024 * 1024
		}
		conns = append(conns, model.Connection{MAC: "nas", DstIP: "192.168.1.1", TS: day, Bytes: bytes})
	}
	hits := e.Baseline(conns, now)
	hit, ok := hits[Subject{MAC: "nas"}]
	if !ok {
		t.Fatal("expected a baseline outlier for nas at 03:00")
	}
	if hit.Hour != 3 {
		t.Errorf("hour = %d, want 3", hit.Hour)
	}
	if hit.Z < e.Cfg.Baseline.ZThreshold {
		t.Errorf("z = %v, want >= %v", hit.Z, e.Cfg.Baseline.ZThreshold)
	}
}

func TestBaselineIgnoresNormalVariation(t *testing.T) {
	e := testEngine()
	now := time.Date(2026, 8, 19, 14, 15, 0, 0, time.UTC)
	var conns []model.Connection
	for d := 1; d <= 6; d++ {
		day := time.Date(2026, 8, d, 14, 0, 0, 0, time.UTC)
		bytes := int64(200*1024 + (d%3)*1024) // mild jitter around 200KB
		if d == 6 {
			day = now
		}
		conns = append(conns, model.Connection{MAC: "pc", DstIP: "192.168.1.1", TS: day, Bytes: bytes})
	}
	if hits := e.Baseline(conns, now); len(hits) != 0 {
		t.Errorf("expected no baseline hit for ordinary variation, got %+v", hits)
	}
}

func TestBaselineRequiresMinimumHistory(t *testing.T) {
	e := testEngine()
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	// Only two days of history — fewer than Cfg.Baseline.MinDays (5) — plus
	// today's spike. Must not fire: not enough history to call it an outlier.
	conns := []model.Connection{
		{MAC: "cam", DstIP: "192.168.1.1", TS: time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC), Bytes: 1024},
		{MAC: "cam", DstIP: "192.168.1.1", TS: time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC), Bytes: 1024},
		{MAC: "cam", DstIP: "192.168.1.1", TS: now, Bytes: 50 * 1024 * 1024},
	}
	if hits := e.Baseline(conns, now); len(hits) != 0 {
		t.Errorf("expected no hit with insufficient history, got %+v", hits)
	}
}

func TestThreatIntelMatchIPCIDR(t *testing.T) {
	_, cidr, err := net.ParseCIDR("5.42.92.0/23")
	if err != nil {
		t.Fatal(err)
	}
	ti := ThreatIntel{
		BadIPs:   map[string]bool{"45.13.34.7": true},
		BadCIDRs: []*net.IPNet{cidr},
	}
	if m, ok := ti.MatchIP("45.13.34.7"); !ok || m != "45.13.34.7" {
		t.Errorf("exact match = (%q, %v), want (45.13.34.7, true)", m, ok)
	}
	if m, ok := ti.MatchIP("5.42.93.10"); !ok || m != "5.42.92.0/23" {
		t.Errorf("CIDR match = (%q, %v), want (5.42.92.0/23, true)", m, ok)
	}
	if _, ok := ti.MatchIP("8.8.8.8"); ok {
		t.Error("8.8.8.8 should not match either the exact set or the CIDR range")
	}
	if _, ok := ti.MatchIP("not-an-ip"); ok {
		t.Error("a malformed address must not match")
	}
}

// A feed-sourced CIDR entry must trigger the same threat_intel signal as a
// hand-injected exact IP.
func TestThreatIntelSignalFromCIDR(t *testing.T) {
	e := testEngine()
	_, cidr, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	e.Intel.BadCIDRs = []*net.IPNet{cidr}
	conns := []model.Connection{{MAC: "pc", DstIP: "203.0.113.55", DstPort: 443, TS: time.Now()}}
	events := e.Analyze(conns, nil, map[string]bool{"pc|203.0.113.55": true})
	found := false
	for _, ev := range events {
		if ev.EventType == "threat_intel" {
			found = true
		}
	}
	if !found {
		t.Error("expected a threat_intel event for a destination inside a blocklisted CIDR")
	}
}
