package detect

import (
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
