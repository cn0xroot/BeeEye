// Package model defines the core data structures shared across the BeeEye agent.
//
// These mirror the storage schema described in program.md §3.6:
// device_registry / connections / dns_records / events / geoip_cache.
package model

import "time"

// DeviceCategory is returned to the frontend as an enum key (not a localized
// string), per program.md §3.8.1 — the UI maps the key to zh/en text.
type DeviceCategory string

const (
	CatUnknown DeviceCategory = "unknown"
	CatCamera  DeviceCategory = "camera"
	CatLock    DeviceCategory = "lock"
	CatNAS     DeviceCategory = "nas"
	CatRouter  DeviceCategory = "router"
	CatTV      DeviceCategory = "tv"
	CatPhone   DeviceCategory = "phone"
	CatLaptop  DeviceCategory = "laptop"
	CatFridge  DeviceCategory = "fridge"
	CatSpeaker DeviceCategory = "speaker"
)

// Sensitivity ranks how closely a category is monitored (program.md §3.5.3).
func (c DeviceCategory) Sensitivity() int {
	switch c {
	case CatLock, CatCamera:
		return 3 // high — full connection-event logging
	case CatNAS, CatRouter:
		return 2 // medium
	default:
		return 1 // low — aggregate stats only
	}
}

// Device is one row of the device_registry asset table (program.md §3.5.2).
type Device struct {
	MAC        string         `json:"mac"`
	IP         string         `json:"ip"`
	Vendor     string         `json:"vendor"`
	ModelGuess string         `json:"model_guess"`
	Category   DeviceCategory `json:"category"`
	Hostname   string         `json:"hostname"`
	Iface      string         `json:"iface"`       // source interface name (F17)
	AccessType string         `json:"access_type"` // "wireless" | "wired" (F17)
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	IsNew      bool           `json:"is_new"` // never acknowledged by admin (F8)
}

// Connection is one summarized flow — the core record feeding the by-IP /
// by-protocol / by-device views (program.md §3.6, connections table).
type Connection struct {
	ID          int64     `json:"id"`
	TS          time.Time `json:"ts"`
	MAC         string    `json:"mac"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     int       `json:"src_port"`
	DstIP       string    `json:"dst_ip"`
	DstPort     int       `json:"dst_port"`
	Proto       string    `json:"proto"`        // transport: TCP/UDP (F23)
	AppProtocol string    `json:"app_protocol"` // application layer (F23)
	Service     string    `json:"service"`      // port→service name (F24)
	Bytes       int64     `json:"bytes"`
	Packets     int64     `json:"packets"`
	Iface       string    `json:"iface"`    // source interface (F17)
	SNI         string    `json:"sni"`      // TLS ClientHello SNI (F3)
	JA3         string    `json:"ja3"`      // JA3 fingerprint (F3)
	Internal    bool      `json:"internal"` // dst is internal (east-west, F34)
}

// DNSRecord captures a resolved query (program.md §3.4.6, F21).
type DNSRecord struct {
	ID          int64     `json:"id"`
	TS          time.Time `json:"ts"`
	MAC         string    `json:"mac"`
	Domain      string    `json:"domain"`
	ResolvedIPs []string  `json:"resolved_ips"`
	TTL         int       `json:"ttl"`
	RCode       string    `json:"rcode"`     // NOERROR / NXDOMAIN — feeds DNS anomaly (F33)
	Encrypted   bool      `json:"encrypted"` // DoH/DoT: content not visible (F21 note)
}

// Severity for events / alerts.
type Severity string

const (
	SevInfo   Severity = "info"
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

// Event is one alert / audit row (program.md §3.6, events table).
// EventType is an enum key resolved to zh/en by the frontend (§3.8.1).
type Event struct {
	ID        int64          `json:"id"`
	TS        time.Time      `json:"ts"`
	MAC       string         `json:"mac"`
	EventType string         `json:"event_type"`
	Severity  Severity       `json:"severity"`
	RiskScore int            `json:"risk_score"`
	Detail    map[string]any `json:"detail"`  // structured, rendered by UI
	Signals   []string       `json:"signals"` // contributing signal keys (F37)
	Acked     bool           `json:"acked"`
}

// GeoInfo is a cached offline GeoIP lookup (program.md §3.5.5, F22).
type GeoInfo struct {
	IP      string  `json:"ip"`
	Country string  `json:"country"` // ISO code or "LOCAL"
	Region  string  `json:"region"`
	City    string  `json:"city"`
	ISP     string  `json:"isp,omitempty"` // network operator / organization (F22)
	ASN     uint    `json:"asn,omitempty"` // autonomous system number
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Local   bool    `json:"local"`            // private / CGNAT range
	Source  string  `json:"source,omitempty"` // "mmdb" | "builtin"
}
