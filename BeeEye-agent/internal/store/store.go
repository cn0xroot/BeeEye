// Package store is the SQLite persistence layer (program.md §3.6).
//
// Tables: device_registry, connections, dns_records, events, geoip_cache.
// Uses the pure-Go modernc.org/sqlite driver so the binary needs no CGO.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"BeeEye/internal/model"
)

type Store struct {
	db *sql.DB
	mu sync.Mutex // serialize writes; SQLite single-writer
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // modernc + single writer: avoid "database is locked"
	s := &Store{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init() error {
	schema := `
CREATE TABLE IF NOT EXISTS device_registry (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    vendor      TEXT,
    model_guess TEXT,
    category    TEXT,
    hostname    TEXT,
    iface       TEXT,
    access_type TEXT,
    first_seen  INTEGER,
    last_seen   INTEGER,
    is_new      INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS connections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER,
    mac          TEXT,
    src_ip       TEXT, src_port INTEGER,
    dst_ip       TEXT, dst_port INTEGER,
    proto        TEXT,
    app_protocol TEXT,
    service      TEXT,
    bytes        INTEGER,
    packets      INTEGER,
    iface        TEXT,
    sni          TEXT,
    ja3          TEXT,
    internal     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_conn_mac  ON connections(mac);
CREATE INDEX IF NOT EXISTS idx_conn_dst  ON connections(dst_ip);
CREATE INDEX IF NOT EXISTS idx_conn_ts   ON connections(ts);
CREATE INDEX IF NOT EXISTS idx_conn_app  ON connections(app_protocol);
CREATE TABLE IF NOT EXISTS dns_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER,
    mac          TEXT,
    domain       TEXT,
    resolved_ips TEXT,
    ttl          INTEGER,
    rcode        TEXT,
    encrypted    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_dns_mac    ON dns_records(mac);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER,
    mac        TEXT,
    event_type TEXT,
    severity   TEXT,
    risk_score INTEGER,
    detail     TEXT,
    signals    TEXT,
    acked      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_evt_ts  ON events(ts);
CREATE INDEX IF NOT EXISTS idx_evt_mac ON events(mac);
CREATE TABLE IF NOT EXISTS geoip_cache (
    ip        TEXT PRIMARY KEY,
    country   TEXT, region TEXT, city TEXT,
    lat       REAL, lon REAL, local INTEGER,
    cached_at INTEGER
);
`
	_, err := s.db.Exec(schema)
	return err
}

// ---------- devices ----------

// UpsertDevice inserts or updates a device, preserving first_seen/is_new.
// Returns true if this MAC was newly inserted (drives F8 new-device alert).
func (s *Store) UpsertDevice(d *model.Device) (isNew bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var existingFirst int64
	row := s.db.QueryRow(`SELECT first_seen FROM device_registry WHERE mac=?`, d.MAC)
	scanErr := row.Scan(&existingFirst)
	if scanErr == sql.ErrNoRows {
		_, err = s.db.Exec(`INSERT INTO device_registry
            (mac,ip,vendor,model_guess,category,hostname,iface,access_type,first_seen,last_seen,is_new)
            VALUES (?,?,?,?,?,?,?,?,?,?,1)`,
			d.MAC, d.IP, d.Vendor, d.ModelGuess, string(d.Category), d.Hostname, d.Iface, d.AccessType,
			d.FirstSeen.Unix(), d.LastSeen.Unix())
		return true, err
	} else if scanErr != nil {
		return false, scanErr
	}
	_, err = s.db.Exec(`UPDATE device_registry
        SET ip=?, vendor=?, model_guess=?, category=?, hostname=?, iface=?, access_type=?, last_seen=?
        WHERE mac=?`,
		d.IP, d.Vendor, d.ModelGuess, string(d.Category), d.Hostname, d.Iface, d.AccessType,
		d.LastSeen.Unix(), d.MAC)
	return false, err
}

func (s *Store) Devices() ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT mac,ip,vendor,model_guess,category,hostname,iface,access_type,first_seen,last_seen,is_new
        FROM device_registry ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		var d model.Device
		var cat string
		var fs, ls int64
		var isNew int
		if err := rows.Scan(&d.MAC, &d.IP, &d.Vendor, &d.ModelGuess, &cat, &d.Hostname, &d.Iface, &d.AccessType, &fs, &ls, &isNew); err != nil {
			return nil, err
		}
		d.Category = model.DeviceCategory(cat)
		d.FirstSeen = time.Unix(fs, 0)
		d.LastSeen = time.Unix(ls, 0)
		d.IsNew = isNew == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) AckDevice(mac string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE device_registry SET is_new=0 WHERE mac=?`, mac)
	return err
}

// SetCategory writes back an admin-assigned category (drives kernel category map).
func (s *Store) SetCategory(mac string, cat model.DeviceCategory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE device_registry SET category=? WHERE mac=?`, string(cat), mac)
	return err
}

// ---------- connections ----------

func (s *Store) InsertConnection(c *model.Connection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO connections
        (ts,mac,src_ip,src_port,dst_ip,dst_port,proto,app_protocol,service,bytes,packets,iface,sni,ja3,internal)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.TS.Unix(), c.MAC, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, c.Proto, c.AppProtocol, c.Service,
		c.Bytes, c.Packets, c.Iface, c.SNI, c.JA3, b2i(c.Internal))
	return err
}

// ConnFilter is the multi-dimension search (program.md §3.6.1, F30).
type ConnFilter struct {
	MACs         []string
	IPLike       string // matches src_ip or dst_ip substring, or domain via join
	Protos       []string
	PortMin      int
	PortMax      int
	Since        time.Time
	Until        time.Time
	InternalOnly bool
	Limit        int
}

func (s *Store) Connections(f ConnFilter) ([]model.Connection, error) {
	var where []string
	var args []any
	if len(f.MACs) > 0 {
		where = append(where, "mac IN ("+placeholders(len(f.MACs))+")")
		for _, m := range f.MACs {
			args = append(args, m)
		}
	}
	if f.IPLike != "" {
		where = append(where, "(src_ip LIKE ? OR dst_ip LIKE ?)")
		args = append(args, "%"+f.IPLike+"%", "%"+f.IPLike+"%")
	}
	if len(f.Protos) > 0 {
		where = append(where, "app_protocol IN ("+placeholders(len(f.Protos))+")")
		for _, p := range f.Protos {
			args = append(args, p)
		}
	}
	if f.PortMin > 0 {
		where = append(where, "dst_port >= ?")
		args = append(args, f.PortMin)
	}
	if f.PortMax > 0 {
		where = append(where, "dst_port <= ?")
		args = append(args, f.PortMax)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, f.Until.Unix())
	}
	if f.InternalOnly {
		where = append(where, "internal = 1")
	}
	q := `SELECT id,ts,mac,src_ip,src_port,dst_ip,dst_port,proto,app_protocol,service,bytes,packets,iface,sni,ja3,internal FROM connections`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY ts DESC"
	if f.Limit <= 0 {
		f.Limit = 1000
	}
	q += fmt.Sprintf(" LIMIT %d", f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanConns(rows)
}

func scanConns(rows *sql.Rows) ([]model.Connection, error) {
	var out []model.Connection
	for rows.Next() {
		var c model.Connection
		var ts int64
		var internal int
		if err := rows.Scan(&c.ID, &ts, &c.MAC, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort,
			&c.Proto, &c.AppProtocol, &c.Service, &c.Bytes, &c.Packets, &c.Iface, &c.SNI, &c.JA3, &internal); err != nil {
			return nil, err
		}
		c.TS = time.Unix(ts, 0)
		c.Internal = internal == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- dns ----------

func (s *Store) InsertDNS(r *model.DNSRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ips, _ := json.Marshal(r.ResolvedIPs)
	_, err := s.db.Exec(`INSERT INTO dns_records (ts,mac,domain,resolved_ips,ttl,rcode,encrypted)
        VALUES (?,?,?,?,?,?,?)`,
		r.TS.Unix(), r.MAC, r.Domain, string(ips), r.TTL, r.RCode, b2i(r.Encrypted))
	return err
}

func (s *Store) DNSRecords(mac string, limit int) ([]model.DNSRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	var rows *sql.Rows
	var err error
	if mac != "" {
		rows, err = s.db.Query(`SELECT id,ts,mac,domain,resolved_ips,ttl,rcode,encrypted FROM dns_records WHERE mac=? ORDER BY ts DESC LIMIT ?`, mac, limit)
	} else {
		rows, err = s.db.Query(`SELECT id,ts,mac,domain,resolved_ips,ttl,rcode,encrypted FROM dns_records ORDER BY ts DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DNSRecord
	for rows.Next() {
		var r model.DNSRecord
		var ts int64
		var ips string
		var enc int
		if err := rows.Scan(&r.ID, &ts, &r.MAC, &r.Domain, &ips, &r.TTL, &r.RCode, &enc); err != nil {
			return nil, err
		}
		r.TS = time.Unix(ts, 0)
		_ = json.Unmarshal([]byte(ips), &r.ResolvedIPs)
		r.Encrypted = enc == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// DomainForIP returns the most recent domain that resolved to ip (F25 join).
func (s *Store) DomainForIP(ip string) (string, bool) {
	rows, err := s.db.Query(`SELECT domain,resolved_ips FROM dns_records ORDER BY ts DESC LIMIT 2000`)
	if err != nil {
		return "", false
	}
	defer rows.Close()
	for rows.Next() {
		var domain, ips string
		if err := rows.Scan(&domain, &ips); err != nil {
			continue
		}
		var list []string
		_ = json.Unmarshal([]byte(ips), &list)
		for _, x := range list {
			if x == ip {
				return domain, true
			}
		}
	}
	return "", false
}

// ---------- events ----------

func (s *Store) InsertEvent(e *model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	detail, _ := json.Marshal(e.Detail)
	sig, _ := json.Marshal(e.Signals)
	_, err := s.db.Exec(`INSERT INTO events (ts,mac,event_type,severity,risk_score,detail,signals,acked)
        VALUES (?,?,?,?,?,?,?,0)`,
		e.TS.Unix(), e.MAC, e.EventType, string(e.Severity), e.RiskScore, string(detail), string(sig))
	return err
}

func (s *Store) Events(limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.Query(`SELECT id,ts,mac,event_type,severity,risk_score,detail,signals,acked
        FROM events ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var ts int64
		var detail, sig string
		var acked int
		if err := rows.Scan(&e.ID, &ts, &e.MAC, &e.EventType, &e.Severity, &e.RiskScore, &detail, &sig, &acked); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		_ = json.Unmarshal([]byte(detail), &e.Detail)
		_ = json.Unmarshal([]byte(sig), &e.Signals)
		e.Acked = acked == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AckEvent(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE events SET acked=1 WHERE id=?`, id)
	return err
}

// ---------- geoip cache ----------

func (s *Store) CacheGeo(g model.GeoInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO geoip_cache (ip,country,region,city,lat,lon,local,cached_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET country=excluded.country, region=excluded.region,
            city=excluded.city, lat=excluded.lat, lon=excluded.lon, cached_at=excluded.cached_at`,
		g.IP, g.Country, g.Region, g.City, g.Lat, g.Lon, b2i(g.Local), time.Now().Unix())
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// DB exposes the raw handle for aggregation queries (used by the api package).
func (s *Store) DB() *sql.DB { return s.db }
