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
    tx_bytes     INTEGER DEFAULT 0,
    rx_bytes     INTEGER DEFAULT 0,
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
    encrypted    INTEGER,
    iface        TEXT
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
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	return s.migrate()
}

// migrate covers columns added after a table's CREATE TABLE IF NOT EXISTS
// already ran on someone's database — that clause only creates a table that
// does not exist yet, so a column added later needs its own step. SQLite has
// no "ADD COLUMN IF NOT EXISTS"; attempting it and ignoring the "duplicate
// column" a table that already has it returns is the ordinary way to make
// that idempotent.
func (s *Store) migrate() error {
	stmts := []string{
		`ALTER TABLE connections ADD COLUMN tx_bytes INTEGER DEFAULT 0`,
		`ALTER TABLE connections ADD COLUMN rx_bytes INTEGER DEFAULT 0`,
		`ALTER TABLE dns_records ADD COLUMN iface TEXT`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("store: migrate: %s: %w", stmt, err)
		}
	}
	return nil
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
        (ts,mac,src_ip,src_port,dst_ip,dst_port,proto,app_protocol,service,bytes,tx_bytes,rx_bytes,packets,iface,sni,ja3,internal)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.TS.Unix(), c.MAC, c.SrcIP, c.SrcPort, c.DstIP, c.DstPort, c.Proto, c.AppProtocol, c.Service,
		c.Bytes, c.TxBytes, c.RxBytes, c.Packets, c.Iface, c.SNI, c.JA3, b2i(c.Internal))
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
	// Iface, when set, restricts to rows from exactly this capture source.
	// For live-captured rows that is the NIC name; for a file imported via
	// livesource.ImportFile it is the filename (see Pipeline.iface, sourced
	// from live.Source.Iface()) — the only thing distinguishing "just this
	// import" from everything else already in the store, short of a
	// dedicated column. Scoping to it is what lets the overview show an
	// import's data without it being crowded out of the default ts-DESC
	// window by ongoing live traffic (see api.geoPairs).
	Iface string
	Limit int
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
	if f.Iface != "" {
		where = append(where, "iface = ?")
		args = append(args, f.Iface)
	}
	if f.InternalOnly {
		where = append(where, "internal = 1")
	}
	q := `SELECT id,ts,mac,src_ip,src_port,dst_ip,dst_port,proto,app_protocol,service,bytes,tx_bytes,rx_bytes,packets,iface,sni,ja3,internal FROM connections`
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

// ConnTotals is the handful of numbers the overview's summary card needs out
// of the connections table — everything /api/summary used to get by calling
// Connections with a 100000 row cap and summing them in Go. That fetched and
// scanned a full Connection struct (18 columns) per row just to throw away
// everything but four numbers; as the table grows past tens of thousands of
// rows on a long-running capture, marshaling all of them every 3-second
// overview poll turns into multi-second stalls the UI reads as a blank
// "Loading…" page. A single SQL aggregate does the same sum inside SQLite
// itself and returns one row regardless of table size.
type ConnTotals struct {
	Count      int
	TotalBytes int64
	TotalTx    int64
	TotalRx    int64
	Internal   int
}

// ConnectionTotals is ConnTotals' query — same Iface scoping as Connections
// (see ConnFilter.Iface's comment), everything else in ConnFilter (mac/proto/
// port/time filters) is not needed by any caller of this today and left out
// rather than plumbed through unused.
func (s *Store) ConnectionTotals(iface string) (ConnTotals, error) {
	q := `SELECT COUNT(*), COALESCE(SUM(bytes),0), COALESCE(SUM(tx_bytes),0), COALESCE(SUM(rx_bytes),0),
	      COALESCE(SUM(CASE WHEN internal = 1 THEN 1 ELSE 0 END),0) FROM connections`
	var args []any
	if iface != "" {
		q += " WHERE iface = ?"
		args = append(args, iface)
	}
	var t ConnTotals
	err := s.db.QueryRow(q, args...).Scan(&t.Count, &t.TotalBytes, &t.TotalTx, &t.TotalRx, &t.Internal)
	return t, err
}

// ImportBatch summarizes one distinct "iface" value's rows in connections —
// in practice, one imported capture file (see ConnFilter.Iface's comment).
// liveIface is excluded so the live NIC (or "simulated") doesn't show up
// alongside genuine imports.
type ImportBatch struct {
	Iface string    `json:"iface"`
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
}

func (s *Store) ImportBatches(liveIface string) ([]ImportBatch, error) {
	rows, err := s.db.Query(
		`SELECT iface, COUNT(*), MAX(ts) FROM connections WHERE iface != '' AND iface != ? GROUP BY iface ORDER BY MAX(ts) DESC LIMIT 50`,
		liveIface)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImportBatch
	for rows.Next() {
		var b ImportBatch
		var last int64
		if err := rows.Scan(&b.Iface, &b.Count, &last); err != nil {
			return nil, err
		}
		b.Last = time.Unix(last, 0)
		out = append(out, b)
	}
	return out, rows.Err()
}

func scanConns(rows *sql.Rows) ([]model.Connection, error) {
	var out []model.Connection
	for rows.Next() {
		var c model.Connection
		var ts int64
		var internal int
		if err := rows.Scan(&c.ID, &ts, &c.MAC, &c.SrcIP, &c.SrcPort, &c.DstIP, &c.DstPort,
			&c.Proto, &c.AppProtocol, &c.Service, &c.Bytes, &c.TxBytes, &c.RxBytes, &c.Packets, &c.Iface, &c.SNI, &c.JA3, &internal); err != nil {
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
	_, err := s.db.Exec(`INSERT INTO dns_records (ts,mac,domain,resolved_ips,ttl,rcode,encrypted,iface)
        VALUES (?,?,?,?,?,?,?,?)`,
		r.TS.Unix(), r.MAC, r.Domain, string(ips), r.TTL, r.RCode, b2i(r.Encrypted), r.Iface)
	return err
}

// DNSRecords lists DNS records, most recent first. mac (exact match) and
// iface (exact match against an imported file's own name, same convention as
// ConnFilter.Iface) each narrow the result when non-empty; "" for either
// means "any". A detection pass over the full history — main.go's flush,
// which must see every record regardless of which capture it came from —
// passes both empty.
func (s *Store) DNSRecords(mac string, limit int) ([]model.DNSRecord, error) {
	return s.dnsRecords(mac, "", limit)
}

// DNSRecordsForIface is DNSRecords scoped to one imported batch (F-import-visible,
// same reasoning as Connections' Iface filter) — the DNS view otherwise buries
// an imported capture's own records under whatever live traffic keeps arriving.
func (s *Store) DNSRecordsForIface(mac, iface string, limit int) ([]model.DNSRecord, error) {
	return s.dnsRecords(mac, iface, limit)
}

func (s *Store) dnsRecords(mac, iface string, limit int) ([]model.DNSRecord, error) {
	if limit <= 0 {
		limit = 500
	}
	q := `SELECT id,ts,mac,domain,resolved_ips,ttl,rcode,encrypted,iface FROM dns_records WHERE 1=1`
	args := []any{}
	if mac != "" {
		q += ` AND mac=?`
		args = append(args, mac)
	}
	if iface != "" {
		q += ` AND iface=?`
		args = append(args, iface)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
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
		var ifaceVal sql.NullString
		if err := rows.Scan(&r.ID, &ts, &r.MAC, &r.Domain, &ips, &r.TTL, &r.RCode, &enc, &ifaceVal); err != nil {
			return nil, err
		}
		r.TS = time.Unix(ts, 0)
		_ = json.Unmarshal([]byte(ips), &r.ResolvedIPs)
		r.Encrypted = enc == 1
		r.Iface = ifaceVal.String
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
