# BeeEye — Home IoT Gateway Traffic Analysis System — Requirements & Technical Design

Version: v1.1
Date: 2026-08-19

---

## 1. Background

Home networks now host an increasingly diverse set of devices (TVs, cameras, NAS, routers, door locks, phones, refrigerators, etc.), often numbering from dozens to over a hundred. Security posture varies widely across these devices — privacy-sensitive devices such as door locks and cameras carry far higher risk than ordinary entertainment devices if compromised or communicating abnormally.

The project name **BeeEye (蜂眼)**: "Bee" echoes eBPF's technical character and the distributed, densely-instrumented, multi-NIC nature of the collection layer; "Eye" corresponds to the system's visualization insight into whole-network traffic and its anomaly-detection capability.

Existing home routers / soft-routers lack deep visibility and anomaly detection at the per-device traffic level. This project (codename "BeeEye") aims to use an **Ubuntu gateway host + eBPF technology** to capture, fingerprint, behaviorally model, and alert on traffic from all connected devices — without changing the home network topology.

---

## 2. Product Requirements Document (PRD)

### 2.1 Project Goals

Deploy a traffic-analysis system on an Ubuntu soft-router host to:

1. Identify every device joining the home network (type, vendor, inferred model)
2. Apply tiered monitoring by device type, with special focus on high-sensitivity devices such as door locks and cameras
3. Extract as much metadata as possible for anomaly detection without decrypting TLS content
4. Provide a web visualization UI accessible from Mac/Windows/mobile browsers
5. Keep resource usage bounded so the gateway's own routing/forwarding performance is unaffected

### 2.2 Scope and Boundaries

**Applicable scenarios**:
- The user has full administrative control over the home network and its devices
- The gateway runs Ubuntu (or another modern Linux distro), kernel ≥ 5.8 (BTF/CO-RE/ringbuf support)
- Tens to over a hundred devices on the home LAN

**Explicitly out of scope**:
- No collection agent deployed on Mac/Windows/IoT endpoints themselves
- No fine-grained tracking of guest devices without notice (anonymous aggregate stats only)
- No uploading of camera video content, door-lock unlock records, or other sensitive data to any third-party cloud service

**Optional capabilities** (see F14/F15 in §2.4 and §3.10):
- TLS/DTLS application-layer content decryption
- Active MITM (man-in-the-middle) proxying

Both are disabled by default and only take effect when explicitly enabled by the user, and only for devices the user personally administers (their own Mac/Windows/phone where a custom CA certificate can be installed). They are naturally inapplicable to IoT devices with certificate pinning (door locks, cameras, etc.) and are not designed as general-purpose capabilities.

### 2.3 User Roles

| Role | Description |
|---|---|
| Home network administrator (owner) | System deployment, rule configuration, alert handling |
| Other household members | View device traffic overview via Web UI only; no configuration rights |

### 2.4 Functional Requirements

#### Must-have (P0)

| ID | Feature | Description |
|---|---|---|
| F1 | Device discovery & identification | Identify device type/vendor via MAC OUI, DHCP fingerprint, mDNS/SSDP broadcasts |
| F2 | Connection-level traffic statistics | Per-device byte counts, connection counts, active periods |
| F3 | TLS handshake extraction | Extract SNI and JA3 fingerprint from ClientHello (no decryption) |
| F4 | Plaintext protocol parsing | Fully parse MQTT/CoAP/HTTP/SSDP/mDNS and other plaintext protocols |
| F5 | Tiered device monitoring | Full connection-event logging for locks/cameras; sampled stats for others |
| F6 | Anomaly detection rule engine | JA3 blocklist matching, off-hours outbound, unfamiliar IP/port alerts |
| F7 | Web visualization UI | Device list, traffic trends, alert timeline |
| F8 | New-device alert | Alert on first appearance of an unregistered MAC |
| F16 | Configurable multi-NIC capture | Capture on any interface (wlan0/eth0/custom names) via config file; multiple interfaces in parallel; no hardcoded NIC names |
| F17 | Source-interface tagging | Every traffic record tagged with source ifindex/interface name, distinguishing wireless vs. wired access |
| F18 | Web UI zh/en switching | UI text supports Chinese/English, with a switcher that remembers the user's choice |
| F19 | Web UI multi-theme | At least 6 selectable color themes, switchable live and persisted |
| F21 | DNS query logging & domain mapping | Log each device's DNS queries (domain, resolved IP, timestamp); build a domain↔IP↔device association |
| F22 | Server IP geolocation | Offline GeoIP lookup on target IPs; annotate country/region/city to spot unusual geography |
| F23 | Protocol identification & display | Identify/display application-layer protocol (HTTP/HTTPS/MQTT/CoAP/DNS/SSH, etc.); distinguish transport protocol (TCP/UDP) |
| F24 | Port-to-service mapping | Show src/dst ports and map well-known ports to readable names (e.g. 443→HTTPS, 1883→MQTT) |
| F25 | Per-IP view | Aggregated view keyed by target/source IP, showing associated domains, geolocation, involved devices, traffic trend |
| F26 | Per-protocol view | Aggregated view keyed by application protocol, showing traffic share, involved devices, target distribution |
| F34 | East-west (intranet) traffic monitoring | Capture and log intranet device-to-device traffic (not just outbound), to detect lateral scanning/attacks after a device is compromised |
| F35 | Beacon (C2 heartbeat) detection | Detect suspected periodic C2 callback based on regularity of connection intervals |
| F36 | Fan-out / scan detection | Detect port scanning / DDoS-participation based on unique target IP/port counts in a sliding window |
| F40 | Real-time capture & analysis GUI | A Wireshark-style three-pane live analyzer, separate from the Web overview UI: packet list / protocol field tree / hex dump, with start-stop capture, interface selection and live refresh |
| F41 | Display-filter expressions | Wireshark-compatible display-filter syntax (field comparison `==`/`!=`/`>`/`<`, logical `&&`/`\|\|`/`!`, parentheses, `contains`, `matches` regexp, CIDR matching, bare protocol-name presence tests), with immediate syntax feedback rather than silent failure |
| F42 | Isolation between the two UIs | The live analyzer and the Web overview UI must be separate processes on separate ports with separate frontend bundles and no shared database connection; a crash, restart or upgrade on either side must not affect the other |
| F43 | Capture-source fallback, honestly labeled | The capture source is selected and degraded automatically in the order eBPF ringbuf → AF_PACKET; the source actually in effect must be labeled in the UI, and when neither is available the UI reports "no data" outright — there is no synthetic-data fallback to present as a real capture (removed entirely 2026-08-21) |

#### Should-have (P1)

| ID | Feature | Description |
|---|---|---|
| F9 | Lock/camera outbound whitelist | eBPF/XDP-based restriction so high-sensitivity devices reach only vendor-official domains |
| F10 | Device behavior baselining | Build a normal-behavior profile from history; alert on deviation |
| F11 | On-demand fine-grained capture | Trigger full PCAP capture for a matching 5-tuple, for post-hoc forensics |
| F20 | Hot-plug interface auto-discovery | Listen for interface add/remove events (e.g. USB Wi-Fi dongle) and auto-attach/detach without restarting |
| F27 | Top-N traffic ranking | Rank by device/domain/IP/country to quickly spot outliers |
| F28 | Unusual-geolocation alert | Alert when a device first reaches an IP outside configured regions, or many countries in a short time |
| F29 | Domain/IP threat-intel matching | Compare targets against public blocklists (malicious domains/C2 IPs); local offline cache supported |
| F30 | Multi-dimension search | Filter historical records by any combination of device/IP/domain/protocol/port/time range |
| F37 | Multi-signal weighted scoring | Combine multiple weak signals (first target, geo anomaly, beacon features, etc.) into a weighted risk score to reduce single-rule false positives |
| F38 | Automated high-risk response | On high-confidence intrusion signals, auto-trigger F9 whitelist/XDP block isolation; configurable as alert-only |
| F44 | PCAP export | The live analyzer can export the current (filtered) packet set as a standard pcap file for offline deep analysis and forensics in Wireshark/tshark |

#### Optional (P2)

| ID | Feature | Description |
|---|---|---|
| F12 | Traffic classification model | Classify traffic type from packet-length sequences/timing (e.g. heartbeat vs. upload) |
| F13 | Mobile push alerts | Push notifications (e.g. ntfy/Bark) for high-risk events |
| F14 | Passive TLS session-key capture | Own-managed endpoints only (Mac/Win/phone); via SSLKEYLOGFILE export, decrypt offline for analysis |
| F15 | Active MITM proxy | For explicitly enabled own devices: transparent proxy decrypts and inspects plaintext; off by default, requires per-device opt-in and custom CA install |
| F31 | Record export | Export filtered records as CSV/JSON for offline analysis/archival |
| F32 | Geographic map visualization | Heatmap/connection-line visualization of a device's outbound geographic distribution |
| F33 | DNS anomaly detection | Detect high-frequency NXDOMAIN (suspected DGA), DNS tunneling signatures (abnormally large/frequent TXT queries) |
| F39 | Malware-download signature detection | Flag suspicious filenames in plaintext downloads (e.g. `.elf`/arch suffixes) and abnormal one-way large downloads, covering common Mirai-style IoT botnet delivery |

> F14/F15 apply only to devices the user personally administers and can install a custom certificate / set environment variables on. For lock/camera-class embedded IoT devices using certificate pinning, neither feature applies — the device will simply reject the connection — so the system should fall back to metadata analysis (F1–F8).

### 2.5 Non-Functional Requirements

| Category | Requirement |
|---|---|
| Performance | Under gigabit LAN traffic, eBPF capture adds no perceptible forwarding latency (target < 1ms added latency) |
| Resource usage | System-wide resident memory < 512MB (excluding the OS itself), CPU < 10% (4-core platform) |
| Reliability | Analysis component crashes must not affect gateway routing/forwarding (capture decoupled from forwarding) |
| Maintainability | One-command deploy/rollback via Docker Compose |
| Privacy & security | High-sensitivity device (lock/camera) event logs stored locally only, never uploaded to any third-party cloud |
| Cross-platform access | Web UI must render correctly on Mac/Windows/iOS/Android mainstream browsers |
| Topology adaptability | Support both NAT mode (Wi-Fi on its own subnet) and bridged mode (Wi-Fi/wired on the same subnet); capture interfaces not hardcoded |
| Internationalization | All Web UI text (chart labels, alert descriptions included) covered in both zh/en, no untranslated strings |
| Geolocation privacy | IP geolocation uses a local offline database; individual target IPs are never sent to a third-party online lookup service |

---

## 3. Technical Design

### 3.1 Overall Architecture

```
┌──────────────────────┐   ┌──────────────────────┐
│ Presentation A:       │   │ Presentation B:       │
│ custom Web overview   │   │ live analyzer GUI     │
│ BeeEye-web  :8080     │   │ BeeEye-gui  :8081     │
│ devices/alerts/views  │   │ Wireshark three-pane  │
│ (everyday entry point)│   │ (admin deep-dive)     │
└──────────┬───────────┘   └───────────┬──────────┘
           │ REST                      │ SSE + REST
┌──────────┴───────────┐   ┌───────────┴──────────┐
│ Process A: BeeEye-agent│  │ Process B: BeeEye-gui │
│ storage+detection+API │   │ live capture+dissect  │
└──────────┬───────────┘   └───────────┬──────────┘
   The two processes share only compile-time internal packages
┌──────────┴───────────────────────────┴──────────┐
│  Presentation (optional): Grafana, raw metrics    │
├─────────────────────────────────────────────────┤
│  Storage: InfluxDB (metrics) + SQLite (events/assets) │
├─────────────────────────────────────────────────┤
│  Analysis: Rule engine + device fingerprinting +  │
│            behavior baseline (Go/Py)              │
├─────────────────────────────────────────────────┤
│  Agent: libbpf+CO-RE userspace program             │
│         (Go, cilium/ebpf)                          │
├─────────────────────────────────────────────────┤
│  Capture: eBPF programs (TC/XDP, attached on LAN)  │
├─────────────────────────────────────────────────┤
│  Ubuntu kernel (≥5.8, BTF required)                │
└─────────────────────────────────────────────────┘
```

Deployment form: a single Ubuntu Server host (x86 mini PC / NUC class), with all components except the eBPF kernel-program attachment point deployed via Docker Compose.

### 3.2 Key Technology Choices

| Component | Choice | Rationale |
|---|---|---|
| eBPF dev framework | libbpf + CO-RE | Portable across kernel versions, no per-kernel recompilation |
| Userspace language | Go (cilium/ebpf library) | Mature ecosystem; ringbuf reading and map ops are well-wrapped, easy to feed into storage |
| Attach point | TC (ingress/egress, on LAN/br-lan) | Sufficient performance for home bandwidth; easier full skb context access than XDP |
| Active blocking (P1) | XDP | Needed for millisecond-level drop response (e.g. lock whitelist enforcement) |
| Event transport | BPF_MAP_TYPE_RINGBUF | Recommended for kernel 5.8+, lower overhead than perf event array |
| Metrics storage | InfluxDB (single-node) | Time-series data; single-node is sufficient at home scale, native Grafana support |
| Event/asset storage | SQLite | Lightweight, no extra service, fits home-scale structured data |
| Primary dashboard (device overview/alerts/config) | Custom Web frontend (React + i18next + Ant Design/custom components) | Grafana natively only offers light/dark themes and no consumer-friendly one-click zh/en switch, so it can't satisfy F18/F19 (6 themes + bilingual switch); the primary UI is therefore custom-built, reading InfluxDB/SQLite via REST API |
| Secondary dashboard (deep metric drill-down, optional) | Grafana | For advanced users/admins to freely drill into raw metrics; not the primary entry point for household members |
| Live analyzer GUI (F40) | Separate Go process, separate port, separate frontend bundle | Fully isolated from the Web overview UI (F42); a headless gateway has no desktop session, so an Electron/native window could not run on the gateway itself, whereas a browser-served UI is reachable from Mac/Windows/phone directly |
| GUI live streaming | Server-Sent Events (SSE) | The packet stream is one-way server→client; SSE needs only the standard library, reconnects automatically, and avoids a WebSocket dependency and upgrade handshake |
| GUI capture source | AF_PACKET raw socket (no CGO) | Avoids the CGO dependency of gopacket+libpcap, keeping static linking and a small image; captures for real given CAP_NET_RAW, otherwise fails outright — no synthetic-data fallback (F43) |
| Display filter (F41) | Hand-written lexer + recursive-descent parser | Syntax matches the muscle memory Wireshark users already have, zero dependencies, and expressions can be syntax-checked as they are typed |
| Deployment | Docker Compose | Simplified deployment and version management; the eBPF Agent container needs host network mode |

### 3.3 Data Flow

```
NIC (LAN port) → TC eBPF program (kernel-space filtering + feature extraction)
              → ringbuf (kernel→userspace event channel)
              → Go Agent:
                  ├─ Device identity association (MAC → asset-DB lookup/update)
                  ├─ JA3/JA3S fingerprint computation
                  ├─ Plaintext protocol parsing (MQTT/mDNS/SSDP/HTTP)
                  ├─ Rule-engine matching (blocklist / anomalous behavior)
                  └─ Output:
                      ├─ Metrics → InfluxDB
                      ├─ Events/alerts → SQLite
                      └─ (on demand) PCAP → local filesystem
              → Grafana reads InfluxDB/SQLite to render dashboards
```

### 3.4 Kernel-Space (eBPF) Design

#### 3.4.1 Attach Points

| Attach point | Purpose |
|---|---|
| TC ingress/egress @ LAN interface | Primary capture: 5-tuple stats, packet-length distribution, TLS ClientHello parsing |
| XDP @ LAN interface (when P1 feature enabled) | Lock/camera whitelist enforcement (drop) |

> Key requirement: attach on the **LAN-side interface** (e.g. `br-lan`), not the WAN interface, to preserve devices' real internal IP/MAC and avoid losing per-device granularity after NAT.

#### 3.4.2 Core Data Structures (illustrative)

```c
// Per-device MAC aggregate stats table
struct device_key {
    __u8 mac[6];
};

struct device_stat {
    __u64 tx_bytes, rx_bytes;
    __u64 conn_count;
    __u32 last_seen;
    __u8  category;   // 0=unknown 1=camera 2=lock 3=nas 4=tv ... (written back from userspace)
};

// Connection-level flow table (LRU, to bound growth)
struct flow_key {
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8  proto;
};

struct flow_stat {
    __u64 pkts, bytes;
    __u64 first_ts, last_ts;
    __u16 pkt_len_hist[16];
    __u8  tls_sni[64];
    __u8  is_tls;
};
```

- The `device_key → category` mapping is written back from userspace after identification; kernel-space then uses it to decide the reporting policy for that traffic (full report vs. sampled), pushing "tiered monitoring" down into kernel space to reduce userspace processing load.
- The flow table uses `BPF_MAP_TYPE_LRU_HASH` to prevent unbounded memory growth as connection count increases.

#### 3.4.3 TLS ClientHello Parsing

Exploiting the fact that the first handshake packet is plaintext, the TC program locates the TCP payload, validates the TLS Record Header and Handshake Type, and extracts:
- SNI extension (plaintext domain)
- Cipher Suites list and extension-type list (used by userspace to compute the JA3 fingerprint)

String concatenation and MD5 computation are not done in kernel space (eBPF verifier restrictions) — only raw fields are extracted; fingerprint computation is left to the userspace Go Agent.

#### 3.4.4 Event Reporting Strategy

To bound throughput and overhead:
- Handshake-stage packets (highest information density) → reported in full
- Ordinary data packets → aggregated per connection and reported periodically in batch (e.g. one stats snapshot every 5 seconds), not packet-by-packet
- Lock/camera devices (category already tagged) → full connection-event logging
- Other devices → sampled/aggregated reporting

#### 3.4.5 Configurable Multi-NIC Capture Design

Home networks typically use two topologies, with different capture-interface choices:

| Topology | Description | Recommended capture interface |
|---|---|---|
| NAT mode | Wi-Fi (e.g. `wlan0`) and uplink (e.g. `eth0`) are different subnets; the host does NAT | Attach `wlan0` (LAN side) to get devices' real IP/MAC; attaching only `eth0` is not recommended — per-device granularity is lost after NAT |
| Bridged mode | `wlan0` and `eth0` bridged into one subnet (e.g. `br0`) | Attach each physical interface (`wlan0`/`eth0`) rather than the bridge `br0`, to preserve "which physical interface" info; if only total traffic is needed, attach only `br0` instead — the two should never be attached simultaneously, to avoid double-counting the same packet |

**Interface attachment is never hardcoded to specific NIC names** — it is declared via config file, supporting arbitrary interface names (including irregular USB NIC names like `wlx*`):

```yaml
# config.yaml
interfaces:
  mode: explicit            # explicit or auto (auto-discover)
  explicit_list:
    - name: wlan0
      role: wifi_ap          # role tag, drives downstream tiered-monitoring policy
    - name: eth0
      role: wan_uplink
  auto_discover:
    exclude_patterns:        # excluded interfaces in auto mode, avoids attaching virtual NICs by mistake
      - "lo"
      - "docker*"
      - "veth*"
      - "br-*"
```

At startup, the userspace Agent attaches to each configured interface in turn; if a given interface doesn't exist or attach fails, only a log entry is recorded and that interface is skipped — it does not affect capture on the rest. In `auto` mode, `netlink` is used to listen for interface add/remove events, enabling automatic attach/detach on hot-plug (e.g. plugging/unplugging a USB Wi-Fi NIC), corresponding to F20.

**A single eBPF bytecode object is attached to multiple interfaces** — no need to compile separately per interface:

```go
for _, ifcfg := range cfg.Interfaces {
    iface, err := net.InterfaceByName(ifcfg.Name)
    if err != nil {
        log.Printf("interface %s does not exist, skipping: %v", ifcfg.Name, err)
        continue
    }
    l, err := link.AttachTCX(link.TCXOptions{
        Program:   bpfObjs.TcIngress,
        Attach:    ebpf.AttachTCXIngress,
        Interface: iface.Index,
    })
    if err != nil {
        log.Printf("attach to %s failed: %v", ifcfg.Name, err)
        continue
    }
    ifindexToRole[iface.Index] = ifcfg.Role   // maintain ifindex→role mapping for userspace/UI
    defer l.Close()
}
```

**The kernel-space `flow_key` carries the source-interface info**, so a single flow table can distinguish multi-NIC sources without needing a separate map per interface:

```c
struct flow_key {
    __u32 ifindex;      // source interface index; TC reads skb->ifindex, XDP reads ctx->ingress_ifindex
    __u32 saddr, daddr;
    __u16 sport, dport;
    __u8  proto;
};
```

Userspace uses the `ifindex → role` mapping to decide display grouping and tiered-monitoring policy for that interface's traffic (e.g. `wifi_ap` role gets "device-level" fine monitoring, `wan_uplink` role only gets aggregate stats), and annotates "access type: wireless/wired" in the device-detail Web UI.

#### 3.4.6 DNS Query Parsing (corresponds to F21)

DNS queries/responses default to plaintext UDP port 53 (unless the device uses DoH/DoT — see below), and content can be parsed directly at the TC attach point, with no decryption involved:

- In the TC ingress/egress program, for UDP packets with source/destination port 53, parse the DNS message: extract the queried domain (Question section), the A/AAAA records in the response (resolved IP), TTL, and the querying device's MAC.
- Build a **domain ↔ IP ↔ device** three-way association table — the data foundation for the "which domain does this IP correspond to" capability in the later "by-IP view" / "by-protocol view". Sniffing TLS traffic alone only yields the SNI from ClientHello — DNS records fill the gap of "what domains a device has actually queried, even for connections that later use no SNI or ECH."
- **DoH/DoT limitation note**: if a device uses DNS over HTTPS (e.g. reaching `1.1.1.1`/`8.8.8.8` port 443 for DoH) or DNS over TLS (port 853), the query content itself is encrypted and eBPF cannot parse out the specific domain queried. In this case the system degrades to a metadata-level detection of "this device appears to be using a DoH/DoT service" (based on target IP+port matching known DoH/DoT providers), without attempting decryption. This limitation must be clearly surfaced in the Web UI rather than silently showing incomplete data.

Illustrative data structure:

```c
struct dns_record {
    __u8  client_mac[6];
    __u32 query_ts;
    char  domain[128];      // fixed-size buffer; eBPF verifier requires explicit bounds
    __u32 resolved_ips[8];  // one response may contain multiple A records
    __u8  resolved_count;
};
```

### 3.5 Userspace Agent Design

#### 3.5.1 Module Breakdown

```
┌──────────────────────────────────────┐
│ Ringbuf Reader                         │  reads kernel events
├──────────────────────────────────────┤
│ Device Identity Engine                 │  MAC→device-type identification & asset-DB maintenance
├──────────────────────────────────────┤
│ Fingerprint Engine                     │  JA3/JA3S computation & block/allow-list matching
├──────────────────────────────────────┤
│ DNS Resolver Tracker                   │  domain↔IP↔device association maintenance
├──────────────────────────────────────┤
│ Protocol Identifier                    │  application-layer protocol ID (port + light DPI + ALPN)
├──────────────────────────────────────┤
│ GeoIP Enrichment                       │  offline target-IP geolocation
├──────────────────────────────────────┤
│ Plaintext Protocol Parser              │  MQTT/CoAP/HTTP/mDNS/SSDP parsing
├──────────────────────────────────────┤
│ Rule Engine                            │  anomaly-detection rule matching (incl. threat-intel comparison)
├──────────────────────────────────────┤
│ Storage Exporter                       │  writes to InfluxDB/SQLite
└──────────────────────────────────────┘
```

#### 3.5.2 Device Identity Workflow

1. New MAC appears → trigger passive fingerprint collection (DHCP Option 55/60, mDNS/SSDP broadcasts, MAC OUI prefix)
2. Match against an open-source fingerprint dataset (e.g. Fingerbank) for an initial device-type guess
3. Write to the local asset DB (SQLite `device_registry` table), including: MAC, vendor, inferred model, category, first-seen time, current category tag
4. Write the category tag back into the eBPF `device_key → category` map, driving kernel-space tiered processing

#### 3.5.3 Tiered Monitoring Policy

| Device category | Monitoring granularity | Special policy |
|---|---|---|
| Door lock | Full connection-event logging | Outbound whitelist (P1), off-hours alert |
| Camera | Full connection-event logging | Outbound whitelist (P1), abnormal-upload alert (e.g. large outbound traffic at 3am) |
| NAS | Medium: login attempts, inbound connections, abnormal large traffic | Watch for ransomware encryption signatures (short-burst mass file-write traffic patterns, combined with host logs) |
| Router itself | Medium: management-interface access monitoring | — |
| TV/fridge/cloud-service devices | Low: basic traffic stats + baseline alert | No fine fingerprinting, to avoid false positives |
| Phone/computer (incl. Mac/Win) | Low: basic traffic stats | General-purpose computing devices have complex traffic patterns; only anomalous-outbound detection, no deep profiling |

#### 3.5.4 Protocol Identification Engine (corresponds to F23)

Application-layer protocol identification does not rely on a single signal; it applies a priority-ordered combination. If identification fails, it is explicitly labeled "unknown (transport/port only)" rather than guessed without basis:

| Priority | Basis | Applicable scenario |
|---|---|---|
| 1 | Direct hit from plaintext protocol parsing (e.g. successfully parsed an MQTT CONNECT packet) | MQTT/CoAP/HTTP/SSDP/mDNS and other protocols with implemented parsers |
| 2 | TLS ClientHello's **ALPN extension** (Application-Layer Protocol Negotiation) | Identifies HTTP/2 (`h2`), HTTP/1.1 (`http/1.1`), etc. — available without decryption, part of the handshake plaintext along with SNI |
| 3 | Known-port mapping table | Port 443→HTTPS, 8883→MQTT over TLS, 22→SSH, 53→DNS, etc., as the fallback when neither of the above hits |
| 4 | Packet-length/timing heuristics (optional, P2 scope, corresponds to F12) | For private protocols unidentifiable by the first three; only coarse classification ("suspected heartbeat," "suspected streaming"), explicitly labeled as a heuristic guess, not a firm conclusion |

The port→service-name mapping is kept as a configurable local table (not hardcoded), so users can extend it with their own network's vendor-private ports:

```yaml
# port-service-map.yaml
443: HTTPS
8883: MQTT-TLS
1883: MQTT
5683: CoAP
53: DNS
22: SSH
80: HTTP
```

#### 3.5.5 GeoIP Geolocation Lookup (corresponds to F22)

- Uses a **local offline GeoIP database** (e.g. MaxMind GeoLite2 or an equivalent open-source alternative), updated incrementally on a schedule (e.g. weekly); lookups happen entirely on-device, with no online third-party API call per visited target IP — avoiding indirectly exposing a household's browsing records to an external geolocation lookup service.
- Lookup results (country/region/city/lat-lon) are cached locally keyed by target IP (TTL suggested 7 days, since IP geolocation changes infrequently), to avoid repeated lookups consuming resources.
- Private address ranges (internal IPs, CGNAT ranges) are directly labeled "local/intranet" and skipped for geolocation lookup.

### 3.6 Storage Layer Design

| Data | Storage | Schema notes |
|---|---|---|
| Time-series metrics (traffic, connection counts) | InfluxDB | measurement bucketed by device category; tags include mac/category/protocol/ifindex, for aggregation by protocol/interface |
| Device asset DB | SQLite | `device_registry(mac, vendor, model_guess, category, first_seen, last_seen)` |
| Event/alert log | SQLite | `events(ts, mac, event_type, severity, detail_json)` |
| Connection-detail records | SQLite/ClickHouse (optional at large scale) | `connections(ts, mac, src_ip, src_port, dst_ip, dst_port, proto, app_protocol, bytes, ifindex)` — the core data source for "by-IP view"/"by-protocol view" |
| DNS query records | SQLite | `dns_records(ts, mac, domain, resolved_ips, ttl)` — supports domain↔IP↔device association queries |
| GeoIP query cache | SQLite or in-memory cache (e.g. Redis/local LRU) | `geoip_cache(ip, country, region, city, lat, lon, cached_at)`; re-query the local offline DB after TTL expiry |
| Fine-grained capture samples (on demand) | Local filesystem (optionally encrypted) | Generated only on rule hit; periodic cleanup policy (e.g. retain 30 days) |

> `connections` is a new, pivotal table recording at "per-connection summary" granularity (not per-packet); its field design directly serves the display needs of F21–F26. At larger data volumes (hundreds of devices running for months) it can be evaluated for migration from SQLite to ClickHouse or DuckDB for better aggregate-query performance; migration does not affect the upper-layer API design.

#### 3.6.1 Web UI Multi-Dimension View Design (corresponds to F21–F26, F30)

Building on the device-dimension view (existing F7), two parallel aggregate-view entry points are added; all three share the same underlying `connections`/`dns_records` data, differing only in aggregation dimension.

**By-device view (existing)**: select a device → show all its communication records

**By-IP view (new, F25)**:
| Field | Description |
|---|---|
| Target/source IP | Supports both internal and external IPs |
| Associated domain | From DNS-record association; if no DNS record exists (e.g. device connects directly to a hardcoded IP), labeled "no DNS resolution record" |
| Geolocation | Country/region/city, shown on a small map thumbnail |
| Involved devices | Which local devices have accessed this IP (may be multiple devices sharing one cloud service) |
| Application protocol | Protocol type(s) identified in this IP's traffic |
| Port distribution | Ports accessed on this IP and their service names |
| Traffic trend | Historical traffic curve for this IP |

Sort/filter support: by traffic size, by first-seen time, by geolocation (e.g. quickly filter "non-mainland-China IPs").

**By-protocol view (new, F26)**:
| Field | Description |
|---|---|
| Protocol name | HTTPS/MQTT/CoAP/DNS/SSH, etc. |
| Traffic share | Pie/bar chart of traffic share per protocol |
| Device count | Number of devices communicating with this protocol |
| Target distribution | Top-N target domains/IPs for this protocol |
| Port distribution | Actual ports used by this protocol (non-standard port usage is a potential anomaly signal) |

**Multi-dimension search (F30)**: a unified filter panel supporting any combination of: device (multi-select) + IP/domain (fuzzy search) + protocol (multi-select) + port (range) + time range; filter results drive the "by-device / by-IP / by-protocol" views in sync, and support export (F31).

### 3.7 Docker Deployment

```yaml
version: "3.8"
services:
  BeeEye-agent:                 # BeeEye capture+analysis core (eBPF Agent)
    build: ./BeeEye-agent
    network_mode: host        # required: needs access to the host's real LAN NIC
    cap_add:
      - CAP_BPF                # kernel 5.8+ specific; narrower than CAP_SYS_ADMIN
      - CAP_NET_ADMIN
      - CAP_PERFMON
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug
      - /sys/fs/bpf:/sys/fs/bpf
      - ./data/sqlite:/data
    restart: unless-stopped

  BeeEye-influxdb:
    image: influxdb:2
    volumes:
      - influx-data:/var/lib/influxdb2
    restart: unless-stopped

  BeeEye-grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    depends_on: [BeeEye-influxdb]
    restart: unless-stopped

  BeeEye-gui:                   # BeeEye live analyzer (Wireshark three-pane, F40)
    build: ./BeeEye-agent        # same Go module as the agent, second binary
    command: ["/usr/local/bin/BeeEye-gui"]
    network_mode: host        # required: AF_PACKET needs the host's real NICs
    cap_add:
      - CAP_NET_RAW            # least privilege for capture; CAP_BPF not needed
      - CAP_NET_ADMIN          # promiscuous mode
    volumes:
      - ./BeeEye-gui/dist:/web:ro
    restart: unless-stopped
    # No depends_on against BeeEye-agent: the two are independent (F42), so a
    # restart or crash on either side leaves the other one running.

  BeeEye-web:                   # BeeEye primary frontend
    build: ./BeeEye-web          # React frontend + lightweight API service (reads InfluxDB/SQLite)
    ports:
      - "8080:8080"
    volumes:
      - ./data/sqlite:/data:ro
    depends_on: [BeeEye-influxdb]
    restart: unless-stopped

volumes:
  influx-data:
```

Notes:
- Only the `BeeEye-agent` container needs privileged configuration (host network + CAP_BPF, etc.); the other components run in ordinary isolated containers, easing security auditing and resource limiting.
- If the host kernel doesn't support fine-grained `CAP_BPF` (pre-5.8), fall back to `CAP_SYS_ADMIN`.
- The kernel must have BTF support (`/sys/kernel/btf/vmlinux` present) to enable CO-RE; current Ubuntu 20.04+ satisfies this by default.
- `BeeEye-web` (port 8080) is the default entry point for household members; `BeeEye-grafana` (port 3000) is an optional deep drill-down tool for admins; both share the same underlying data, with no duplicate collection.

### 3.8 Cross-Platform Strategy

| Need | Approach |
|---|---|
| Mac/Windows device monitoring | Covered uniformly as ordinary endpoints via the Ubuntu gateway's eBPF system, no component needed on the device itself |
| Mac/Windows viewing analysis results | Via browser access to the custom Web UI (default entry) or Grafana (deep drill-down) — naturally cross-platform |
| Mac/Windows ad-hoc capture while away from the home network (edge case) | Use built-in OS tools (macOS: tcpdump/Wireshark; Windows: npcap+Wireshark) to export PCAP, transfer back to the Ubuntu side for offline analysis with tshark/Zeek; not part of the regular system scope |

#### 3.8.1 Web UI Internationalization Design (F18)

- Frontend stack: **React + react-i18next** (or Vue + vue-i18n, per team familiarity). All UI text (navigation, buttons, table headers, chart axis labels, alert descriptions, rule-engine prompts) uniformly goes through i18n keys — no hardcoded Chinese/English strings allowed.
- Locale resource file structure:

```
locales/
  zh-CN/
    common.json      # common text (nav, buttons)
    device.json       # device-related text
    alert.json         # alert-related text
  en-US/
    common.json
    device.json
    alert.json
```

- Dynamic content returned by the backend (e.g. device category `category`, alert type `event_type`) is returned as an **enum key** (rather than a raw Chinese/English string); the frontend looks it up per the current locale and renders it, avoiding an inconsistent state after a language switch where "the table is in English but the alert description is still in Chinese." E.g. the backend returns `category: "camera"`, the frontend renders "摄像头" or "Camera".
- The language switcher lives in the top navigation bar; after switching, the choice is persisted via browser `localStorage` and auto-applied on next visit — no need to switch manually every time.
- Default language: auto-detected from the browser's `Accept-Language`; falls back to Chinese if detection fails (configurable).

#### 3.8.2 Web UI Multi-Theme Design (F19)

Provides **6 preset color themes**, implemented via CSS variables (design tokens), non-invasive to component logic — adding/adjusting a theme only requires editing the token file:

| Theme | Positioning | Primary color example |
|---|---|---|
| Minimal White (Light) | Default light, daytime use | White background + indigo primary |
| Deep Black (Dark) | Default dark, nighttime use | Dark gray background + cyan primary |
| Tech Blue | Emphasizes professionalism for data-viz scenarios | Deep blue background + neon-blue/teal accents |
| Warm Amber | Long screen-time use, reduces blue-light stimulation | Beige/warm-gray background + amber primary |
| Forest Green | Soft, low-distraction, suited to an always-on monitoring wall | Deep green background + light green/off-white accents |
| High Contrast (Accessible) | Readability optimization for low-vision/bright-light environments | Pure black background + high-saturation yellow text, meeting WCAG AA contrast |

Implementation notes:
- Each theme defines a set of CSS variables (background, text, primary, and status-color scale — success/warning/danger three levels must stay semantically consistent across all themes; "danger" must never look insufficiently prominent under any theme):

```css
:root[data-theme="tech-blue"] {
  --bg-primary: #0b1e3a;
  --bg-secondary: #142d52;
  --text-primary: #e6edf7;
  --accent-primary: #3ac6ff;
  --status-success: #2ecc71;
  --status-warning: #f5a623;
  --status-danger: #ff4d4f;
}
```

- The theme switcher sits in the top navigation bar alongside the language switcher; after switching, the preference is persisted to `localStorage`, with a "follow system" option available (reads `prefers-color-scheme`).
- Chart components (traffic-trend chart, alert timeline) must pull colors dynamically from the current theme's tokens — colors must never be hardcoded in chart-library config — ensuring charts update in sync with theme switches.
- The High-Contrast/Accessible theme requires additional verification that text-to-background contrast meets WCAG 2.1 AA (at least 4.5:1) as a hard acceptance criterion for that theme.

### 3.9 Security & Privacy Design Points

1. High-sensitivity device (lock/camera) event logs are stored locally only, never connected to any third-party cloud logging service.
2. The system performs no video-content analysis by default — only connection metadata (time, byte count, target address) is collected, avoiding creation of a new privacy risk.
3. Guest devices default to anonymous aggregate stats only, no individual behavioral profiling, unless the user explicitly configures otherwise.
4. The `BeeEye-agent` container's capabilities are narrowed to the minimum necessary set; `--privileged` is never used by default.
5. Fine-grained PCAP capture is off by default, enabled only briefly on rule hit, with an automatic cleanup cycle configured.

---

### 3.10 Optional Feature: TLS Decryption & Active MITM (F14/F15)

Disabled by default; designed as a pluggable extension module decoupled from the core metadata-analysis pipeline — enabling or disabling it does not affect the normal operation of F1–F8.

#### 3.10.1 Applicability Assessment

| Device type | Feasible? | Notes |
|---|---|---|
| Own Mac/Windows (browser/self-built app) | Feasible | Can control client environment variables or install a custom CA |
| Own Android phone | Partially feasible | Requires manually installing a user-level CA cert; Android 7+ apps don't trust user CAs by default unless the target app lacks a network-security-config restriction |
| Own iPhone | Partially feasible | Requires installing a configuration profile and manually enabling full trust in "Certificate Trust Settings"; more system-level restrictions |
| Lock, camera and other embedded IoT | Usually infeasible | Firmware has built-in certificate pinning, cannot install a custom CA; MITM causes connection failure |

#### 3.10.2 Approach A: Passive — SSLKEYLOGFILE Key Export

Principle: on a client process you control, set an environment variable at startup so the process writes each TLS session's key material to a specified file; the eBPF/gateway-side passively captured ciphertext traffic can then be decrypted offline using that file — no change to the network path is needed, making this a relatively gentle approach.

```bash
# On your own Mac/Linux terminal, before launching an app that supports this mechanism (e.g. a browser)
export SSLKEYLOGFILE=~/tls-keys.log
```

- Mainstream browsers (Chrome/Firefox) natively support this environment variable.
- The key file needs to be periodically synced to the gateway side (e.g. via a LAN shared folder), for use with `tshark -o tls.keylog_file:xxx` or Wireshark offline decryption.
- Limitation: only works for clients supporting this mechanism — most IoT firmware doesn't support it, nor do most homegrown/closed-source apps.

#### 3.10.3 Approach B: Active — Transparent MITM Proxy

Principle: the gateway DNATs a specific device's outbound 443/8883/etc. traffic to a local proxy process (e.g. `mitmproxy`); the proxy dynamically issues a certificate impersonating the target site, establishing two separate TLS sessions with the client and the real server respectively, thereby obtaining application-layer content in plaintext within the proxy process.

```
Target device → (DNAT to local gateway proxy) → mitmproxy → real server
                  ↑ device must trust the gateway's self-signed CA
```

Implementation notes:
- Use `iptables`/`nftables` (or eBPF `sk_msg`/`sockops` for transparent forwarding) to redirect traffic only for **explicitly, individually enabled** device MAC/IPs — global default-on is prohibited.
- `mitmproxy` runs as an independent container; decrypted content is used only for local rule matching and log summaries, with no full-body persistent storage by default (unless the user explicitly wants fine-grained forensics and accepts the privacy trade-off).
- The target device requires manual installation of the mitmproxy-generated CA root certificate — a step only possible on a Mac/Windows/phone you personally administer, which is what actually constrains this to "own controlled devices only" in practice.
- For target sites/apps with HSTS preloading or certificate pinning enabled (e.g. banking apps, some vendor apps), MITM will simply fail, which is expected and should not be force-bypassed.

#### 3.10.4 Risks & Usage Constraints

- Once MITM is enabled, confidentiality between that device and the target server is effectively replaced by the gateway — if the gateway itself is compromised, decrypted data carries a centralized-leak risk; whether this new attack surface is worth the analysis value must be weighed.
- Should only be enabled on devices you **personally and solely use, with full administrative control** — never silently enabled for other household members' devices, given the communication-privacy implications; users should be clearly informed and consent obtained before enabling.
- Decrypted plaintext content should, by default, be used only for **real-time rule matching and then immediately discarded** (e.g. detecting sensitive keywords/anomalous domains) — full-body persistent storage is not recommended by default; if storage is genuinely needed for post-hoc analysis, it should be encrypted with a short auto-expiry.

### 3.11 Post-Intrusion Anomalous Behavior Detection & Response (corresponds to F34–F39)

A compromised device's abnormal behavior typically progresses through three stages: "download backdoor → receive C2 instructions → attack outward." Since most traffic is TLS-encrypted, detection relies primarily on **behavioral side-channel time/spatial statistical features**, not on decrypted content. All detectors in this section are built on the `connections`/`dns_records` tables from §3.6, are a concrete extension of the rule-engine module (§3.5.1), and require no additional capture capability.

#### 3.11.1 Detector Overview

| Detector | Corresponding stage | Data dependency | Core logic |
|---|---|---|---|
| First-target detector | Delivery stage | `device_registry` baseline + new connection | Device's first-ever access to a never-before-seen IP/domain |
| Direct-IP detector | Delivery stage | `connections` vs `dns_records` | A TLS connection's target IP has no corresponding resolution in recent DNS records |
| Malicious-download signature detector (F39) | Delivery stage | Plaintext HTTP parse results | URI contains `.elf`/arch-suffix-like suspicious naming, or one-way large-volume download |
| Threat-intel matcher (existing F29) | Delivery/C2 stage | Target IP/domain/JA3 vs. blocklist | Hit against a public malware-intel database |
| Beacon detector (F35) | C2 stage | `connections` timestamp sequence | Statistical regularity of connection intervals |
| DNS anomaly detector (existing F33) | C2 stage | `dns_records` | High-frequency NXDOMAIN, high domain entropy (DGA signature) |
| Fan-out/scan detector (F36) | Attack stage | `connections` sliding-window aggregation | Unique target IP/port count exceeds threshold |
| Lateral-movement detector | Attack stage | `connections` where both src and dst are intranet | Device connects to another intranet device it has never communicated with before |
| Half-open-connection detector | Attack stage | TCP state (count of incomplete SYN handshakes) | Suspected outbound SYN flood |

#### 3.11.2 Beaconing Detection Algorithm

For each (device MAC, target IP) pair, maintain a sliding window (e.g. last 2 hours) of connection-initiation timestamps `t1, t2, ..., tn`:

```
1. Compute the inter-arrival sequence: Δt_i = t_i - t_{i-1}
2. Compute mean μ and standard deviation σ of the intervals
3. Compute coefficient of variation: CV = σ / μ
4. If all of the following hold, flag as a suspected beacon:
   - n ≥ N_min (e.g. connection count ≥ 6, to avoid unstable statistics from too few samples)
   - CV < CV_threshold (e.g. 0.15, i.e. interval variation is under 15% of the mean —
     the more mechanical, the closer CV gets to 0)
   - μ falls within a suspicious range (e.g. 10 seconds ~ 1 hour;
     too short may be normal keep-alive, too long has weak statistical significance)
```

- This algorithm is effective against fixed-interval-with-small-jitter beacons (common malware behavior); it has limited effect against fully adaptive-interval advanced C2 (which actively evades statistical signatures) and needs to be combined with other signals (see §3.11.5).
- A **whitelist exemption** is needed for common legitimate periodic behavior to avoid false positives: NTP sync, normal firmware/app heartbeat keep-alive (especially common on IoT devices), known official vendor domains' periodic update checks, etc. — these should be excluded by the rule engine with priority.

#### 3.11.3 Fan-out/Scan Detection Algorithm

For each device, maintain a sliding window (e.g. 1-minute and 5-minute tiers) tracking:

```
- unique_dst_ip_count: number of unique target IPs connected to within the window
- unique_dst_port_count (per single target IP): number of unique ports attempted against that IP within the window
```

Set differentiated thresholds by device category (to avoid a "one-size-fits-all" approach causing high false-positive or false-negative rates):

| Device category | 5-min unique-target-IP threshold | 5-min unique-port-per-target threshold |
|---|---|---|
| Lock/camera | > 5 triggers alert | > 3 triggers alert |
| NAS/router | > 20 triggers alert | > 10 triggers alert |
| TV/phone/computer | > 50 triggers alert (looser — multi-target concurrency is normal for general-purpose devices) | > 15 triggers alert |

Thresholds should be adjustable in the Web UI per device/category; initial values are only a default baseline — after the system has run for a while, they can be auto-calibrated in combination with F10 behavior baselining.

#### 3.11.4 East-West (Intranet) Traffic Monitoring (F34)

The design so far has defaulted to focusing only on "intranet device → external" traffic, but a compromised device attacking other intranet devices (e.g. a camera scanning a NAS) never crosses the gateway's WAN side, so it must be covered explicitly:

- **Capture-scope adjustment**: the multi-NIC attachment in §3.4.5 already naturally covers all bidirectional traffic on intranet interfaces (`wlan0`/`br0`), including intranet device-to-device traffic — no new attach point is needed; the userspace processing logic just needs to **stop filtering out connection records whose destination is an internal address** (easily mistaken as "internal traffic we don't care about" and discarded).
- **Baseline expectation**: most home IoT devices **shouldn't normally talk to each other** (a camera has no need to actively connect to a fridge), so intranet-to-intranet connections — especially ones initiated by a typically "dumb" device toward another device's management port (e.g. 22/23/80/445/3389) — carry relatively high-confidence signal and should be treated as medium-to-high priority alerts directly, without needing the complex statistical modeling used for external traffic.
- It's recommended to establish a default "allowed communication matrix" for the home intranet (e.g. a smart speaker connecting to the router's admin page is normal; a door lock should not connect to any other intranet device except the router itself) — any deviation from the matrix triggers an alert.

#### 3.11.5 Multi-Signal Weighted Scoring Model (F37)

A single rule hit is prone to false positives (e.g. a device visiting a never-before-seen domain very possibly just means the vendor pushed a firmware-update-server change), so a **weighted scoring** approach is recommended over single-rule triggering:

```
risk_score = Σ (signal_weight × signal_hit)

Example weight design:
  Direct threat-intel hit (domain/IP/JA3)         : weight 50 (single hit alone can determine high-risk)
  Intranet lateral-movement anomaly                 : weight 40
  Beacon signature hit                              : weight 25
  Fan-out/scan signature hit                        : weight 30
  DNS anomaly (DGA/tunneling signature)              : weight 20
  First-ever access to an unfamiliar target         : weight 10
  Unusual geolocation                               : weight 10
  Off-hours communication                           : weight 5
  JA3 fingerprint inconsistent with device history  : weight 15

Risk-level bands:
  score ≥ 50  → High (recommend auto-block, see §3.11.6)
  30 ≤ score < 50 → Medium (alert, manual confirmation)
  15 ≤ score < 30 → Low (log only, shown in Web UI, not actively pushed)
  score < 15  → no alert
```

Weights and thresholds should be configuration items, not hardcoded, so users can tune them to their own false-positive/false-negative tolerance; it's recommended to run initially in "log-only, no blocking" mode to observe, calibrate thresholds against accumulated data, and only then enable automated response.

#### 3.11.6 Automated High-Risk Response (F38)

```
High-risk event triggered (risk_score ≥ threshold)
        │
        ▼
  Is this a high-sensitivity device (lock/camera etc., see §3.5.3 tiering)?
        │                           │
      Yes                          No
        │                           │
        ▼                           ▼
 Auto-trigger XDP block (reuses the F9 outbound-      Alert only, push notification (F13),
  whitelist mechanism; temporarily bans all outbound   await manual confirmation before
  from this device except the router's admin port)     manual blocking
        │
        ▼
 Log the block event + a snapshot of the triggering reason
  (the specific rule that hit, related connection records)
  into the events table, for post-hoc review
```

- Auto-block is **off** by default; the user must explicitly enable it in the Web UI, and can configure whether auto-blocking is allowed per device/device-category, to avoid a device being unexpectedly disconnected due to a false positive (especially for devices like door locks, where being disconnected itself can introduce a usability risk that the user must weigh).
- A block action must have a clear **release mechanism** (one-click release in the Web UI + a configurable auto-release timeout, e.g. auto-restore network access after 30 minutes and resume observation), to avoid a false positive leaving a device disconnected long-term without the user noticing.
- All automated response actions must be fully audit-logged (who/which rule/when triggered the block), ensuring traceability.

### 3.12 Live Capture & Analysis GUI Design (corresponds to F40–F44)

#### 3.12.1 Why a second independent UI rather than a tab in the Web UI

The two interfaces serve genuinely different situations, and merging them would make both worse:

| | Web overview UI (BeeEye-web) | Live analyzer GUI (BeeEye-gui) |
|---|---|---|
| Audience | family members + admin | admin only |
| Time scale | aggregated trends over hours/days/weeks | millisecond-level per-packet sequence |
| Data source | historical records in SQLite/InfluxDB | frames flowing across the NIC right now |
| Interaction focus | understanding *what happened* | tracing *which exact byte* |
| Cost of failure | refresh the page | an interrupted capture loses the evidence permanently |

Hence the split into two processes required by F42:

- **Separate processes, separate ports**: `BeeEye-agent` listens on :8080, `BeeEye-gui` on :8081.
- **Separate frontend bundles**: `BeeEye-web/dist` and `BeeEye-gui/dist` build independently and reference nothing of each other.
- **No shared database connection**: the GUI never opens the agent's SQLite; live analysis happens entirely in memory, so no load on the GUI can slow the overview UI's queries, or vice versa.
- **Only compile-time sharing**: both import packages such as `internal/dissect` and `internal/geoip`. That is source-level reuse, not runtime coupling.

#### 3.12.2 Layout (three panes)

The classic Wireshark layout, so existing experience carries over:

```
┌ Toolbar: interface | ▶Start ■Stop | display filter | source label ┐
├──────────────────────────────────────────────────────────┤
│ Pane 1 packet list: No / Time / Source / Destination /    │
│         Protocol / Length / Info, colored per protocol,   │
│         auto-scrolling as packets arrive                  │
├────────────────────────────┬─────────────────────────────┤
│ Pane 2 protocol field tree │ Pane 3 hex dump             │
│ ▼ Ethernet II              │ 0000  3c 84 6a 11 00 02 ...  │
│ ▼ Internet Protocol v4     │ 0010  00 54 1a 2b 40 00 ...  │
│ ▼ Transmission Control     │                             │
│   ▼ TLS ClientHello        │ bytes of the selected field  │
│       SNI / ALPN / JA3     │ are highlighted             │
├────────────────────────────┴─────────────────────────────┤
│ Status bar: captured N / dropped M / displayed K / source │
└──────────────────────────────────────────────────────────┘
```

Key behavior: selecting any field in the tree highlights the corresponding byte range in pane 3. That requires the dissector to record `offset`/`length` for every field, not just its value.

#### 3.12.3 Capture-source priority and fallback (F43)

Two implementations sit behind one `live.Source` interface, selected automatically:

| Priority | Implementation | Prerequisite | Notes |
|---|---|---|---|
| 1 | eBPF ringbuf | kernel ≥5.8 + BTF + CAP_BPF | production path, shares the §3.4 kernel program with the agent |
| 2 | AF_PACKET raw socket | CAP_NET_RAW | current default; no CGO, no libpcap |

**No third-tier fallback since 2026-08-21**: when neither can be opened, `live.Open`/`capsource.Open` return an error outright — nothing is synthesized. **Honest labeling is mandatory**: the source actually in effect must be shown in the status bar (`ebpf`/`af_packet`/`unavailable`). A simulator used to exist here, producing structurally genuine Ethernet frames (they went through the same dissector) as a fallback — but they were still not traffic that really happened on that NIC, and presenting them as a real capture would be worse than showing nothing, which is why that fallback path was removed outright rather than merely kept labeled.

#### 3.12.4 Display-filter syntax (F41)

Deliberately a subset of Wireshark's, so people who already know Wireshark do not have to learn a second vocabulary:

```
tcp.port == 443 && !mdns
ip.addr == 192.168.1.0/24 and dns.qry.name contains "tuya"
tls.handshake.extensions_server_name matches "^ota\."
dns.flags.rcode == 3 || (tcp.flags.syn == 1 && tcp.flags.ack == 0)
```

Supported: `&&` `||` `!` (and `and` `or` `not`), parentheses, `==` `!=` `>` `<` `>=` `<=`, `contains`, `matches` (regexp), CIDR matching on address fields, and bare protocol names as presence tests.

**One deliberate divergence**: here `a != b` means "no value of a equals b". Wireshark's `!=` means "some value differs", which on a multi-valued field like `tcp.port` makes `tcp.port != 443` true for every packet (the other endpoint's port is never 443) — almost never what the user wanted. This implementation takes the intuitive reading; `!(a == b)` is equivalent.

#### 3.12.5 Consistency constraints against the Web overview UI

Although the two UIs run independently, three things must stay aligned, or the same traffic would support different conclusions in the two interfaces:

1. **Same protocol-identification rules**: both follow the §3.5.4 priority chain (plaintext parse > ALPN > port table > unknown). One must not show "HTTPS" while the other shows "TCP 443".
2. **Same field names**: the GUI's filter field names and the Web UI's search field names come from one vocabulary — `ip.addr` means the same thing on both sides.
3. **Same i18n policy**: UI chrome goes through i18n (F18), but protocol field names (`ip.src`, `tls.handshake.type`) stay untranslated technical identifiers — they are part of a filter syntax the user types, and translating them would make filters impossible to enter.

---

## 4. Milestones & Suggested Implementation Order

> Status vocabulary: **Done** = works and is covered by tests; **Partial** = the core path works but has a named gap; **In progress**; **Not started**.
> Per-requirement status (F1–F44) lives in [PROGRESS.en.md](PROGRESS.en.md), kept in sync with the code.

| Phase | Content | Goal | Status |
|---|---|---|---|
| M1 | Basic traffic visualization | Deploy InfluxDB+Grafana; use existing tools (ntopng etc.) to understand current devices and traffic patterns | Partial — carried by SQLite + a custom REST API instead; InfluxDB/Grafana not wired up |
| M2 | Lock/camera specialized monitoring | For high-risk device categories, implement eBPF capture + full event logging + basic alerting on its own | Partial — kernel-side tiered reporting implemented and verifier-clean; alert UI still to build |
| M3 | Full device-fingerprinting framework | Extend passive fingerprinting and tiered monitoring to all device types | Partial — OUI/hostname/DHCP 55·60/mDNS/SSDP collection in place; fingerprint database not integrated |
| M4 | DNS/GeoIP/protocol ID & multi-dim views | Implement domain mapping, geolocation tagging, protocol ID; deliver by-IP/by-protocol views and the custom Web UI (with i18n and multi-theme) | In progress — backend API complete, custom Web frontend still to build |
| M5 | Rule engine & behavior baseline | Complete the anomaly-detection rule library, introduce behavior baselining | Partial — rule engine implemented; behavior baselining not started |
| M6 | Post-intrusion anomaly detection | Implement beacon detection, fan-out detection, east-west monitoring, multi-signal weighted scoring | Done (backend) — all four detectors implemented with unit tests |
| M7 (optional) | Active protection capabilities | Lock/camera outbound whitelist, XDP active blocking, automated high-risk response | Not started |
| M8 | Live capture & analysis GUI | Deliver the separate-process Wireshark-style three-pane analyzer with display filters and PCAP export (F40–F44) | In progress — capture sources, dissector and filter engine done with tests; GUI server and frontend still to build |

---

## 5. Acceptance Criteria (example)

- [ ] System auto-discovers and identifies connected devices, correctly categorizing into predefined classes (covering at least: TV/camera/NAS/router/lock/phone/computer/other)
- [ ] All outbound connections from lock/camera devices are fully logged as events, queryable in the Web UI timeline
- [ ] A new device joining the network triggers an alert within 5 minutes
- [ ] Under peak gigabit LAN traffic, system-wide CPU usage < 10% (4-core platform baseline)
- [ ] Both the Web UI and Grafana dashboards render correctly on Mac/Windows/iOS/Android mainstream browsers
- [ ] An abnormal exit of the system does not affect the host's routing/forwarding function
- [ ] Any interface specified via config file (including non-standard names like `wlx*`) attaches for capture correctly, with 2+ interfaces working in parallel supported
- [ ] Traffic records correctly distinguish source interface (wireless vs. wired), with no double-counting across multiple interfaces
- [ ] After a Web UI zh/en switch, all UI text (chart labels, alert descriptions included) is correctly translated, with no leftover untranslated text
- [ ] Web UI offers one-click switching among 6 themes; chart colors update in sync after switching, and the preference persists (survives refresh/reopening the browser)
- [ ] The High-Contrast/Accessible theme's text-to-background contrast meets WCAG 2.1 AA (≥4.5:1)
- [ ] Plaintext DNS queries (UDP 53) correctly resolve the queried domain and resolved IP, correctly associated with the originating device
- [ ] For DoH/DoT scenarios, the system detects "this device is using encrypted DNS" and clearly indicates in the UI that query content is not visible, without showing incorrect or guessed data
- [ ] Target IP geolocation tagging accuracy matches the stated accuracy of the offline GeoIP database used; internal/CGNAT addresses are correctly labeled as local, with no fabricated geolocation produced
- [ ] Application-layer protocol identification covers at least: HTTP/HTTPS/MQTT/CoAP/DNS/SSH; unknown protocols are explicitly labeled "unknown" rather than left blank or erroring
- [ ] Both the by-IP view and by-protocol view aggregate and display correctly, and stay consistent with the by-device view's filter conditions when linked
- [ ] Multi-dimension search (device+IP+protocol+port+time) correctly returns records matching all conditions, with CSV/JSON export supported
- [ ] Intranet (east-west) device-to-device communication records are captured normally and queryable in the Web UI, not filtered out just because the destination is an internal address
- [ ] When simulating fixed-interval periodic callback traffic, the beacon detector correctly flags a suspected beacon within the configured minimum sample count, without false-positiving on known legitimate periodic behavior (e.g. NTP sync)
- [ ] When simulating short-burst connections to many target IPs/ports, the fan-out detector correctly triggers an alert using the category-differentiated thresholds
- [ ] The multi-signal weighted scoring model correctly computes the risk score and bands it into high/medium/low per the configured thresholds, with thresholds adjustable in config
- [ ] Automated high-risk response is off by default; once explicitly enabled, it correctly triggers device blocking, with block/release actions fully audit-logged and queryable
- [ ] The live analyzer and the Web overview UI run simultaneously on different ports, and stopping either process leaves the other fully usable
- [ ] The analyzer's packet list refreshes continuously while capturing; selecting a packet expands the full protocol field tree and highlights that field's bytes in the hex pane
- [ ] The display filter correctly parses and applies at least: field equality/magnitude comparison, `contains`, `matches` regexp, CIDR matching, logical combinations and parentheses; a syntax error produces a clear message and does not interrupt a running capture
- [ ] The active capture source (eBPF / AF_PACKET) is labeled honestly in the GUI status bar, and "no data" is reported honestly when neither is available — there is no synthetic source that could be mislabeled as a real capture
- [ ] Snaplen-truncated capture data never crashes the dissector; it shows as much as it could parse
- [ ] A TLS ClientHello yields SNI, ALPN and JA3 correctly, with JA3 stable across repeated handshakes from one client and different across differing cipher lists
- [ ] Exported pcap files open in Wireshark/tshark with identical packet contents
