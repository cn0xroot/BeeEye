# BeeEye — Implementation Progress

> Kept in sync with the code. Requirement IDs refer to [program.en.md](program.en.md) §2.4; section references point at the same document.
> Chinese version: [PROGRESS.md](PROGRESS.md) · Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)

**Last updated**: 2026-08-19

## Status vocabulary

| Mark | Meaning |
|---|---|
| ✅ Done | Works, and is covered by automated tests or verified on this machine |
| 🟡 Partial | The core path works, with the specific gap named in the "evidence / gap" column |
| 🔵 In progress | Being implemented, not yet usable |
| ⬜ Not started | No work done |

---

## 0. Data source: real capture is now wired in

**The agent now captures real traffic by default**, not the simulated scenario. `BeeEye-agent/main.go` uses `internal/livesource` — the same AF_PACKET capture the analyzer uses — and folds it into devices, connections, DNS records and alerts in SQLite.

| Process | Port | Data source | Real? |
|---|---|---|---|
| `BeeEye-agent` | :8080 | `internal/livesource` (AF_PACKET) | ✅ **real capture** |
| `BeeEye-gui` | :8081 | `internal/live` (AF_PACKET) | ✅ **real capture** |

So **the overview UI and the analyzer UI now describe the same real network** (this host's subnet, e.g. `192.168.x.x`); they agree.

**The fallback is still honest (F43)**: with no raw-capture permission (missing `CAP_NET_RAW`), or with `-simulate`, the agent falls back to the built-in simulated scenario and says so in the startup log (`SIMULATED traffic`) — it never passes simulated flows off as real.

**Interface selection (F16)**: `captureIface` tries, in order, a configured interface that exists, then the default-route NIC, then `any` — so the shipped `wlan0`/`eth0` that this host lacks resolve to the real NIC instead of silently dropping back to the simulator.

**On `internal/ebpf`**: that package (CO-RE TC program + ringbuf reader) still stands on its own with an attach test, but the current live capture goes through the AF_PACKET path (shared with the analyzer, reusing the tested dissect/aggregation chain) rather than the eBPF ring buffer. Both capture paths yield real traffic; wiring the eBPF ring buffer in as a lower-overhead source is a later optimisation.

---

## 1. Overall

| Layer | Status | Notes |
|---|---|---|
| Live capture | ✅ | Both the agent and the analyzer capture live via AF_PACKET (`internal/livesource` / `internal/live`). The eBPF CO-RE program stands on its own with an attach test, pending wiring in as a lower-overhead source |
| Userspace agent core | ✅ | Live capture → dissect → aggregate → detect → persist wired end to end (`internal/livesource`, 507 lines) |
| Dissector | ✅ | Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP + DNS/mDNS/TLS/HTTP/MQTT/SSDP/DHCP, in use end to end by the analyzer |
| Display-filter engine | ✅ | Wireshark-compatible subset including CIDR and regexp; the frontend's validation and the actual filtering share one parser |
| Storage | 🟡 | All SQLite tables in place and in use; InfluxDB time-series store not wired up |
| Detection engine | 🟡 | Nine weighted signals implemented and producing events; behaviour baselining not started |
| REST API | ✅ | Devices/connections/DNS/events/by-IP/by-protocol/top-N/time-series/export all ready, each checked by the smoke test |
| Web overview frontend | ✅ | Six views + bilingual + themes; verified showing the real network (this host's subnet, real devices/protocols/alerts) |
| Live analyzer GUI | ✅ | Three panes + display filter + colour field + pcap export, verified against a real capture |
| Deployment & local test environment | ✅ | `start.sh` one-command + `scripts/dev.sh` + `Makefile` + `docker-compose.yml` + `smoke.sh` (24/24 passing) |

---

## 2. Per-requirement status

### P0 — Must have

| ID | Feature | Status | Evidence / gap |
|---|---|---|---|
| F1 | Device discovery & identity | 🟡 | `internal/identity` infers from OUI + hostname; the kernel reports raw DHCP Option 55/60, mDNS and SSDP, and `internal/dissect/app.go` extracts the fingerprint fields. **Gap**: no Fingerbank-class database for model matching (under real capture most device OUIs miss, so category shows unknown) |
| F2 | Connection-level statistics | 🟡 | Kernel `flows` LRU table + periodic snapshots implemented; the `connections` table is persisted and populated from live capture |
| F3 | TLS handshake extraction | ✅ | SNI / ALPN / JA3 in `internal/dissect/app.go`, with JA3 stability under test; used end to end by the analyzer on real traffic |
| F4 | Plaintext protocol parsing | ✅ | MQTT / HTTP / SSDP / mDNS / DNS / DHCP implemented. **Gap**: CoAP is identified but not field-decoded |
| F5 | Tiered monitoring policy | 🟡 | Tiering pushed into the kernel: locks/cameras report per flow, everything else via aggregated snapshots. **Gap**: tiering lives in the eBPF path; the AF_PACKET path does not tier |
| F6 | Anomaly rule engine | ✅ | `internal/detect`: threat intel, beacon, fan-out, lateral, DNS anomaly, geo, off-hours — observed producing 38 risk events |
| F7 | Web visualization UI | ✅ | Overview / devices / connections / by-IP / by-protocol / DNS / alerts all usable; screenshotted page by page with zero page errors |
| F8 | New-device alert | 🟡 | Kernel emits `EVT_NEWDEV` the first time a MAC is seen; `device_registry.is_new` tracks acknowledgement and the UI has an Acknowledge button; new devices are recorded under live capture. The eBPF `EVT_NEWDEV` path stands on its own |
| F16 | Configurable multi-NIC capture | 🟡 | Interface names come entirely from `config/config.yaml`; one bytecode attached to many NICs. `captureIface` tries a configured interface, then the default-route NIC, then `any`, so a config that does not match the hardware still lands on the real NIC (F16 holds on the AF_PACKET path) |
| F17 | Source-interface tagging | 🟡 | connection and device rows carry the source interface name, in use under live capture; the eBPF `ifindex` path stands on its own |
| F18 | zh/en switching | ✅ | The backend returns enum keys only (category/event_type are never localized strings); both UIs ship `locales/zh-CN` and `en-US`, switched instantly from the header |
| F19 | Multi-theme colors | 🟡 | All 6 theme token sets implemented and working (light is now paper beige, plus dark, tech-blue, warm-amber, forest-green, high-contrast). **Gap**: the header switch is now a two-state sun/moon control as requested, so the other four themes are reachable only via `localStorage` and have no UI entry point |
| F21 | DNS records & domain mapping | ✅ | The parser handles compression pointers and A/AAAA/CNAME; `dns_records` table plus `DomainForIP` reverse lookup; verified resolving real names in the analyzer |
| F22 | GeoIP tagging | 🟡 | `internal/geoip` is fully offline and labels private/CGNAT correctly as local. **Gap**: the built-in table is a coarse first-octet stand-in, not a MaxMind GeoLite2 .mmdb |
| F23 | Protocol identification | ✅ | Implements the §3.5.4 priority chain and reports `unknown` honestly when nothing matches |
| F24 | Port→service mapping | ✅ | `config/port-service-map.yaml`, 24 entries loaded at startup over the built-in table |
| F25 | Per-IP view | ✅ | `GET /api/views/ip` aggregates domain/geo/devices/protocols/ports/bytes; covered by the smoke test |
| F26 | Per-protocol view | ✅ | `GET /api/views/protocol`; covered by the smoke test |
| F34 | East-west monitoring | ✅ | Intranet destinations are never filtered out; `connections.internal` plus the lateral detector — 1335 east-west flows observed |
| F35 | Beacon detection | ✅ | Interval coefficient-of-variation test, thresholds from config |
| F36 | Fan-out / scan detection | ✅ | Sliding-window unique-target counting with per-category thresholds |
| F40 | Live analyzer GUI | ✅ | Three linked panes, display filter, template menu, colour field, process attribution and **click-to-sort columns** all working; verified capturing 69,300 packets on `wlp9s0` with zero drops |
| F41 | Display-filter expressions | ✅ | `internal/dfilter`: logic/comparison/contains/matches/CIDR/presence, immediate syntax errors; the frontend runs no second parser — one grammar, one verdict |
| F42 | Isolation between the two UIs | ✅ | Two binaries on two ports; the smoke test specifically checks that the overview API still answers while the analyzer is suspended |
| F43 | Capture-source fallback & labeling | 🟡 | `live.Open` implements the priority fallback and returns whether the capture is real; the analyzer labels it in the status bar (`Source: af_packet`), and the overview UI shows a header badge (● live / ⚠ simulated, read from `/api/source`). Closed loop |

### P1 — Should have

| ID | Feature | Status | Evidence / gap |
|---|---|---|---|
| F9 | Lock/camera outbound whitelist | ⬜ | Needs an XDP program; not started |
| F10 | Behavior baselining | ⬜ | Not started |
| F11 | On-demand PCAP capture | ⬜ | Not started. Note the distinction from F44: **export** is done, **triggered capture** is not |
| F20 | Interface hot-plug discovery | ⬜ | Config already has `auto` mode and exclusion patterns; the netlink listener is not implemented |
| F27 | Top-N rankings | ✅ | `GET /api/views/topn?dim=device\|ip\|country\|domain`; covered by the smoke test |
| F28 | Geo anomaly alerting | ✅ | The geo_anomaly signal in `detect` |
| F29 | Threat-intel matching | 🟡 | Matching implemented and wired into scoring. **Gap**: feeds are injected by the caller, with no public blocklist ingestion or local cache refresh |
| F30 | Multi-dimension search | ✅ | `GET /api/connections` combines device/IP/protocol/port range/time range freely |
| F37 | Multi-signal weighted scoring | ✅ | Nine weighted signals, configurable thresholds, high/medium/low grading |
| F38 | Automated high-risk response | ⬜ | The `auto_block` switch exists and defaults to off; the blocking action is not implemented |
| F44 | PCAP export | ✅ | `GET /api/export/pcap`; the smoke test exports and then actually reads the file back with `tcpdump -r` |

### P2 — Optional

| ID | Status |
|---|---|
| F12 traffic classification / F13 mobile push / F32 map visualization / F39 malware-download signatures | ⬜ Not started |
| F14 TLS plaintext capture | 🟡 **Phase one implemented**: `internal/tlspeek` + `cmd/BeeEye-tlspeek`, uprobes on OpenSSL's `SSL_write`/`SSL_read`; `TestCapturesRealTLSPlaintext` recovers plaintext from a real TLS session, and the CLI was verified reconstructing the HTTP/2 content of a real `curl https`. **Both paths implemented**: (A) `BeeEye-tlspeek` uprobes decrypt dynamically-linked OpenSSL processes; (B) `scripts/tls-decrypt.sh` uses SSLKEYLOGFILE to decrypt **Chrome/AdsPower and other Chromium/Electron** (verified recovering plaintext SNI + HTTP/2 requests and responses). **Boundary**: path A is gateway-local and needs unstripped symbols; path B must launch the target. **Gaps**: pcapng+DSB export, GnuTLS/NSS/Go crypto/tls, and the analyzer UI pane are unbuilt |
| F15 active MITM | ⬜ Not started, and recommended against: useless against the target IoT devices, needs a cert installed on the device, and directly contradicts "no agent on any device" |
| F31 record export (CSV/JSON) | ✅ `GET /api/export?format=csv\|json`; the CSV carries a UTF-8 BOM so Excel reads CJK correctly |
| F33 DNS anomaly detection | 🟡 High-rate NXDOMAIN (suspected DGA) implemented; DNS tunneling signatures not implemented |

---

## 3. Verified facts

These are measured on this machine, not design intent:

**Kernel and dissection**

- **The eBPF program loads**: both `bpftool prog loadall` and the Go loader pass the verifier on kernel `7.0.0-28-generic` with BTF available.
- **TCX attaches in both directions**: `attach_test.go` attaches to `lo`, sends a UDP/53 datagram, and receives an `EVT_DNS` record whose payload matches what was sent byte for byte.
- **Kernel and userspace agree on struct layout**: `TestEventLayoutMatchesBTF` reads the real field offsets out of the compiled object's BTF and compares them field by field against the Go decoder's hardcoded offsets, instead of trusting manual alignment.
- **The dissector survives truncation**: `TestTruncatedPacketsDoNotPanic` re-dissects every prefix length of a ClientHello frame.
- **JA3 means what it should**: repeated handshakes from one client fingerprint identically; a different cipher list fingerprints differently.
- **Process attribution prefers a blank to a guess**: `internal/procmap` verifies another device's flow comes back **unattributed** rather than pinned on a coincidental local process.

**End to end**
- **Offline pcap import works end to end**: `POST /api/pcap/upload` runs `analyze.Analyze` and returns a full report (protocols, talkers, conversations, sessions, credentials, carved files, security findings, geo); the overview UI's Analysis tab uploads a file and renders all nine report panes (verified: a 713-packet capture parsed and displayed).
- **Captured packets are persisted to disk**: the analyzer streams the live capture to `/tmp/BeeEye/*.pcap`; `TestPcapSinkRoundTrip` and a live check confirm the detail of a packet already evicted from the in-memory ring is read back from disk (packet #1 returned HTTP 200 after 791 evictions), instead of "no longer buffered".

- **Every endpoint on both services answers**: `scripts/smoke.sh` passes **24/24, 0 failed** — 12 overview endpoints, 11 analyzer checks (including SSE stream open, valid and invalid filter paths, and a pcap export read back with `tcpdump`), plus the F42 isolation check.
- **Real capture**: the analyzer took 69,300 packets / 66 MB off `wlp9s0` via AF_PACKET with `kernel_drops: 0`.
- **CUDA and CPU renderers agree**: `TestBackendsAgree` renders the same input on an RTX 2080 Ti and in Go and compares byte by byte — **worst channel delta 1/255**, mean 0.00001.
- **The colour-field palette matches the frontend**: `TestPaletteCSSMatchesChannels` compares `PaletteCSS()` against `ChannelColors` slot by slot, so the packet list's swatches cannot drift from the field's channel colours.
- **Auto-scroll no longer drifts**: with it off, 214 new rows arrived (content grew 6170px) while `scrollTop` stayed at 41909 and the row at the top of the viewport did not change; with it on, the pane follows the tail and the page itself never scrolls.
- **Column sorting is correct**: with the capture stopped, zero inversions across 2966 IPv4 rows, and the three address families each form one contiguous block.

---

## 4. Next

In priority order:

1. **Wire the eBPF ring buffer in as a capture source** — the agent already captures live via AF_PACKET (§0), and the eBPF CO-RE program stands on its own; wiring `internal/ebpf` in as a second source would add in-kernel tiering (F5) and lower overhead, but is no longer a blocker for real data in the overview.
2. **A real/simulated badge in the overview UI** — only the startup log states the fallback today; the page has no badge like the analyzer's status bar (F43).
3. **A second entry point for the remaining four themes** — after the header switch became a two-state sun/moon control, tech-blue / warm-amber / forest-green / high-contrast are unreachable from the UI.
4. GeoLite2 .mmdb (F22), threat-intel feed ingestion (F29), CoAP field decoding (F4).
5. Behaviour baselining (F10), on-demand capture (F11), interface hot-plug (F20).
6. TLS plaintext capture, **phases two/three**: pcapng+DSB export, per-OpenSSL-version keylog offset tables, and an analyzer "plaintext" pane. Phase one (text mode) is done — see [TLS-DECRYPT.md](TLS-DECRYPT.md); the README's privacy promise has been narrowed accordingly.
