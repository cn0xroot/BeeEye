# BeeEye — Implementation Progress

> Website: https://www.beeeye.dev/
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

**The agent now captures real traffic by default**, not the simulated scenario. `BeeEye-agent/main.go` uses `internal/livesource`, which picks its capture source through `internal/capsource`'s priority chain, and folds it into devices, connections, DNS records and alerts in SQLite.

| Process | Port | Data source | Real? |
|---|---|---|---|
| `BeeEye-agent` | :8080 | `internal/capsource` → eBPF ring buffer (preferred) or AF_PACKET (fallback) | ✅ **real capture** |
| `BeeEye-gui` | :8081 | `internal/live` (AF_PACKET — see "why the analyzer doesn't use eBPF" below) | ✅ **real capture** |

So **the overview UI and the analyzer UI now describe the same real network** (this host's subnet, e.g. `192.168.x.x`); they agree.

**The fallback is still honest (F43)**: with no raw-capture permission, or with neither eBPF nor AF_PACKET available, or with `-simulate`, the agent falls back to the built-in simulated scenario and says so in the startup log (`SIMULATED traffic`) — it never passes simulated flows off as real. The overview UI header carries a live badge (`source-badge`) naming which of `ebpf`/`af_packet`/`simulated` is actually running.

**Interface selection (F16)**: `captureIface` tries, in order, a configured interface that exists, then the default-route NIC, then `any` — so the shipped `wlan0`/`eth0` that this host lacks resolve to the real NIC instead of silently dropping back to the simulator.

**`internal/ebpf` today (updated 2026-08-19)**: the CO-RE TC program now supports a "raw-frame mode" — a new `EVT_RAW_FRAME` event kind plus a `CFG_RAW_FRAME_MODE` switch that, once flipped, mirrors every packet's whole raw frame unconditionally (not just the selective DNS/TLS/etc. header regions). `internal/ebpf.OpenEBPF` wraps that into an ordinary `live.Source`, structurally identical to AF_PACKET's, so it feeds the existing dissect pipeline unchanged. `internal/capsource` implements the three-tier chain (eBPF preferred, AF_PACKET fallback, simulator last), and `internal/livesource` (the agent) uses it.

**Why the analyzer (`internal/gui`) doesn't use eBPF**: verified live with `bpftool prog show`'s `run_cnt` field — on this host's kernel, TCX lets multiple independent programs attach to the same interface's same direction, but **only the first one attached is ever actually invoked**; a second attach "succeeds" (no error) yet its `run_cnt` stays 0 forever (confirmed on both ingress and egress). So the agent — the long-running process eBPF's lower overhead matters most for — gets sole claim to eBPF, and the analyzer — a diagnostics tool started on demand — keeps using AF_PACKET, which has always supported multiple independent readers on one NIC, rather than building self-check/retry logic around a kernel-specific quirk. See the comments in `internal/capsource/capsource.go` and `internal/gui/session.go`.

---

## 1. Overall

| Layer | Status | Notes |
|---|---|---|
| Live capture | ✅ | The agent prefers eBPF ring buffer (raw-frame mode) via `internal/capsource`, falling back to AF_PACKET; the analyzer stays on AF_PACKET (see §0 for why). Both paths verified live; `EVT_RAW_FRAME` end to end proven |
| Userspace agent core | ✅ | Live capture → dissect → aggregate → detect → persist wired end to end (`internal/livesource`, 507 lines) |
| Dissector | ✅ | Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP + DNS/mDNS/TLS/HTTP/MQTT/SSDP/DHCP, in use end to end by the analyzer |
| Display-filter engine | ✅ | Wireshark-compatible subset including CIDR and regexp; the frontend's validation and the actual filtering share one parser |
| Storage | 🟡 | All SQLite tables in place and in use; InfluxDB time-series store not wired up |
| Detection engine | ✅ | Ten weighted signals implemented and producing events, including behavior baselining (z-score, F10); threat intel (F29) now backed by a real public blocklist |
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
| F4 | Plaintext protocol parsing | ✅ | MQTT / HTTP / SSDP / mDNS / DNS / DHCP / **CoAP** (RFC 7252 header + token + Uri-Path/Uri-Query/Content-Format/Observe and other options, field-decoded; covered by `TestDissectCoAP` plus a truncation fuzz test) all implemented |
| F5 | Tiered monitoring policy | 🟡 | Tiering pushed into the kernel: locks/cameras report per flow, everything else via aggregated snapshots. **Gap**: tiering lives in the eBPF path; the AF_PACKET path does not tier |
| F6 | Anomaly rule engine | ✅ | `internal/detect`: threat intel, beacon, fan-out, lateral, DNS anomaly, geo, off-hours — observed producing 38 risk events |
| F7 | Web visualization UI | ✅ | Overview / devices / connections / by-IP / by-protocol / DNS / alerts all usable; screenshotted page by page with zero page errors. **New**: the alerts table has a "related to" column (destination IP, domain, geo) — `GET /api/events` now enriches server-side; `detail.dst_ip` used to be buried in the raw JSON blob, it's a first-class field now |
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
| F10 | Behavior baselining | ✅ | `internal/detect.Engine.Baseline`: per (device, hour-of-day) bucket, a Welford online mean/stddev over the days seen in that bucket, and today's byte count for that hour is z-scored against it (defaults `min_days=5`, `z_threshold=3.0`), producing a new `baseline_deviation` signal (weight 15). Stays a pure function like every other detector here — no persisted model, relearns on restart. Covered by `TestBaselineFlagsVolumeOutlier`/`TestBaselineIgnoresNormalVariation`/`TestBaselineRequiresMinimumHistory` |
| F11 | On-demand PCAP capture | ✅ | New `internal/tcapture`: a MAC-triggered, time/byte-bounded targeted capture (distinct from F44's export of the existing ring buffer — this is a *fresh* capture from the moment it's requested), fed straight off the `livesource.Pipeline` hot path to disk, nothing buffered in memory. `POST /api/capture/targeted` starts one, `GET .../{id}` polls status, `GET .../{id}/download` fetches the file. **Verified live**: a 15s targeted capture against a real gateway MAC captured 1811 frames / 1.6MB; every one of the 1811 frames in the downloaded pcap matched the target MAC on read-back via `tcpdump -e`, zero false matches |
| F20 | Interface hot-plug discovery | ✅ | New `internal/live/hotplug.go`: a raw AF_NETLINK socket subscribed to `RTMGRP_LINK`, parsing `RTM_NEWLINK`/`RTM_DELLINK` with explicit byte offsets (no unsafe pointer casts; a truncated message never panics). `auto_discover.exclude_patterns` went from "present in config but never consulted" to actually driving `autoDiscoverIface`. `main.go`'s `hotplugSupervisor` re-evaluates `captureIface` on every event and, if it now names a different interface, closes the old pipeline and opens a new one, re-wiring the threat-intel/targeted-capture callbacks onto it. **Verified**: a real dummy NIC proved both that kernel events are captured correctly and that `captureIface`/`autoDiscoverIface` return the right answer before and after the interface exists (`main_test.go`) |
| F27 | Top-N rankings | ✅ | `GET /api/views/topn?dim=device\|ip\|country\|domain`; covered by the smoke test |
| F28 | Geo anomaly alerting | ✅ | The geo_anomaly signal in `detect` |
| F29 | Threat-intel matching | ✅ | New `internal/threatintel`: pulls the Spamhaus DROP public blocklist (CIDR ranges, no signup), loads its local cache synchronously at startup (never blocks capture on the network) and refreshes in the background on `refresh_hours` (default 24h), falling back to the last-good cache on any fetch failure with just a log warning. `detect.ThreatIntel` gained `BadCIDRs` + `MatchIP` (exact match first, then CIDR containment). **Verified live**: a real fetch returned 1693 CIDR ranges, cached to `data/threatintel/spamhaus_drop.txt` |
| F30 | Multi-dimension search | ✅ | `GET /api/connections` combines device/IP/protocol/port range/time range freely |
| F37 | Multi-signal weighted scoring | ✅ | Nine weighted signals, configurable thresholds, high/medium/low grading |
| F38 | Automated high-risk response | ⬜ | The `auto_block` switch exists and defaults to off; the blocking action is not implemented |
| F44 | PCAP export | ✅ | `GET /api/export/pcap`; the smoke test exports and then actually reads the file back with `tcpdump -r` |

### P2 — Optional

| ID | Status |
|---|---|
| F12 traffic classification / F13 mobile push / F39 malware-download signatures | ⬜ Not started |
| F32 map visualization | ✅ **Client-side WebGL2 3D globe** (`BeeEye-web/src/components/Globe.jsx`) — not the server-side CUDA traffic-field pipeline; two different GPUs, two different pipelines. The website roadmap's original "reuses the CUDA pipeline" framing has been corrected. New backend endpoint `GET /api/views/geopairs`: recent external connections (internal traffic excluded) with lat/lon, country, domain, byte count, newest first by `ts`. The frontend polls every 4s; destination points on the globe persist (they don't vanish just because no new connection showed up in the last poll), and each newly-seen connection triggers a great-circle light-trail animation. The gateway itself has no real coordinate here — it never phones out to look up its own public IP — so every arc's local end is a fixed, explicitly-labelled schematic anchor, not a claim about where the gateway actually is. **A real bug got fixed along the way**: `geoip.Lookup` returned immediately on any mmdb hit, even a Country-tier database with no Location record at all — and the Clash `Country.mmdb` this machine auto-discovers by default is exactly that (and also tags ranges with non-ISO pseudo-codes like `GOOGLE`/`CLOUDFLARE` for proxy routing rather than real country codes), so the map would have shipped with zero plottable points. Fixed with a two-tier lat/lon fallback — a country-centroid table for real ISO codes, then the known-infrastructure-range table for pseudo-codes — new `internal/geoip/centroid.go`, covered by `TestCountryCentroidSane`/`TestFirstOctetLatLon`. **Tested for real**: against the actual simulated dataset, `/api/views/geopairs` returns real destinations with real coordinates (`time.windows.com`→NL, `dns.google`→GOOGLE, etc.); screenshots confirmed correct rendering in both warm/dark themes and both languages, captured via a CDP script that waits on the real wall clock specifically to rule out `--virtual-time-budget`'s virtual-clock artifacts in headless Chrome. **Gaps**: only destination points are real — there's no real gateway coordinate; a burst of many new connections in the same second animates as separate arcs rather than being visually batched. |
| F14 TLS plaintext capture | 🟡 **Phase one implemented**: `internal/tlspeek` + `cmd/BeeEye-tlspeek`, uprobes on OpenSSL's `SSL_write`/`SSL_read`; `TestCapturesRealTLSPlaintext` recovers plaintext from a real TLS session, and the CLI was verified reconstructing the HTTP/2 content of a real `curl https`. **Both paths implemented**: (A) `BeeEye-tlspeek` uprobes decrypt dynamically-linked OpenSSL processes; (B) `scripts/tls-decrypt.sh` uses SSLKEYLOGFILE to decrypt **Chrome/AdsPower and other Chromium/Electron** (verified recovering plaintext SNI + HTTP/2 requests and responses). **Boundary**: path A is gateway-local and needs unstripped symbols; path B must launch the target. **Gaps**: pcapng+DSB export, GnuTLS/NSS/Go crypto/tls, and the analyzer UI pane are unbuilt. Specific technical routes worked out from [eCapture](https://github.com/gojue/ecapture)'s source (`kern/`, `internal/probe`, `internal/output`), not just its README, are below |
| F14 details worth borrowing (source-level research, not the README summary) | ⬜ **① OpenSSL/GnuTLS multi-version compatibility goes "version detection + a pre-measured offset table", not CO-RE**: eCapture keeps one plain field-offset constant table per specific OpenSSL release (39 of them, 1.0.2a→3.5.0) and per GnuTLS release (7), e.g. `#define SSL_CONNECTION_ST_SESSION 0x880`; the probe logic itself is generic, and detects the loaded library's version at runtime to pick the matching table. Why: CO-RE needs BTF, and the .so a system actually has installed almost never carries it — CO-RE solves cross-version kernel structs, not cross-version userspace library structs. `internal/tlspeek` today almost certainly only fits the one OpenSSL version on this machine; this is the only viable route to real multi-version support, not something to wait on CO-RE for. **② GoTLS goes the other way and does use CO-RE**: `gotls_kern.c` is a single file, no per-version split; `go_argument.h` uses `BPF_CORE_READ` to abstract Go 1.17+'s register-based calling ABI per architecture (x86 reads `ax`/`bx`/…, arm64 goes through `PT_REGS_PARMx_CORE`), and pulls in `tc.h` because a uprobe at the application layer can't see the socket's 5-tuple — a TC program has to supply it at the network layer. The uprobe(plaintext)+TC(5-tuple) combination is a workable architecture reference for Go crypto/tls support. **③ Output-layer writer/encoder separation**: `internal/output/writers` (file/stdout/**tcp**/**websocket**/logger) crossed with `encoders` (json/plain/protobuf) is a clean reference architecture for "forward plaintext events to an external tool live" (a local analysis script, a third-party consumer) — optional, not required, and a different consumption path from pcapng+DSB export. |
| F15 active MITM (blanket, all devices) | ⬜ Not started, and recommended against: useless against the target IoT devices, needs a cert installed on the device, and directly contradicts "no agent on any device" |
| F45 opt-in phone MITM decryption (Surge/Burp/mitmproxy-style) | ✅ New `internal/mitm`: locally-generated root CA (ECDSA P-256, private key written 0600, never leaves the host), per-SNI leaf certs signed on demand (one shared leaf key, only the cert changes), an HTTP CONNECT proxy that terminates the client's TLS with that leaf and forwards over a **fully validated** TLS connection to the real origin (no `InsecureSkipVerify`). Scope is deliberately CONNECT/HTTPS only — plain HTTP gets a 400. API: `GET /api/mitm/status`, `GET /api/mitm/ca.pem`, `GET /api/mitm/ca.mobileconfig` (one-tap iOS install profile), `GET /api/mitm/exchanges[/{id}]` (in-memory ring, cleared on restart, never written to disk — the most sensitive data this project handles). Off by default (`mitm.enabled: false`), needs an explicit config change and restart. **Tested for real** (not simulated): a full run against the actual `https://example.com` — a curl trusting the generated CA got back the real decrypted response body; a curl that doesn't trust it was correctly refused (fail-closed, not a silent plaintext passthrough); the `.mobileconfig` was validated as a real Apple configuration profile via Python's `plistlib`, not just well-formed XML. Four unit tests (end-to-end decryption, untrusted-client rejection, plain-HTTP rejection, mobileconfig content) pass under `-race`. Overview UI got a new "Certificate & decryption" page (`BeeEye-web/src/components/Mitm.jsx`): proxy address / CA fingerprint / decrypted-request-count tiles, PEM and `.mobileconfig` download buttons, and a five-platform "installing the cert isn't the same as trusting it" table, in both languages. **Gaps**: this is an explicit proxy (CONNECT), not transparent redirection — a device still has to be configured to point at it by hand; the decrypted exchange list has an API but no UI panel yet. See [TLS-DECRYPT.md §5](TLS-DECRYPT.md) for the full per-platform trust-caveat table. |
| F31 record export (CSV/JSON) | ✅ `GET /api/export?format=csv\|json`; the CSV carries a UTF-8 BOM so Excel reads CJK correctly |
| F33 DNS anomaly detection | 🟡 High-rate NXDOMAIN (suspected DGA) implemented; DNS tunneling signatures not implemented |

---

## 2.5. Delivered beyond the original requirements

### BeeEye-desktop — a native window shell for the analyzer

`BeeEye-desktop/src-tauri`: a ~200-line Tauri 2 shell wrapping the existing `BeeEye-gui` web UI in a native window. It **duplicates or rewrites no frontend code** — the window is, in substance, a browser shell pointed at `http://127.0.0.1:8081`. On startup: if a backend is already answering on that port (e.g. started by hand via `scripts/dev.sh`) it connects directly; otherwise it locates and spawns the `BeeEye-gui`/`BeeEye-gui-cuda` binary itself (picking the default-route interface via `ip route get`, the same logic as `scripts/dev.sh`'s `default_iface()`). On window close it kills only the child process it spawned itself, leaving a pre-existing backend instance untouched.

**This does not contradict F40's design rationale in program.en.md**: that document argues against installing a native window *on the headless gateway itself* (no desktop session there). What this delivers is the opposite scenario — a more native-feeling alternative to a browser tab for an operator's own **desktop workstation** (Mac/Windows/Linux desktop), talking to a backend that may be local or a remote gateway reached over a tunnel/forward. The two serve different deployment locations and are not in tension.

**Verified**: `cargo build --release` compiles clean on the reference machine (Ubuntu 24.04, Rust 1.97.1, tauri 2.11.5 with the webkit2gtk dependency chain), producing a working ELF executable. No automated tests — the logic is mostly I/O integration (port probing, child-process lifecycle).

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

**Added 2026-08-19 (F10/F11/F20/F29)**
- **Threat intel actually fetched live**: `internal/threatintel` pulled Spamhaus DROP on this machine and got back **1693 CIDR ranges**, correctly cached to `data/threatintel/spamhaus_drop.txt`; the fetch never blocked agent startup (cache loads synchronously first, the network fetch runs in a background goroutine).
- **On-demand targeted capture works end to end**: a 15-second targeted capture against a real LAN gateway MAC (`POST /api/capture/targeted`) captured **1811 frames / 1.6MB** and closed correctly on its deadline; the downloaded pcap was correctly recognized and read by `file`/`tcpdump`, and **every one of the 1811 frames matched the target MAC** (checked frame by frame with `tcpdump -e`, zero false matches).
- **Interface hot-plug reacts to real kernel events**: creating/deleting a dummy NIC, `internal/live.WatchLinks` correctly received `RTM_NEWLINK`/`RTM_DELLINK` over a real AF_NETLINK socket; `captureIface`/`autoDiscoverIface` return the right interface before and after it exists (`main_test.go`, also against a real dummy NIC rather than synthetic data).
- **A data race introduced by the hot-plug work was caught by `go test -race` and fixed**: `tcapture.Session`'s deadline-timer callback and `Start()`'s assignment to `s.timer` raced unguarded; `api.Server`'s `SetSource`/`SetTargetedCapture` — previously called once at startup and never under concurrent access — are now an atomic-pointer swap of an immutable struct, so a concurrent reader can't see a torn combination of fields. `go test -race ./...` is clean.
- **Regression**: `make smoke` re-run after this round of changes still passes **24/24, 0 failed**.

**Added 2026-08-19 (eBPF raw-frame capture)**
- **A real compile-time limit and its fix**: `struct BeeEye_event` grew past roughly 1KB once `PAYLOAD_MAX` moved from 512 to 1536, and clang for the BPF target flatly refuses to inline-expand a `__builtin_memcpy`/`__builtin_memset` that large ("A call to built-in function 'memcpy' is not supported"). Fixed with a hand-unrolled 8-byte word-copy loop (`#pragma unroll`, 205 iterations, purely sequential instructions the verifier never has to reason about inductively) in place of the big memcpy, and an `offsetof`-bounded memset that only clears the 104-byte header, not the payload array. Both changes verified against the real kernel verifier via `make bpf-verify`.
- **Fine-grained truncation was actively losing data**: `load_payload`'s cascade, designed for selective reporting (1536/384/256/…/48/32/16/8), over-truncates a frame that lands between two steps in raw-frame mode (a real 63-byte DNS query frame got cut to 48 bytes in testing — not even enough for a 12-byte DNS header — and dissection silently failed). Switched to an exact, runtime-computed length (`len = min(skb->len, PAYLOAD_MAX)`) — the verifier accepted this dynamic-length `bpf_skb_load_bytes` once `len`'s value range was narrowed to `[0, PAYLOAD_MAX]` by two comparisons, contradicting the old in-code comment claiming the length had to be a compile-time constant; verified working on this kernel.
- **eBPF source verified end to end**: `internal/ebpf.OpenEBPF` captured a real, hand-constructed DNS query on `lo`; `live.Packet.CapLen` matched the original frame length exactly (63 bytes — Ethernet + IP + UDP headers + the DNS message, not just a protocol payload), and re-dissecting it produced results identical to the AF_PACKET path.
- **A significant kernel behavior discovery**: `bpftool prog show`'s `run_cnt` field proved that on this host's kernel, TCX allows multiple independent programs to attach to the same interface's same direction, but **only the first one attached is ever actually invoked** — a second, "successful" attach (no error) has `run_cnt` stuck at 0 forever. This directly shaped the architecture: only the agent uses eBPF; the analyzer keeps AF_PACKET rather than the two processes fighting over one NIC's eBPF attach point.
- **Verified live on a real NIC**: on `wlp9s0`, the agent's `/api/source` confirmed `source: "ebpf"` with `connection_count` climbing in real time (28218→28233 over 15s); the analyzer's `/api/status` confirmed `source: "af_packet"` with `captured` climbing (3602→6227); F11's targeted capture worked the same way against the eBPF-backed pipeline (186 frames / 37KB).
- **Regression**: `go test -race ./...` clean; `make smoke` 24/24.

---

## 4. Next

> Updated 2026-08-19: GeoLite2 ingestion, a real public threat-intel blocklist, CoAP field decoding, behavior baselining, on-demand targeted capture, interface hot-plug, the overview's real/simulated badge, the F19 theme entry point, and **wiring the eBPF ring buffer into the agent's capture source** are all done now — see the per-requirement table above and §0. What follows is the re-checked, still-genuinely-open list.

In priority order:

1. **TLS plaintext capture, phases two/three** — pcapng+DSB export, GnuTLS/NSS/Go crypto/tls, and an analyzer "plaintext" pane. The technical route is now worked out from eCapture's source, not a vague pointer — version-detection-plus-offset-table vs. GoTLS going the CO-RE route (see the F14 row in §2). Phase one (text mode) is done — see [TLS-DECRYPT.md](TLS-DECRYPT.md).
2. ~~F45, opt-in phone MITM decryption~~ **Done** (`internal/mitm` + the overview UI's "Certificate & decryption" page) — see the F45 row above and [TLS-DECRYPT.md §5](TLS-DECRYPT.md). Left: a UI panel for the decrypted-exchange list, transparent redirection (currently an explicit proxy).
3. A Fingerbank-style model-fingerprint database (F1 gap), DNS tunneling signatures (F33 gap; high-rate NXDOMAIN/DGA is done).
4. Outbound allowlisting for locks/cameras needs an XDP program (F9); automated response to high-severity events (F38, the config switch exists and defaults off); the remaining P2 items (F12 traffic classification / F13 mobile push / F39 malware-download signatures) are all unstarted. F32 map visualization is done — see §2.
5. (Optional, low priority) Investigate whether this host's TCX chain only ever invoking the first attached program is specific to this kernel or more general; if it can be lifted, the analyzer could share eBPF with the agent via some form of shared ring-buffer reader instead of forgoing it outright. Right now the payoff (the analyzer keeps using well-proven AF_PACKET) outweighs digging further into this kernel detail — recorded honestly in §0 instead.
