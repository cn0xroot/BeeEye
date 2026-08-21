# Changelog

All notable changes to BeeEye are documented in this file.

[中文](CHANGELOG.zh-CN.md)

## [Unreleased]

## [1.2.0] — 2026-08-21

### Added

- **BeeEye-desktop: one window, tabbed** — the desktop shell no longer navigates between the overview and analyzer web UIs; `dist-placeholder/index.html` is now a permanent tab-switcher hosting both as lazily-probed iframes. Closing the window now stops both backend processes regardless of which one the desktop app itself spawned, using each backend's own `.run/<name>.pid` file rather than `ss -tlnp` (which cannot report the PID of a setcap'd, non-dumpable process to another user).
- **Offline analysis now reads pcapng, not just classic pcap**: a full pcapng reader (`internal/pcapfile/pcapng.go`) — Section Header Block byte-order detection, Interface Description Block (timestamp resolution *and* link type), Enhanced/Simple Packet Blocks — behind the same `pcapfile.Open` auto-detection classic pcap already used.
- **Importing a capture now updates the overview, not just the analyzer**: `livesource.ImportFile` replays a file through the exact same device/connection/DNS aggregation a live capture gets, so a capture opened in the analyzer stops disagreeing with what the overview shows. Because an import's own packet timestamps can be arbitrarily old and get crowded out of the overview's normal recency-ordered views by live traffic, the affected endpoints (`geopairs`, `summary`, `views/protocol`, `views/topn`) accept an `iface` scope naming one import batch, and the overview's world map gained an import picker that auto-scopes to a batch imported in the last 90 seconds.
- **New protocol dissectors**: SIP (request/status line, From/To/Call-ID/CSeq/Via/Contact, RFC 3261 §7.3.3 compact header forms), SCTP (chunk types, DATA's TSN/stream ID/payload-protocol-id), and GTP-U/GTP-C tunnel decapsulation (a G-PDU's inner IPv4/IPv6 packet is recursively dissected, so whatever the tunneled device was actually doing — TLS, HTTP, SIP, DNS — is no longer hidden behind "UDP 2152"). Verified end-to-end against a real capture containing nested GTP → SIP/SCTP/TLS traffic.
- **World map**: coastline outlines, arcs that keep pulsing for as long as traffic continues (not just on a destination's first appearance), pulse direction driven by which way more of the traffic actually flowed (upload vs. download) instead of always animating outward, and a hover tooltip showing the resolved country/region/city for both ends of a flow when the non-local end has a real geo point (e.g. after a GTP tunnel is unwrapped).
- **Traffic Trend rebuilt as a plain client-side SVG chart** (`TrafficTrendChart.jsx`) with a real Y-axis (byte-value gridlines), X-axis time labels, and a legend — replacing the earlier GPU-rendered glow/bloom picture, which had no way to show an actual number. tx (this gateway sending) and rx (receiving) are mirrored above/below a centre baseline sharing one axis scale, sized to match the world map card.
- A top-level `ErrorBoundary`, re-keyed per tab, so a render error in one view can no longer take the whole navigation bar down with it.
- The analyzer no longer auto-starts capturing on launch; a new `-autostart` flag on `BeeEye-gui` restores the old immediate-capture behaviour for scripted/headless deployments.
- **GSMTAP/SIM dissector**, so offline import can parse SIMtrace-style captures: a full ISO/IEC 7816-4 APDU decode (CLA/INS/P1/P2, SELECT by AID vs. by path — distinguished by P1 per ETSI TS 102.221 §11.1.1, not by data shape, which is not reliable — READ/UPDATE BINARY/RECORD, VERIFY/CHANGE/UNBLOCK CHV, RUN GSM ALGORITHM, STATUS, GET RESPONSE, and more), a 57-entry (U)SIM file table (MF/DF/EF names), and status-word interpretation — all cross-checked field-by-field against `tshark`'s own dissection of a real capture rather than guessed from memory.
- **Bilingual (English + 中文) plain-language explanations for SIM/GTP/SCTP messages** in the analyzer's plaintext pane: these protocols never carry the gateway's own decryptable HTTPS, so the pane that used to just say "nothing to decrypt" for them now explains what the selected message actually does (e.g. what a SIM `RUN GSM ALGORITHM` or a GTP `Create PDP Context Request` is for), in both languages at once.
- **Overview: a colored network-interface card** showing the interface currently being captured on — IP, MAC, live upload/download throughput read from the kernel's own per-NIC counters, cumulative totals, and for a wireless adapter, SSID/channel/signal (via `iw`) — each stat in its own vivid color, conky-style.
- Import scoping (an imported capture's `iface` batch) now also applies to the Connections, By-IP, and DNS views, matching the world map/summary/By-protocol views that already had it; DNS records gained their own `iface` column so a DNS lookup can be attributed back to the capture it came from.

### Fixed

- **A raw-IP or Linux-cooked-capture link type was silently dissected as Ethernet**: a file captured on a tunnel/VPN-style interface has no link-layer header at all, and the dissector was reading the IP header's own bytes as a bogus 12-byte MAC pair — real source/destination addresses replaced by garbage, everything past that layer left unparsed. `dissect.Packet` now branches on the capture's actual link type (`LINKTYPE_RAW`/`DLT_RAW`/`LINKTYPE_LINUX_SLL`) instead of assuming Ethernet unconditionally.
- **"That packet is no longer buffered" appearing frequently**: traced to a data directory silently owned by a different user than the one running the capture process, which disabled the on-disk fallback a ring-buffer eviction is supposed to read from.
- **StatusBar's "Displayed" count** was the browser's own local packet-list length (capped at its retention limit) rather than the server's authoritative, filter-matched count — now reads directly from the polled `status.displayed` field.
- **A world-map rendering crash could permanently blank the panel**: the Canvas2D fallback renderer (used when WebGL2 isn't available) could pass a non-finite coordinate to `createRadialGradient`, and because its render loop only reschedules itself from its own last line, one bad frame silently ended the animation forever. Both the Canvas2D and WebGL render loops now catch per-frame errors and keep rescheduling regardless, plus the specific non-finite cases (a zero-sized canvas mid-layout, a degenerate arc) are guarded directly.
- A concurrency race in offline replay (`Session.startWith`) where a just-stopped capture's trailing writes could land in a freshly-reset ring buffer, most visible as a freshly opened file's captured/buffered counts disagreeing.
- **World map traffic pulses had frozen in place**: an arc's "born" timestamp (set when new traffic is seen) and the render loop's own clock were measured from two different epochs — one from page load, the other from however long the map had already been mounted — so an arc's computed age came out permanently negative once the map had been open more than a moment. Every pulse then stayed clamped to its arc's starting point forever, and the arc itself never aged out either. Both the Canvas2D and WebGL render loops now measure age against the same clock the poll that creates an arc already uses.
- **A stale frontend bundle could keep running long after a redeploy**: `index.html` was served with no `Cache-Control` at all, leaving a browser free to keep it (and therefore whichever old, hashed JS/CSS it pointed at) for an extended period on its own heuristic. `index.html` now explicitly requires revalidation on every request; the hashed `/assets/*` files it points to (whose name changes the moment their content does) are now cached for as long as a browser likes, since that has always been safe.
- **`/api/summary` could take multiple seconds and read as a blank/stuck overview page**: it queried and summed the *entire* connections table in Go on every 3-second poll from every open tab — fine at a few hundred rows, a multi-second stall once a long-running capture's table reaches the tens of thousands. Replaced with a single SQL aggregate (`ConnectionTotals`) computed inside SQLite itself, which returns one row regardless of table size.
- The world map's WebGL context is now released explicitly on unmount (`deleteProgram`/`deleteBuffer`/`WEBGL_lose_context`) rather than left for the browser to reclaim whenever it gets around to it — a defensive hardening step against GPU-context-teardown crashes some WebView engines are prone to under repeated mount/unmount (e.g. switching tabs quickly), which is the leading theory for a still-unconfirmed "view goes blank, navigation stops responding" report from BeeEye-desktop specifically.

### Notes

- Still investigating: HTTPS decryption occasionally fails to attach with `opening mem: open /proc/self/mem: permission denied` even though the process holds the expected capability. Narrowed to the exact trigger — `cilium/ebpf` only performs a kernel-version probe that opens `/proc/self/mem` when loading a `Kprobe`-type program (uprobes included), so it is specific to the decryption path's program type, not a general capability problem — but the root cause of the open itself failing is not yet found.
- Still investigating: an intermittent "view goes blank, other tabs stop responding" report specific to BeeEye-desktop (its Tauri window, which uses WebKitGTK on Linux rather than the Chromium engine every other test in this project has been run against). The GPU-context-teardown hardening above is a reasoned mitigation, not a confirmed fix — it could not be reproduced or verified in a Chromium-based test environment.

## [1.1.0] — 2026-08-20

### Added

- **HTTPS decryption on by default**: the analyzer now attaches decryption uprobes automatically on startup (`internal/gui/decrypt.go`) instead of requiring a separate manual step — verified decrypting real curl traffic live.
- **Crypto-library support became a declarative rule table**: `internal/tlspeek/rules.go` — one rule (family name, SONAME regex, read/write symbols) covers a whole library family across versions/distros by regex rather than a fixed filename; adding a library is a one-line addition. **GnuTLS** joins **OpenSSL** as a supported family (72 GnuTLS processes + 44 OpenSSL processes attached simultaneously on the reference machine).
- **Crypto-library detection**: `BeeEye-tlspeek -detect` + `GET /api/decrypt/libs` report, per library, whether its ELF symbols are actually present (attachable vs. merely installed) and its **version, parsed from the library's own embedded version banner** (e.g. `OpenSSL 3.0.13`, `GnuTLS 3.8.3`), correctly distinguishing two different OpenSSL builds installed in different environments on the same host.
- **F22, real GeoIP database support**: `internal/geoip/mmdb.go` loads standard MaxMind-format `.mmdb` files (via `geoip2-golang`), auto-discovering `./data/`, `/usr/share/GeoIP/`, and a Clash `Country.mmdb`; resolves country/province/city when a City database is present, operator/ASN when an ASN database is present. New `GET /api/geoip/status` and an overview UI accuracy badge (`GeoAccuracyBadge.jsx`) tell the operator whether locations are precise, country-only, or the built-in coarse fallback. New `scripts/geoip-setup.sh` guides downloading GeoLite2-City/ASN (requires the user's own free MaxMind license key) — the download itself does not touch the "no per-IP online lookups" privacy requirement, since every lookup after the file lands is local.
- **F45, decrypted-request list UI**: the MITM proxy's `/api/mitm/exchanges` API now has a frontend panel (`Mitm.jsx`) — a live-updating table of decrypted requests, click-to-expand into request/response headers and body (binary bytes rendered as `·` placeholders). Verified against a real end-to-end MITM session: a trusted client's decrypted `GET https://example.com` appears in the list with its full response body visible.
- **F32, world map changed from a 3D globe to a 2D map with GPU rendering**, per explicit request: `WorldMap.jsx` replaces `Globe.jsx` (deleted). WebGL2 fragment shaders render destinations as additively-blended radial glows (repeated/overlapping traffic visibly brightens) and animated great-circle-ish arcs; colours are read live from the active theme's CSS variables. A Canvas2D fallback renderer (radial gradients, same visual language) covers browsers/environments without WebGL2, so the map always shows something rather than an error.
- **Appearance settings panel** on both UIs: a theme picker with live-preview swatches (9 themes on the overview UI, 5 on the analyzer, including two new high-chroma themes — **Midnight Neon** and **Matrix**), a font picker (System / Tech Mono / Rounded / Serif, each option rendered in its own font), and a UI-scale picker (S/M/L/XL via CSS zoom). All three persist per-browser and are independent between the two UIs.
- An `INSTALL.md` / `INSTALL.zh-CN.md` pair: a from-scratch setup guide for a brand-new clean host, including the actual hardware/software versions this project is developed and tested on.
- A bilingual `USAGE.en.md` mirroring `USAGE.md`, kept in sync, linked from the English README.

### Fixed

- **Analyzer layout bug**: selecting a packet could cover the packet list with the detail region, making other traffic unreachable. Root cause: the endpoint-info bar and the plaintext pane had been added as implicit grid children rather than inside the intended 2-column/3-column structure. Fixed by wrapping the detail region in its own flex container as the second grid row, with the lower region now an explicit 3-column grid (field tree / hex / plaintext) where every pane scrolls internally and never grows to cover the list above it.
- Two crypto-library-detection bugs found while adding the version-banner parser: a GnuTLS marker match could land on an unrelated string containing the word "GnuTLS" (its own error-message table) instead of the version banner — fixed by requiring a digit immediately after the marker; OpenSSL's version string usually lives in `libcrypto` even when `libssl` is a separate file — fixed by falling back to the sibling `libcrypto` file next to a given `libssl` path.
- **Decryption attach bugs**: uprobes were being attempted against `libcrypto` (which does not export `SSL_write`/`SSL_read` — only `libssl` does) and against library paths discovered from `/proc/*/maps` that no longer existed on disk by the time of attach (a process that had since exited or a path outside the mount namespace) — both fixed by filtering to rule-matched libssl-family paths and skipping paths that fail `os.Stat`.

- **F10, behavior baselining**: `internal/detect.Engine.Baseline` learns a per-device, per-hour-of-day traffic distribution (Welford online mean/stddev across the days seen in that hour bucket) and flags today's value as an outlier past a configurable z-score threshold — e.g. a NAS that only ever talks 09:00–18:00 suddenly active at 03:00. Stays a pure function like every other detector here; no persisted model.
- **F11, on-demand targeted capture**: `internal/tcapture` + `POST /api/capture/targeted` starts a fresh, MAC-filtered pcap capture for a bounded duration/byte budget, distinct from F44's export of the existing ring buffer. Verified live against a real gateway MAC: 1811 frames / 1.6MB captured, every frame in the downloaded pcap correctly matched the target MAC on read-back.
- **F20, interface hot-plug discovery**: a raw AF_NETLINK watcher (`internal/live/hotplug.go`) reacts to a NIC appearing or disappearing without a restart; `auto_discover.exclude_patterns` (present in config since the start but never consulted) now actually drives interface selection. Verified against a real dummy NIC, including the kernel-event parsing and the interface-selection logic before/after the NIC exists.
- **F29, real threat-intel feed**: `internal/threatintel` replaces "the caller injects everything" with a real Spamhaus DROP blocklist fetch, local disk cache, and periodic background refresh that never blocks capture on a network fetch. `detect.ThreatIntel` gained CIDR-range matching (`BadCIDRs` + `MatchIP`) alongside the existing exact-match sets. Verified live: 1693 CIDR ranges fetched and cached.
- **F4, CoAP field decoding**: full RFC 7252 parsing (header, token, delta-encoded options — Uri-Path, Uri-Query, Content-Format, Observe, etc.) rather than protocol identification only.
- **eBPF ring buffer as the agent's capture source**: the CO-RE kernel program gained a raw-frame mode (`EVT_RAW_FRAME` + `CFG_RAW_FRAME_MODE`) that mirrors every packet's whole frame, wrapped by `internal/ebpf.OpenEBPF` into an ordinary `live.Source` structurally identical to AF_PACKET's. `internal/capsource` implements the fallback chain (eBPF → AF_PACKET → simulator); `internal/livesource` (the agent) uses it. Verified live on a real NIC with `connection_count` climbing in real time under `source: "ebpf"`.
- An **Acknowledgements** section in the README crediting the projects BeeEye's design leans on (Wireshark, [eCapture](https://github.com/gojue/ecapture), [Pcap-Analyzer](https://github.com/HatBoy/Pcap-Analyzer)) and the open-source libraries it runs on.
- **BeeEye-desktop**: a ~200-line Tauri 2 shell (`BeeEye-desktop/src-tauri`) that wraps the existing `BeeEye-gui` web UI in a native window for an operator's own desktop — connects to an already-running backend or spawns one itself, kills only the child it spawned on close. Duplicates no frontend code. Verified building to a working binary on the reference machine.

### Fixed

- A data race in `tcapture.Session`'s deadline-timer handling (`s.timer` assigned outside the lock the callback reads it under), caught by `go test -race` before it shipped.
- `api.Server`'s data-source and targeted-capture state (`SetSource`/`SetTargetedCapture`) could be read mid-update once the hot-plug supervisor started calling them more than once at runtime; both are now atomic-pointer swaps of an immutable snapshot instead of separate plain fields, so a concurrent reader never sees a torn combination.
- `dns.id` was registered as a display field twice with two different formats (decimal and `0x`-hex), so filtering/reading it back returned two values for one field; now registered once (hex, matching the tree's display value).

### Notes

- Discovered — not a bug to fix, but worth recording: on this host's kernel, TCX invokes only the *first* eBPF program attached to a given interface/direction; a second attach "succeeds" but is never actually called (confirmed via `bpftool prog show`'s `run_cnt`). Because of this, only the agent uses eBPF; the analyzer intentionally stays on AF_PACKET rather than the two competing for one NIC's hook.

## [1.0.0] — 2026-08-19

First tagged release. BeeEye is a home IoT gateway traffic analysis system: two
independent UIs (an always-on overview and a Wireshark-style live analyzer),
both driven by real packet capture, plus offline pcap analysis, eBPF/AF_PACKET
capture, CUDA-accelerated visualization, and a signal-based detection engine.

### Added

**Capture & kernel**
- eBPF CO-RE capture program (`BeeEye-agent/bpf/BeeEye.bpf.c`) attached via TCX on
  both directions, with a ringbuf event channel, an LRU flow table, and
  per-device category tuning (lock/camera get full-fidelity per-flow reporting,
  everything else gets aggregated snapshots).
- AF_PACKET raw-socket capture (`internal/live`, `internal/livesource`) as the
  default real-traffic source for both binaries — no libpcap, no CGO.
- `any` pseudo-interface: capture across every interface at once, with
  per-packet attribution back to the real interface name.
- Honest degradation: capture falls back to a built-in simulator only when raw
  capture is unavailable, and always says so in the startup log and analyzer
  status bar — never presented as real traffic (F43).
- `BeeEye-tlspeek` (`cmd/BeeEye-tlspeek`, `internal/tlspeek`): uprobe-based TLS
  plaintext capture against dynamically-linked OpenSSL processes, plus
  `scripts/tls-decrypt.sh` for `SSLKEYLOGFILE`-based decryption of
  Chromium/Electron apps. See `TLS-DECRYPT.md`.

**Protocol dissection & filtering**
- Layered protocol dissector: Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP plus
  DNS/mDNS/TLS/HTTP/MQTT/SSDP/DHCP application parsers.
- TLS fingerprinting: SNI, ALPN, and JA3 (GREASE-stripped per RFC 8701).
- Wireshark-compatible display-filter language (`internal/dfilter`): `&&`/`||`/`!`,
  comparisons, `contains`, `matches` (regexp), CIDR on address fields, bare
  protocol presence tests — the same parser drives both live validation and
  actual filtering, so there is no second syntax to drift out of sync.
- Filter template menu: ready-made protocol, IP, and other practical filter
  presets, applied immediately on selection.

**Detection engine**
- Nine weighted detection signals (`internal/detect`): threat-intel match,
  beaconing (C2-style heartbeat via interval coefficient of variation),
  fan-out/scanning, lateral (east-west) movement, DNS anomalies, geo anomalies,
  and off-hours activity, with configurable thresholds and high/medium/low
  severity banding.

**Attribution & mapping**
- Process attribution (`internal/procmap`): maps live flows to the owning
  local process via `/proc/net/{tcp,udp}` + `/proc/*/fd`, and correctly
  refuses to attribute another device's traffic to a local process.
- IP↔hostname/domain association (`internal/namemap`): learned live from DNS,
  TLS SNI, HTTP Host, and mDNS traffic, ranked by source confidence; no
  reverse-DNS lookups are ever issued (would leak destinations to a third
  party).
- Offline GeoIP (`internal/geoip`): fully offline lookups with correct
  private/CGNAT handling.

**Offline & live pcap analysis**
- pcap file reader (`internal/pcapfile`) and analysis engine (`internal/analyze`):
  protocol/talker/conversation statistics, TCP stream reassembly, plaintext
  credential extraction (FTP/POP3/IMAP/SMTP/HTTP Basic/HTTP form/Telnet),
  file carving by magic number, and heuristic attack-pattern detection
  (SQLi/XSS/traversal/cmdi/webshell/scanner/IoT exploit) — every finding is
  explicitly labeled `Heuristic: true`.
- `POST /api/pcap/upload` + report endpoints, backed by an in-memory-only
  store (reports can contain plaintext credentials, so nothing touches disk).
- Overview UI "Analysis" view modeled on Pcap-Analyzer: drag-and-drop upload,
  nine report tabs (summary, protocols, talkers, conversations, sessions,
  credentials, files, findings, geo), with explicit in-UI warnings that
  extracted credentials/files must be treated as compromised/untrusted.
- Same analysis engine wired into the live analyzer for real-time traffic.

**Visualization**
- CUDA-accelerated traffic-field rendering (`BeeEye-agent/cuda/BeeEye_render.cu`):
  hue-encodes protocol identity, brightness encodes magnitude, with a
  bit-identical Go CPU fallback (`internal/render`) when no GPU is present.
  Colorful, contrast-validated palette across the packet list, field tree,
  and traffic field (categorical + sequential palettes checked for CVD
  separation and contrast).
- Light/dark theme toggle in the live analyzer; six themes (light, dark,
  tech-blue, warm-amber, forest-green, high-contrast) in the overview UI.

**UI**
- Two independent frontends, two processes, two ports, sharing source at
  compile time and nothing at runtime (proven in `smoke.sh` by SIGSTOPping
  the analyzer and confirming the overview API still answers — F42).
- Full bilingual UI (English/Chinese) in both frontends via `react-i18next`,
  switchable instantly from the header.
- Live analyzer: three-pane packet list / protocol field tree / hex dump with
  synchronized selection and auto-expand on packet selection; sortable
  columns; auto-scroll as a persistent toggle (not a transient state);
  process-owner column; PCAP export (F44).
- Overview UI: seven views (overview, devices, connections, by-IP, by-protocol,
  DNS, alerts, analysis) plus Top-N rankings and CSV/JSON export with UTF-8 BOM.

**Deployment & docs**
- `start.sh` one-shot launcher, `scripts/dev.sh` (start/stop/restart/status/logs),
  `Makefile`, `docker-compose.yml`, and `scripts/smoke.sh` — 24 end-to-end
  checks covering both UIs, SSE streaming, filter validation, pcap export
  round-tripped through `tcpdump`, and process isolation.
- Bilingual documentation: `README.md`/`README.zh-CN.md`,
  `INSTALL.md`/`INSTALL.zh-CN.md`, `PROGRESS.md`/`PROGRESS.en.md`,
  `program.md`/`program.en.md`, plus `ARCHITECTURE.md`, `USAGE.md`, and
  `TLS-DECRYPT.md`.

### Fixed

- Packet detail pane stayed blank on selection: byte slices marshal as
  base64 over JSON; the frontend was treating the string as a byte array.
  Fixed with a proper `decodeBytes()` step.
- Language switch had no effect: i18next resolves `zh-CN` down to `zh` via
  `languageOnly`, but locale resources were keyed `zh-CN`, so every lookup
  silently fell back to English. Resources are now keyed `en`/`zh`.
- Protocol field tree stayed collapsed on selection instead of auto-expanding.
- Auto-scroll silently re-enabled itself on the next scroll event after being
  turned off; it is now a real toggle that persists across sessions and
  ignores the analyzer's own programmatic scrolling.
- Filter templates appeared to match nothing on a real LAN capture with no
  matching plaintext traffic; template selection now applies immediately, and
  the empty state now distinguishes "filter matched zero packets" from
  "nothing captured yet."
- Missing "any" interface option in the interface picker.
- Timestamps were not displayed in system wall-clock time.
- `dev.sh restart` intermittently failed with "address already in use"
  because stop returned before the process had actually exited; stop now
  polls for exit before allowing a restart.
- A four-color layer palette failed color-vision-deficiency validation
  (indistinguishable hues under protanopia); replaced with three validated
  hues plus a neutral grey, with text labels so color never carries identity
  alone.
- Kernel/userspace event struct layout could silently drift out of sync on a
  reordered C field; a BTF-driven layout test now fails the build if it does.

[中文变更日志 →](CHANGELOG.zh-CN.md)
