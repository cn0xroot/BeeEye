# Changelog

All notable changes to BeeEye are documented in this file.

[中文](CHANGELOG.zh-CN.md)

## [Unreleased]

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
