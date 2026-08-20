# Changelog

All notable changes to BeeEye are documented in this file.

[中文](CHANGELOG.zh-CN.md)

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
