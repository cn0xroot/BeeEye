# BeeEye — Install & Usage Guide

> Covers installation, running both UIs day to day, TLS plaintext decryption (the
> gateway's own processes are decrypted automatically by default, plus an
> opt-in MITM mode for a phone or computer), accurate GeoIP, and appearance
> customization.
> Website: https://www.beeeye.dev/
> Requirements & design: [program.en.md](program.en.md) · Architecture: [ARCHITECTURE.md](ARCHITECTURE.md) · Progress: [PROGRESS.en.md](PROGRESS.en.md)
> 中文: [USAGE.md](USAGE.md)

**Last updated**: 2026-08-20

---

## Table of contents

1. [Five-minute start](#1-five-minute-start)
2. [Requirements & installation](#2-requirements--installation)
3. [start.sh reference](#3-startsh-reference)
4. [Granting capture permissions](#4-granting-capture-permissions)
5. [Configuration file](#5-configuration-file)
6. [Overview UI (:8080)](#6-overview-ui8080)
7. [Live analyzer (:8081)](#7-live-analyzer8081)
8. [Display filter syntax](#8-display-filter-syntax)
9. [TLS plaintext decryption](#9-tls-plaintext-decryption)
   - [9.1 Built-in analyzer decryption — on by default](#91-built-in-analyzer-decryption--on-by-default)
   - [9.2 Crypto library detection](#92-crypto-library-detection)
   - [9.3 The standalone CLI (BeeEye-tlspeek)](#93-the-standalone-cli-beeeye-tlspeek)
   - [9.4 Decrypting Chrome / AdsPower](#94-decrypting-chrome--adspower-the-sslkeylogfile-route)
   - [9.5 Opt-in MITM for a phone or computer](#95-opt-in-mitm-for-a-phone-or-computer)
   - [9.6 Offline pcap import & analysis](#96-offline-pcap-import--analysis)
10. [Dev mode & hot reload](#10-dev-mode--hot-reload)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Five-minute start

```bash
cd BeeEye
./start.sh              # preflight + incremental build + start both services
```

Then open:

| Address | What it is |
|---|---|
| http://localhost:8080 | **Overview UI** — devices, alerts, by-IP / by-protocol views, traffic trends |
| http://localhost:8081 | **Live analyzer** — Wireshark-style packet list + protocol tree + hex + colour field |

Stop: `./start.sh stop`　Status: `./start.sh status`　Logs: `./start.sh logs`

> **Data source**: both UIs now run on **real AF_PACKET capture** on this host, describing the same real network. Without capture permission, the agent runs with no capture pipeline and says so in the startup log — there is no simulated scenario to fall back to (F43). See [PROGRESS.en.md §0](PROGRESS.en.md).

---

## 2. Requirements & installation

### Dependencies

| | Minimum | Install |
|---|---|---|
| Kernel | Linux ≥ 5.8 with BTF | needs `/sys/kernel/btf/vmlinux`; TCX attach needs ≥ 6.6 |
| Go | 1.25 | https://go.dev/dl/ |
| clang | ≥ 11 | `apt install clang` |
| bpftool | any | `apt install linux-tools-common linux-tools-$(uname -r)` |
| libbpf headers | any | `apt install libbpf-dev` |
| Node | ≥ 18 | `apt install nodejs npm` |
| CUDA toolkit | optional | GPU colour-field rendering; falls back to CPU with an identical picture |

### Install

No separate install step — `start.sh` does the whole build on first run:

```bash
git clone <repo-url> && cd BeeEye
./start.sh
```

In order: checks the toolchain → generates `vmlinux.h` if missing (via bpftool) → compiles eBPF → builds both Go binaries → builds both frontends → starts the services. A second run rebuilds only what is stale and usually finishes in seconds.

To run the same steps by hand:

```bash
make bpf          # compile the eBPF program
make build        # build BeeEye-agent and BeeEye-gui
make frontends    # build both frontends (npm install + vite build)
make run          # start both services in the background
make smoke        # end-to-end check of every endpoint (24 checks)
```

---

## 3. start.sh reference

```
usage: ./start.sh [command] [options]

commands:
  start (default)  build anything stale, then start
  stop             stop the services (and the dev servers)
  restart          stop, then start
  status           show what is running
  logs             follow every log under .run/

options:
  --dev            also start the two Vite dev servers (HMR, :5173 / :5174)
  --rebuild        force a full rebuild
  --no-build       start whatever is already built; build nothing
  --iface NAME     the analyzer's capture interface (default: auto)
  --setcap         grant capture capabilities to the binaries (uses sudo)
  -h, --help       this text
```

**How the incremental build decides what's stale**: it compares source and artifact timestamps with `find -newer`; `npm install` only runs when `package-lock.json` is newer than `node_modules`, so a plain restart never pays for a full reinstall.

**Logs & pids**: all under `.run/` (`agent.log`, `gui.log`, plus `web.log`/`guiweb.log` with `--dev`) — they survive a restart.

---

## 4. Granting capture permissions

Both the eBPF path and the analyzer's AF_PACKET socket need privileges. Without them, that source simply cannot open — the analyzer's Start call returns the permission error outright rather than falling back to synthetic traffic. There is no simulated state left that could be presented as a real capture.

Real capture without root, one command:

```bash
./start.sh --setcap
```

Equivalent to:

```bash
sudo setcap cap_net_raw,cap_net_admin+ep         BeeEye-agent/bin/BeeEye-gui
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep BeeEye-agent/bin/BeeEye-agent
```

Then `./start.sh restart`. The analyzer status bar showing `Source: af_packet` and `real_capture: true` confirms real capture is live.

---

## 5. Configuration file

`config/config.yaml` drives the agent. Key fields:

```yaml
listen_addr: ":8080"          # overview API listen address

interfaces:
  mode: explicit              # explicit = only the interfaces below; auto = auto-discover
  explicit_list:
    - name: wlan0             # ⚠ change to your real NIC!
      role: wifi_ap           #    role decides access_type (wireless/wired)
    - name: eth0
      role: wan_uplink
  auto_discover:
    exclude_patterns: [lo, "docker*", "veth*", "br-*"]

detection:                    # detection-engine thresholds, all tunable
  beacon:
    min_samples: 6            # fewer samples than this: no beacon verdict
    cv_threshold: 0.15        # interval coefficient of variation; smaller = "more regular"
    min_interval_s: 10        # below this, treated as streaming, not a beacon
    max_interval_s: 3600
    window_min: 120           # sliding window (minutes)
  risk_thresholds:            # weighted-score grading
    high: 50
    medium: 30
    low: 15
  auto_block: false           # F38 automatic high-risk blocking, off by default

port_service_map_file: "./config/port-service-map.yaml"
```

> **Change the interface names** in `interfaces.explicit_list` — the shipped `wlan0` / `eth0` are placeholders; use `ip link` to find your real NIC (e.g. `wlp9s0`). Attach the **LAN-side** interface, not the WAN side — after NAT the device-level identity is gone.

### 5.1 GeoIP location accuracy

The default is the built-in coarse first-octet table — country-level approximation only. The overview **By IP** page header carries an accuracy badge:

| Badge | Meaning |
|---|---|
| ● precise (city + operator) | GeoLite2-City + ASN loaded — country/province/city/operator all accurate |
| ◐ country-only | a country-only database is loaded (e.g. Clash's `Country.mmdb`) — no province/city |
| ○ approximate | no mmdb found — using the built-in table |

**Upgrading to precise location**:

```bash
./scripts/geoip-setup.sh status                       # see what is currently loaded
./scripts/geoip-setup.sh fetch <MAXMIND_LICENSE_KEY>   # download GeoLite2-City + ASN into ./data
./start.sh restart
```

A free license key: https://www.maxmind.com/en/geolite2/signup . Downloading the database file itself does not violate the privacy requirement — once the file is on disk, every subsequent lookup is 100% local; visited IPs are never sent per-lookup to MaxMind or anyone else. This step is entirely optional; BeeEye works fine without it.

The program also auto-discovers `./data/`, `/usr/share/GeoIP/`, and a Clash `Country.mmdb` — no path needs to be given by hand. Check current status: `curl http://127.0.0.1:8080/api/geoip/status`.

---

## 6. Overview UI (:8080)

Seven-plus tabs, switchable from the header:

| Tab | Content |
|---|---|
| **Overview** | four cards (devices/connections/traffic/alerts); traffic trend chart; by-category/by-protocol/by-country breakdowns; alert list |
| **Devices** | each device's MAC/IP/vendor/category/access type/last seen; new devices get an Acknowledge button (F8) |
| **Connections** | connection-level log, searchable by any combination of device/IP/protocol/port range/time range (F30) |
| **By IP** | aggregated per IP: domain, geo, devices involved, protocols, ports, bytes (F25) |
| **By protocol** | aggregated per protocol (F26) |
| **DNS** | DNS query records and domain mapping (F21) |
| **Analysis** | import a pcap file for offline forensic analysis, see [§9.6](#96-offline-pcap-import--analysis) |
| **Certificate & decryption** | the opt-in phone/computer MITM decryption panel, see [§9.5](#95-opt-in-mitm-for-a-phone-or-computer) |
| **Alerts** | risk events, graded by severity; the red number on the tab is the high-severity count |

**Header controls**:
- **Sun / moon buttons** — quick light (paper beige) / dark theme toggle. Under "follow system" the button for whichever is actually showing lights up.
- **⚙ Settings panel** — click the gear icon for the full appearance panel:
  - **Theme**: 9 choices, each swatch previews its own palette live (Paper Beige, Deep Dark, **Midnight Neon**, **Matrix**, Tech Blue, Warm Amber, Forest Green, Follow System, High Contrast)
  - **Font**: System / Tech Mono / Rounded / Serif — each option's button renders in that font so you see it before picking
  - **Size**: S / M / L / XL — scales the whole page, icons and spacing included
  All three persist in the browser and survive a reload. The analyzer (:8081) has its own, parallel settings panel — theme/font/size are remembered independently on each side.
- **EN / 中文** — instant language switch, no page reload.

---

## 7. Live analyzer (:8081)

Three panes, the layout Wireshark users already know: packet list on top, protocol field tree bottom-left, hex dump bottom-right. Selecting a field highlights exactly its bytes.

### Top toolbar

| Control | Effect |
|---|---|
| **Interface** | pick the capture NIC; `any` captures every interface (recommended on a gateway) |
| **Promiscuous** | whether to put the NIC into promiscuous mode |
| **Start / Stop** | start/stop capture |
| **Export pcap** | export the current packets as pcap, opens in Wireshark/tcpdump (F44) |
| **Sun / moon** | beige / dark appearance toggle |
| **EN / 中文** | language switch |

### Display filter

The filter box below the toolbar validates against the **server's own parser** as you type: valid turns green, invalid turns red with the error. The `Templates` menu offers ready-made filters (by protocol, by address, investigation scenarios, noise reduction); picking one ANDs it onto what's already there and leaves it editable. Syntax in the next section.

### Packet list — click-to-sort columns

All eight columns (No. / Time / Source / Destination / Protocol / Process / Length / Info) **sort on click**, Wireshark-style:

- Click a heading → ascending; click again → descending; a third click → back to capture order
- **Addresses sort numerically**, not lexically (`192.168.1.9` never lands after `192.168.1.10`)
- IPv4 / IPv6 / MAC each form one contiguous block
- Packets with no local process sort to the bottom
- Sorting releases auto-scroll automatically (following the tail means nothing once the list is not in capture order)

### Auto-scroll

The **Auto-scroll** toggle by the packet list header controls whether it follows the newest packet. Turn it off to read history in peace — new data arriving will not yank your position away. Scrolling up turns it off automatically.

### Process attribution

The "Process" column: traffic on a local socket shows the owning process name+pid (e.g. `chrome 351980`); traffic between other devices shows `Not this host` (an honest blank, not a guess). **To see that local process's TLS plaintext, see §9.**

### Capture persistence (detail never goes missing)

The analyzer **persists the live capture to disk** as it runs (`/tmp/BeeEye/capture-*.pcap` by default). So clicking any packet's detail works even after it has been evicted from the in-memory ring — the raw bytes are read back from disk and re-dissected, instead of returning "That packet is no longer buffered".

- The in-memory ring keeps only the most recent ~20,000 packets (fast detail lookups); the disk files hold far more (512 MiB per file by default, current + previous kept, roughly hundreds of thousands of packets).
- The status bar / `/api/status`'s `capture_file` field shows the current save path.
- Standard pcap format — open directly in Wireshark/tcpdump.
- Flags (`cmd/BeeEye-gui`): `-capture-dir` (default `/tmp/BeeEye`, empty string disables it), `-capture-max-mb` (default 512); or the `BEEEYE_CAPTURE_DIR` env var.

### Traffic colour field

The live waterfall above the packet list: one row per protocol, **hue = identity, brightness = magnitude**. The badge in the top-right names the actual rendering backend (CUDA GPU or CPU).

---

## 8. Display filter syntax

A deliberately chosen subset of Wireshark's syntax:

```
tcp.port == 443 && !mdns
ip.addr == 192.168.1.0/24 and dns.qry.name contains "tuya"
tls.handshake.extensions_server_name matches "^ota\."
dns.flags.rcode == 3 || (tcp.flags.syn == 1 && tcp.flags.ack == 0)
```

| Category | Supported |
|---|---|
| Logic | `&&` `\|\|` `!` (also `and` `or` `not`), parentheses |
| Comparison | `==` `!=` `>` `<` `>=` `<=` |
| String | `contains`, `matches` (regexp) |
| Address | CIDR, e.g. `ip.addr == 10.0.0.0/8` |
| Presence | a bare protocol name, e.g. `tls`, `mqtt` |

> **The one deliberate divergence from Wireshark**: here `a != b` means *no* value of `a` equals `b`. Wireshark's `!=` means *some* value differs, which makes `tcp.port != 443` true for every packet (the other endpoint's port is never 443). Equivalent: `!(a == b)`.

---

## 9. TLS plaintext decryption

> Reference: the uprobe approach in [gojue/ecapture](https://github.com/gojue/ecapture). Full design and boundaries in [TLS-DECRYPT.md](TLS-DECRYPT.md).

### 9.1 Built-in analyzer decryption — on by default

**The analyzer (:8081) attaches decryption uprobes automatically on startup**, no extra action needed. It hooks the read/write functions of OpenSSL and GnuTLS, reading the plaintext buffer before encryption / after decryption.

| Target | Decryptable? |
|---|---|
| **Gateway-local processes dynamically linked against OpenSSL/GnuTLS** (curl, wget, git, apt, python, …) | ✅ yes, automatically |
| Chrome / AdsPower / Node (statically-linked, stripped BoringSSL) | ❌ see the SSLKEYLOGFILE route in §9.4 |
| Cameras / locks / TVs / phones | ❌ **no** — their TLS libraries run on their own hardware, out of reach of a local uprobe |

It is the content-level companion to the analyzer's process attribution: the set of processes it can decrypt is exactly the set the "Process" column names (rather than showing `Not this host`). Select a packet belonging to a local process and the "DECRYPTED PLAINTEXT" pane in the detail region shows that process's plaintext live.

> **Privacy**: this is the only BeeEye feature that reads application **content**. It is therefore deliberately scoped to gateway-local processes only, and needs an explicit capability to work (below); dropping the capability, or using the standalone CLI (§9.3) instead, behaves identically and stays fully under your control.

**Granting it** (the analyzer needs `cap_bpf,cap_perfmon`, included in the one-shot script):

```bash
./start.sh --setcap && ./start.sh restart
```

**Checking status**:

```bash
curl http://127.0.0.1:8081/api/decrypt          # {"enabled":true,"running":true,"attached":2}
curl http://127.0.0.1:8081/api/decrypt/libs     # each library's family/version/process count/attachability
```

Can also be toggled at runtime: `POST /api/decrypt {"enabled":false}` to turn it off, `{"enabled":true}` to turn it back on.

### 9.2 Crypto library detection

Before attaching, see what crypto libraries this host actually has, their versions, and whether each is attachable:

```bash
./BeeEye-agent/bin/BeeEye-tlspeek -detect
```

Example output (real machine):

```
supported families (rules): [OpenSSL GnuTLS]

OK   FAMILY    VERSION               PROCS       PATH
✓    GnuTLS    GnuTLS 3.8.3          72          /usr/lib/x86_64-linux-gnu/libgnutls.so.30.37.1
       uprobe decryption attaches to gnutls_record_send / gnutls_record_recv
✓    OpenSSL   OpenSSL 3.0.13        44          /usr/lib/x86_64-linux-gnu/libssl.so.3
       uprobe decryption attaches to SSL_write / SSL_read
```

`✓`/`✗` reports whether the ELF symbols exist (whether it can actually attach); the version is parsed from the library's own embedded version banner (different OpenSSL versions installed in different environments on the same machine are listed separately and do not interfere with each other).

**Crypto-library support is a declarative rule table** (`internal/tlspeek/rules.go`): one rule = a family name + a SONAME regex + the read/write function symbol names, matching across distros/versions by filename pattern (e.g. `libssl.so.3` and `libssl.so.1.1` both match the same rule). OpenSSL and GnuTLS are supported today; extending coverage to another library family is one rule contributed upstream.

### 9.3 The standalone CLI (BeeEye-tlspeek)

Besides the analyzer's built-in automatic decryption, the standalone CLI suits watching just one process, or capturing plaintext on its own without the analyzer running.

**Build & grant**:

```bash
make tlspeek                                              # build bin/BeeEye-tlspeek
sudo setcap cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-tlspeek   # grant it (no root)
```

**Usage**:

```bash
cd BeeEye-agent

# 1) see which processes are using an OpenSSL-family library
./bin/BeeEye-tlspeek -list

# 2) capture just one process (recommended, narrowest scope)
./bin/BeeEye-tlspeek -pid 12345

# 3) capture every process using a given library
./bin/BeeEye-tlspeek -lib /usr/lib/x86_64-linux-gnu/libssl.so.3

# 4) no target given: auto-picks the busiest library (prints which one)
./bin/BeeEye-tlspeek
```

| Flag | Meaning |
|---|---|
| `-list` | list OpenSSL-family libraries in use and their processes, then exit |
| `-pid N` | capture only process N |
| `-lib PATH` | the TLS library to attach to (default: auto-discover) |
| `-max N` | print the first N bytes of each chunk (default 512; up to 2047 is actually captured) |
| `-raw` | print raw bytes, without escaping non-printable characters |

### Sample output

Against a real `curl https://example.com`:

```
14:38:11.164 → curl  pid=598947  117B
PRI * HTTP/2.0

SM
...
14:38:11.461 ← curl  pid=598947  568B
...<!doctype html><html lang="en"><head><title>Example Domain</title>...
```

`→` is outbound (SSL_write, before encryption), `←` is inbound (SSL_read, after decryption). `(+N more)` means that call's data exceeded the capture cap and was truncated.

**Boundaries**:

- Covers the **OpenSSL** and **GnuTLS** families (rule table, §9.2). NSS and Go's `crypto/tls` are not covered.
- **Text mode only** (plaintext as-is). Keylog export and pcapng with an embedded key are later stages, see [TLS-DECRYPT.md](TLS-DECRYPT.md).
- A binary that statically links its own OpenSSL: `-pid` auto-discovery may find no separate library mapping — point `-lib` directly at the executable instead.

### 9.4 Decrypting Chrome / AdsPower (the SSLKEYLOGFILE route)

**Chrome and AdsPower cannot be decrypted by BeeEye-tlspeek** — they statically link a stripped BoringSSL into the main binary, with no `SSL_write`/`SSL_read` to hook. For these Chromium/Electron browsers, use the mechanism they already support: SSLKEYLOGFILE, via `scripts/tls-decrypt.sh`:

```bash
# one command: capture + launch Chrome + decrypt (needs root or CAP_NET_RAW to capture)
sudo ./scripts/tls-decrypt.sh capture --app chrome --url https://example.com/

# decrypt AdsPower: make sure it is not already running, let the script launch it
sudo ./scripts/tls-decrypt.sh capture --app adspower
#   → the script launches AdsPower; browse normally; closing the window triggers decryption

# point at any Chromium/Electron binary
sudo ./scripts/tls-decrypt.sh capture --app "/opt/AdsPower Global/adspower_global"

# re-decrypt a saved capture+keys pair (auto-picks the newest under .run/tls)
./scripts/tls-decrypt.sh decrypt
./scripts/tls-decrypt.sh decrypt --pcap some.pcap --keys some.log --filter http2
```

**Key precondition**: SSLKEYLOGFILE only covers TLS sessions started **after the script launches the browser**. An already-running Chrome that was not started with that variable set **cannot be decrypted retroactively**, by forward secrecy — the target must be launched or relaunched by the script.

**Output** (verified against a real Chrome):

```
── decrypted SNI ──
  clientservices.googleapis.com
  example.com
── decrypted HTTP/2 requests ──
  GET clientservices.googleapis.com /chrome-variations/seed?osname=linux&channel=stable...
── decrypted HTTP/2 responses ──
  302 text/html; charset=UTF-8 ClientMapServer
```

Capture and keys are saved under `.run/tls/` and can be opened in Wireshark any time (Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename, pointed at `keys-*.log`).

**Which path to use**:

| Target | Use |
|---|---|
| curl, dynamically-linked-OpenSSL services | `BeeEye-tlspeek` (live, chunk by chunk) |
| Chrome, AdsPower, Chromium, Electron, Firefox | `scripts/tls-decrypt.sh` (SSLKEYLOGFILE) |

Full comparison and rationale in [TLS-DECRYPT.md](TLS-DECRYPT.md).

### 9.5 Opt-in MITM for a phone or computer

Beyond decrypting the gateway's own processes, the overview UI offers an **opt-in** option: like Surge / Burp / mitmproxy, point some device's system proxy at BeeEye and see that device's own plaintext traffic. **Off by default**, because it requires installing a custom root certificate on the device — once installed, that device's HTTPS to anywhere is plaintext-visible at this hop, which is a trust decision the device's owner has to make deliberately.

**Turning it on** (edit `config/config.yaml`):

```yaml
mitm:
  enabled: true
  listen: ":8443"          # CONNECT proxy listen address
  ca_dir: "./data/mitm"    # root CA storage — auto-generated on first start
```

After `./start.sh restart`, open the overview UI's **Certificate & decryption** tab:

1. **Proxy address**: point that device's Wi-Fi / HTTPS proxy settings here (e.g. `192.168.1.1:8443`)
2. **Download the root cert**: PEM for Android/Windows, `.mobileconfig` for iOS/macOS (a one-tap install profile)
3. **Install per platform**: the page has an Android/iOS/macOS/Windows/Firefox table of "what to do by hand after installing the cert" (e.g. on iOS, after installing the profile you still have to go to Settings → General → About → Certificate Trust Settings and switch on full trust)
4. **Decrypted request list**: once the cert is installed and the proxy is configured, that device's HTTPS requests appear live in the table below, with a click-to-expand row showing the full request headers/response headers/response body

**It is fail-closed**: a device without this certificate installed simply fails to connect — never a silent fallback to plaintext passthrough.

**API**: `GET /api/mitm/status`, `GET /api/mitm/ca.pem`, `GET /api/mitm/ca.mobileconfig`, `GET /api/mitm/exchanges[/{id}]`. Decrypted records live only in an in-memory ring — **cleared on restart, never written to disk** — this is the most sensitive data this project ever handles.

> Difference from §9.1–9.4: those decrypt **the gateway's own processes** (no device cooperation needed); §9.5 decrypts **another device you have opted in** (that device must actively trust this proxy and certificate). The two serve different scenarios and neither replaces the other.

Full design and the four platforms' certificate-trust differences: [TLS-DECRYPT.md §5](TLS-DECRYPT.md).

### 9.6 Offline pcap import & analysis

Beyond live capture, the overview UI's **Analysis** tab can **import a pcap file for offline analysis** — drag in an exported capture, or one collected elsewhere, and it runs through the same engine as live analysis, producing a forensic-grade report.

**Usage**:
1. Open http://localhost:8080 → click **Analysis** in the header
2. Drag a `.pcap` file onto the upload area, or click to choose one
3. The report has nine tabs:
   - **Summary**: packet count, bytes, duration, unique IPs/MACs, link type
   - **Protocols**: share by protocol
   - **Talkers**: the biggest endpoints by traffic (with geo)
   - **Conversations**: five-tuple conversation stats
   - **Sessions**: reassembled application-layer sessions
   - **Credentials**: usernames/passwords found in plaintext protocols
   - **Files**: files carved out of the traffic, downloadable
   - **Security findings**: heuristically detected suspicious behaviour
   - **Geography**: destination geo distribution

**Relationship to live capture**: it runs the exact same `analyze` engine, so the same traffic reaches the same conclusions whether viewed live or imported later. Paired with the analyzer's **Export pcap** (F44), it forms an "export → deep offline analysis" loop. An uploaded file is analyzed in memory only, never written to disk.

Standard libpcap format is supported; pcapng needs converting first with `editcap -F pcap in.pcapng out.pcap`.

---

## 10. Dev mode & hot reload

When working on the frontends, use `--dev`:

```bash
./start.sh --dev
```

This additionally starts two Vite dev servers:

| Address | Serves | Proxies to |
|---|---|---|
| http://localhost:5173 | Overview UI (hot reload) | :8080 |
| http://localhost:5174 | Analyzer UI (hot reload) | :8081 |

A CSS/JSX edit applies instantly, no rebuild needed, and never interrupts a running capture. **Production does not need these two ports** — the Go binaries serve the built `dist/` directly.

---

## 11. Troubleshooting

| Symptom | Cause & fix |
|---|---|
| Overview has no devices/connections | the agent has no capture pipeline without capture permission (it never fabricates data). Grant it: `./start.sh --setcap` then `restart`; or confirm real traffic is passing through the NIC |
| Analyzer's Start call fails / `real_capture: false` after a running capture | no capture permission. Run `./start.sh --setcap` then `restart` |
| `./start.sh` reports a tool not found | install the named tool; `vmlinux.h` generation needs `bpftool` and a BTF-enabled kernel |
| 5173/5174 won't open | they only start with `--dev`; confirm you used `./start.sh --dev` |
| `BeeEye-tlspeek` reports a permission error | needs `cap_bpf,cap_perfmon`, see the grant command in §9.1/§9.3 |
| `BeeEye-tlspeek -list` can't find a process's library | that process may statically link OpenSSL — point `-lib` at its executable instead |
| Chrome/AdsPower won't attach with tlspeek | expected — they statically link a stripped BoringSSL. Use `scripts/tls-decrypt.sh` (SSLKEYLOGFILE) instead |
| `tls-decrypt.sh` produced an empty key log | the target browser was already running before the script launched it. Fully quit it first, then let the script start it |
| Changed the NIC but still no capture | confirm `config/config.yaml`'s interface name matches `ip link`, and that it is the LAN-side interface |
| Port already in use | `./start.sh stop`, then check `.run/*.pid`; clean up 8080/8081/5173/5174 by hand if needed |
| `/api/decrypt` shows `attached:0` | missing `cap_bpf,cap_perfmon`. Run `./start.sh --setcap` then `restart` |
| By IP page shows country only | expected without a City/ASN database. Run `./scripts/geoip-setup.sh fetch <key>`, see [§5.1](#51-geoip-location-accuracy) |
| MITM page's proxy doesn't work / phone can't connect | confirm `mitm.enabled: true` in `config/config.yaml` and `restart`; the proxy address must be one the device can reach — not `localhost` |
| Some app still shows a certificate error after installing the MITM cert | that app very likely does certificate pinning — it trusts only its own bundled certificate and no proxy can get in. Not a BeeEye bug; a designed boundary |

Verify everything is healthy:

```bash
make smoke        # end-to-end check of every endpoint on both services; expect 24 passed, 0 failed
```
