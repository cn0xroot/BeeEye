# 🐝 BeeEye

**Home IoT gateway traffic analysis — device fingerprinting, protocol dissection, and post-intrusion behaviour detection, built on eBPF.**

[Website](https://www.beeeye.dev/) · [中文](README.zh-CN.md) · [Install guide](INSTALL.md) · [Usage guide](USAGE.en.md) · [Architecture](ARCHITECTURE.md) · [Requirements & design](program.en.md) · [Implementation progress](PROGRESS.en.md) · [TLS decryption](TLS-DECRYPT.md) · [Changelog](CHANGELOG.md)

BeeEye runs on the Ubuntu box that already routes your home network. It attaches eBPF programs to the LAN-side interfaces, identifies every device that joins, and watches what those devices talk to — without installing an agent on a single camera, lock or phone, and without decrypting any of *their* traffic (the one deliberate exception is the gateway's own processes, decrypted locally and opt-in for other devices — see [Privacy](#privacy)).

## Screenshots

The live analyzer — same live capture, switched between its light/dark themes and English/Chinese, all without a reload:

| Light · English | Dark · English |
|---|---|
| ![Analyzer, light theme, English](PIC/analyzer-light-en.png) | ![Analyzer, dark theme, English](PIC/analyzer-dark-en.png) |

| Light · 中文 | Dark · 中文 |
|---|---|
| ![Analyzer, light theme, Chinese](PIC/analyzer-light-zh.png) | ![Analyzer, dark theme, Chinese](PIC/analyzer-dark-zh.png) |

---

## Two UIs, two processes

BeeEye ships two separate front ends because they answer genuinely different questions. They run as independent processes on independent ports with independent frontend bundles, and neither can take the other down.

| | Overview UI | Live analyzer |
|---|---|---|
| **URL** | http://localhost:8080 | http://localhost:8081 |
| **Binary** | `BeeEye-agent` | `BeeEye-gui` |
| **Audience** | everyone in the house | whoever is investigating |
| **Time scale** | hours to weeks | milliseconds |
| **Shows** | devices, alerts, by-IP / by-protocol views, traffic trends | Wireshark-style packet list, protocol field tree, hex dump |
| **Storage** | SQLite | nothing — analysis is in memory |
| **Data source** | ✅ **real AF_PACKET capture** | ✅ **real AF_PACKET capture** |

They share source packages at compile time and nothing at runtime.

> ### Both UIs show the same real network
>
> `BeeEye-agent` captures live traffic through `internal/livesource` — the same
> AF_PACKET capture the analyzer uses — so the overview and the analyzer now
> describe the same machine's real network (`192.168.x.x` here). Without
> raw-capture permission, or with `-simulate`, the agent falls back to the
> built-in simulated scenario and says so in its startup log; it never passes
> simulated flows off as real (F43). See [PROGRESS.en.md §0](PROGRESS.en.md).

---

## Requirements

| | Minimum | Notes |
|---|---|---|
| Kernel | Linux ≥ 5.8 with BTF | `/sys/kernel/btf/vmlinux` must exist. TCX attach needs ≥ 6.6. |
| Go | 1.25 | |
| clang | ≥ 11 | compiles the eBPF program |
| bpftool | any | generates `vmlinux.h` — `apt install linux-tools-$(uname -r)` |
| libbpf headers | any | `apt install libbpf-dev` |
| Node | ≥ 18 | builds the two frontends |
| CUDA toolkit | optional | GPU colour-field rendering; the CPU path is identical and always available |

---

## Quick start

```bash
./start.sh        # preflight, build whatever is stale, start both services
```

Then open **http://localhost:8080** (overview) and **http://localhost:8081** (analyzer).

`start.sh` checks the toolchain, regenerates `vmlinux.h` if it is missing, and
rebuilds only what is out of date — it compares sources against artifacts with
`find -newer`, and runs `npm install` only when the lockfile is newer than
`node_modules`. A second run starts in seconds.

```bash
./start.sh --dev        # also start the two Vite dev servers (HMR)
./start.sh stop|restart|status|logs
./start.sh --setcap     # grant capture capabilities, so root is not needed
./start.sh --rebuild    # rebuild everything, even if it looks up to date
./start.sh --iface eth0 # capture interface for the analyzer
```

With `--dev` you additionally get **http://localhost:5173** (overview UI with
hot reload, proxying `/api` to :8080) and **http://localhost:5174** (analyzer UI,
proxying to :8081). Those two are for working on the frontends; production
serves the built `dist/` from the Go binaries directly.

The individual `make` targets still exist if you want the steps separately —
`make bpf`, `make build`, `make frontends`, `make run`, `make smoke`. Logs from
either route land in `.run/`.

### Capturing real packets

Both the eBPF path and the analyzer's AF_PACKET socket need privileges. Without them **nothing fails** — the analyzer falls back to a synthetic trace and says so in its status bar, in as many words. It will never present simulated packets as a real capture.

To capture for real without running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+ep BeeEye-agent/bin/BeeEye-gui
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep BeeEye-agent/bin/BeeEye-agent
```

### Choosing interfaces

Interface names are never hardcoded. Edit `config/config.yaml`:

```yaml
interfaces:
  mode: explicit
  explicit_list:
    - name: wlan0
      role: wifi_ap
    - name: eth0
      role: wan_uplink
```

Attach to the **LAN-side** interface, not the WAN side — after NAT the device-level identity is gone. On a bridged setup attach the physical interfaces rather than the bridge, or the bridge alone; attaching both double-counts every packet.

---

## The live analyzer

Three panes, the layout Wireshark users already know: packet list on top, protocol field tree and hex dump below. Selecting a field highlights exactly its bytes.

**Every column sorts.** Click a heading to sort by it, click again to reverse, click a third time to return to capture order — which is a state of its own, and the only one in which a live capture keeps making sense as it grows. Addresses sort numerically rather than lexically (as text, `192.168.1.9` lands after `192.168.1.10`, which makes a sorted address column useless), and IPv4, IPv6 and MAC each form one contiguous block. Sorting releases auto-scroll, because following the tail means nothing once the list is not in capture order.

**Display filters** use a deliberate subset of Wireshark's syntax:

```
tcp.port == 443 && !mdns
ip.addr == 192.168.1.0/24 and dns.qry.name contains "tuya"
tls.handshake.extensions_server_name matches "^ota\."
dns.flags.rcode == 3 || (tcp.flags.syn == 1 && tcp.flags.ack == 0)
```

Supported: `&&` `||` `!` (also `and` `or` `not`), parentheses, `==` `!=` `>` `<` `>=` `<=`, `contains`, `matches` (regexp), CIDR on address fields, and a bare protocol name as a presence test. The filter box validates as you type against the server's own parser — there is one grammar, not two.

A **Templates** menu offers ready-made filters (by protocol, by address, investigation scenarios, noise reduction). Picking one ANDs it onto what you already have and leaves it editable.

> **One deliberate divergence from Wireshark:** here `a != b` means *no* value of `a` equals `b`. Wireshark's `!=` means *some* value differs, which makes `tcp.port != 443` true for every packet, since the other endpoint's port never is. `!(a == b)` is equivalent.

### Process attribution

Flows whose local endpoint is a socket **on the gateway itself** are attributed to the owning process (`/proc/net/*` → inode → `/proc/*/fd`, the same mechanism as `ss -p`).

Flows between other devices are shown as *not this host*, never as a guess. A packet carries no process identity; nothing recoverable at the gateway says which program on a camera sent it. For those flows the strongest identity available is the device itself.

### Traffic colour field

The band above the packet list is a live waterfall: one row per protocol, **hue carries identity and brightness carries magnitude**, so a burst of MQTT never looks like a burst of DNS.

It is rendered per pixel by a CUDA kernel (`BeeEye-agent/cuda/BeeEye_render.cu`) when built with `make build-cuda` on a machine with an NVIDIA GPU, and by an identical Go implementation otherwise. The status badge names whichever is actually running. The two are held to producing the same image by a test that renders both and compares them pixel by pixel.

---

## Make targets

```
./start.sh         one command: preflight + incremental build + start
./start.sh --dev   …plus the two Vite dev servers on :5173 / :5174

make help          list every target
make bpf           compile the eBPF program
make bpf-verify    load it to prove it passes the kernel verifier
make cuda          build the CUDA renderer
make build         build both binaries (CPU renderer)
make build-cuda    build the analyzer with CUDA linked in
make test          run the Go test suite
make test-cuda     also check the CUDA and CPU renderers still agree
make web           build the overview UI
make gui-web       build the analyzer UI
make run/stop/status
make smoke         end-to-end check of both services
make up/down       docker compose
```

---

## Layout

```
BeeEye-agent/            Go module — both binaries
  bpf/                   eBPF C source + the kernel↔userspace event contract
  cuda/                  CUDA colour-field renderer
  cmd/BeeEye-gui/        analyzer entry point
  internal/
    ebpf/                loads the kernel program, reads the ringbuf
    live/                capture sources: AF_PACKET, simulator, frame builders
    dissect/             protocol dissection → field tree + filter index
    dfilter/             the display-filter language
    procmap/             local-process attribution
    render/              colour field: CUDA and CPU backends
    gui/                 analyzer server (SSE, pcap export)
    api/                 overview REST API
    store/ detect/ identity/ protocol/ geoip/ model/ config/
BeeEye-web/              overview UI (React + Vite + i18next, 6 themes)
BeeEye-gui/              analyzer UI (React + Vite + i18next, light/dark)
config/                  config.yaml, port-service-map.yaml
scripts/                 dev.sh, smoke.sh
```

---

## Testing

```bash
make test           # unit tests
make test-cuda      # plus the GPU/CPU renderer agreement check
make bpf-verify     # prove the eBPF program passes the verifier
make smoke          # both services end to end
```

Notable checks, because they cover the things most likely to break silently:

- `internal/ebpf` reads the compiled object's **BTF** and compares the real struct offsets against the Go decoder's — a field reordered in the C header fails the build instead of producing garbage IPs.
- `internal/dissect` re-dissects **every prefix length** of a TLS ClientHello frame; snaplen truncation is routine on a real capture and must never panic.
- JA3 is checked for the property that makes it useful: stable across repeated handshakes from one client, different across differing cipher lists.
- `internal/procmap` verifies that another device's flow comes back **unattributed** rather than pinned on a coincidental local process.
- `internal/render` renders the same frame on the GPU and the CPU and compares them.

---

## Privacy

- GeoIP is looked up against a **local** database. Destination IPs are never sent to a third-party API one by one.
- Lock and camera events stay on the box. Nothing is uploaded anywhere.
- TLS on the wire is not decrypted. SNI, ALPN and JA3 come from the handshake, which is plaintext by design.
- **One deliberate exception, off by default and gateway-local only**: `BeeEye-tlspeek` (F14) can read the plaintext of TLS processes *running on the gateway itself* by attaching uprobes to their OpenSSL library — the same content, and the same set of processes, that `procmap` already attributes by name. It reaches nothing on a camera, a lock or a phone; those libraries run on their own hardware. It is a separate command that captures nothing until you start it and name a target, and it is the reason this line no longer says "TLS is not decrypted" without qualification. Design and scope: [TLS-DECRYPT.md](TLS-DECRYPT.md).
- Optional TLS decryption and MITM (program.md §3.10) are off by default and apply only to devices you can install a certificate on — which excludes the pinned IoT firmware this system exists to watch.
- The uprobe-based approach used by [eCapture](https://github.com/gojue/ecapture) runs into the same wall from the other side: it can only reach TLS libraries running on **this** kernel, so it would decrypt the gateway's own processes and nothing on a camera or a lock. The full evaluation, including what it is good for here, is in [TLS-DECRYPT.md](TLS-DECRYPT.md); its phase one — gateway-local plaintext capture in text mode — is implemented as `BeeEye-tlspeek` and covered by a test that decrypts a real TLS session.

---

## Status

This is under active development. [PROGRESS.en.md](PROGRESS.en.md) tracks every requirement (F1–F44) with its real state and the specific gaps, and is kept in sync with the code. [ARCHITECTURE.md](ARCHITECTURE.md) explains how the pieces fit together, with diagrams.

What works end to end today: both UIs, the REST API, the display-filter engine, the dissector, the detection engine, pcap export, and the CUDA/CPU colour field — `scripts/smoke.sh` checks 24 of those paths and all 24 pass. The agent captures live via AF_PACKET, falling back to the simulated scenario (announced) only without capture permission; wiring the eBPF ring buffer in as a lower-overhead source is the main remaining capture-path task (see the note above).

---

## Acknowledgements

BeeEye doesn't stand alone — its design leans directly on a few projects, and its code leans on the open-source libraries listed below.

**Design influences**

- **[Wireshark](https://www.wireshark.org/)** — the three-pane packet list / protocol field tree / hex dump layout, the display-filter grammar `internal/dfilter` implements a compatible subset of, and JA3/TLS field naming conventions all follow Wireshark's, deliberately, so the muscle memory transfers.
- **[eCapture](https://github.com/gojue/ecapture)** — the uprobe-based TLS plaintext capture design `BeeEye-tlspeek` (F14) follows the same shape eCapture pioneered (attach to a crypto library's read/write functions, no MITM, no cert on the target). Its module list is also the roadmap for BeeEye's own gaps: GoTLS, GnuTLS and NSS coverage, and combined pcap+keylog export are still open here (see [PROGRESS.en.md](PROGRESS.en.md) F14/F45) precisely because eCapture already proved each one is buildable. See [TLS-DECRYPT.md](TLS-DECRYPT.md) for where the two projects' scopes diverge (gateway-local only, here, on purpose).
- **[Pcap-Analyzer](https://github.com/HatBoy/Pcap-Analyzer)** — the shape of the offline-analysis view (protocol/talker/conversation stats, credential extraction, file carving, attack-pattern heuristics) that both `internal/analyze` and the overview UI's "Analysis" tab follow.

**Open-source libraries this code runs on**

| | Used for |
|---|---|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Go bindings for loading/attaching the eBPF CO-RE program and reading the ringbuf |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | pure-Go SQLite (no CGO) backing the overview's storage layer |
| [oschwald/geoip2-golang](https://github.com/oschwald/geoip2-golang) + [maxminddb-golang](https://github.com/oschwald/maxminddb-golang) | reading MaxMind-format `.mmdb` GeoIP databases, entirely offline |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | the raw AF_PACKET socket and RTNETLINK hot-plug watcher — no libpcap, no CGO |
| [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) | `config.yaml` / `port-service-map.yaml` parsing |
| [React](https://react.dev/) + [Vite](https://vitejs.dev/) | both frontend SPAs |
| [react-i18next](https://react.i18next.com/) / [i18next](https://www.i18next.com/) | the bilingual (EN/中文) UI in both frontends |
| [NVIDIA CUDA](https://developer.nvidia.com/cuda-toolkit) | optional GPU path for the traffic colour-field renderer — the CPU fallback is bit-compatible and always available |

And of course [Spamhaus](https://www.spamhaus.org/) for the DROP list `internal/threatintel` pulls threat-intel CIDR ranges from (F29), and the [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database format, if you choose to drop one into `data/` for more accurate geolocation than the built-in table.
