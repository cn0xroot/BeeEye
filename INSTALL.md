# BeeEye — Setup on a Fresh Host

> A complete, from-scratch guide for **a brand-new, clean Linux machine** — from
> system dependencies to a running stack.
> 中文：[INSTALL.zh-CN.md](INSTALL.zh-CN.md) · Usage: [USAGE.md](USAGE.md) · Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)

**Last updated**: 2026-08-19

---

## 0. Requirements at a glance

| Component | Minimum | Notes |
|---|---|---|
| OS | Linux, kernel ≥ 5.8 with BTF | `/sys/kernel/btf/vmlinux` must exist; TCX attach needs ≥ 6.6 |
| Arch | x86_64 / arm64 | eBPF target arch is derived, not assumed |
| Go | ≥ 1.25 | builds the two backend binaries |
| clang | ≥ 11 | compiles the eBPF program |
| bpftool | any | generates `vmlinux.h` |
| libbpf headers | any | eBPF build dependency |
| Node.js | ≥ 18 | builds the two frontends |
| CUDA toolkit | optional | GPU colour-field rendering; the CPU path is identical |
| tshark | optional | the SSLKEYLOGFILE decryption path for Chrome/AdsPower |

---

## 1. Install system dependencies (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y \
  clang llvm libbpf-dev \
  linux-tools-common linux-tools-$(uname -r) \
  libcap2-bin \
  nodejs npm \
  git make curl \
  tshark            # optional: browser SSLKEYLOGFILE decryption

bpftool version     # confirm bpftool is available
```

> **Other distributions**:
> - Fedora/RHEL: `sudo dnf install clang llvm libbpf-devel bpftool nodejs npm make git`
> - Arch: `sudo pacman -S clang llvm libbpf bpf nodejs npm make git`

### Install Go (≥ 1.25)

Distro packages are often too old; install from upstream:

```bash
GO_VER=1.25.0
curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tgz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
export PATH=$PATH:/usr/local/go/bin
go version   # should be ≥ go1.25
```

### (Optional) CUDA toolkit

Only needed for GPU rendering of the traffic colour field on an NVIDIA machine.
Everything runs without it, falling back to the identical CPU renderer:

```bash
# see https://developer.nvidia.com/cuda-downloads, then confirm:
/usr/local/cuda/bin/nvcc --version
```

---

## 2. Preflight checks

```bash
# The kernel must ship BTF (the prerequisite for CO-RE eBPF)
test -r /sys/kernel/btf/vmlinux && echo "BTF present" || echo "no BTF — cannot build CO-RE eBPF"

uname -r    # need ≥ 5.8 (TCX needs ≥ 6.6)
```

If `/sys/kernel/btf/vmlinux` is missing, the kernel was built without BTF — use a
kernel with `CONFIG_DEBUG_INFO_BTF=y` (the generic kernels of mainstream distros
have it by default).

---

## 3. Clone and build

```bash
git clone <repo-url> BeeEye
cd BeeEye

# One command: preflight → generate vmlinux.h → compile eBPF → build both
# backends → build both frontends → start.
./start.sh
```

`start.sh` performs every build step. The first run takes ~1–3 minutes (including
`npm install`); later runs rebuild only what is stale and start in seconds.

Open:
- **Overview UI**: http://localhost:8080
- **Live analyzer**: http://localhost:8081

---

## 4. Grant capture & decryption capabilities (no root)

It runs without privileges (falling back to labelled simulated data), but real
capture and HTTPS decryption need capabilities:

```bash
./start.sh --setcap
```

which is equivalent to:

```bash
# capture (the agent's eBPF + the analyzer's AF_PACKET)
sudo setcap cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-agent
sudo setcap cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-gui
# HTTPS decryption tool (uprobes)
sudo setcap cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-tlspeek
```

Then `./start.sh restart`. The analyzer status bar shows `Source: af_packet` when
real capture is live; the overview header shows a green "● live" badge.

> `cap_bpf,cap_perfmon` is what the default HTTPS decryption (uprobes on
> OpenSSL/GnuTLS) needs.

---

## 5. Configure the interface

Edit `config/config.yaml` and set the interface names to this host's real NICs
(`ip link` lists them):

```yaml
interfaces:
  mode: explicit
  explicit_list:
    - name: wlan0        # ← change to your real NIC
      role: wifi_ap
```

Attach to the **LAN-side** interface, not the WAN side — after NAT the
device-level identity is gone. If a configured interface does not exist, the
program falls back to the default-route NIC rather than silently dropping to
simulated data.

---

## 6. Verify the install

```bash
make smoke          # end-to-end check of every endpoint; expect 24 passed, 0 failed
make test           # Go unit tests
```

Or check the ports by hand (5173/5174 exist only in `--dev` mode):

```bash
./start.sh --dev
for p in 8080 8081 5173 5174; do
  printf "%s: " $p; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:$p/
done
```

---

## 7. (Optional) GeoIP database: accurate province / city / operator

The default is a coarse built-in table (country-level approximation). For
accurate **province / city / network operator**, drop MaxMind-format databases
into `./data/`:

```bash
mkdir -p data
#   data/GeoLite2-City.mmdb   → country / province / city
#   data/GeoLite2-ASN.mmdb    → operator / ASN
#   data/GeoCN.mmdb           → finer detail inside China
```

They are auto-discovered from `./data/`, `/usr/share/GeoIP/`, and a Clash
`Country.mmdb`. Every lookup is offline — no per-IP calls to any third-party
online service (a privacy requirement).

---

## 8. (Optional) Decrypt browser HTTPS (Chrome / AdsPower / Node)

The default uprobe decryption covers **dynamically-linked OpenSSL/GnuTLS
processes** (curl, wget, git, apt, python, …). Chrome, AdsPower and Node
static-link a stripped BoringSSL, so use the SSLKEYLOGFILE path:

```bash
# one command: capture + launch browser + decrypt (needs root or CAP_NET_RAW)
sudo ./scripts/tls-decrypt.sh capture --app chrome --url https://example.com/
sudo ./scripts/tls-decrypt.sh capture --app adspower

# detect which crypto libraries on this host are uprobe-decryptable:
./BeeEye-agent/bin/BeeEye-tlspeek -detect
```

See [TLS-DECRYPT.md](TLS-DECRYPT.md) and [USAGE.md](USAGE.md) §9.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `/sys/kernel/btf/vmlinux missing` | kernel lacks BTF; use a generic kernel |
| `bpftool: command not found` | `apt install linux-tools-$(uname -r)` |
| `go: command not found` / too old | install Go ≥ 1.25 from upstream (§1) |
| analyzer shows "simulated" | no capture permission; `./start.sh --setcap` then `restart` |
| overview has no devices/connections | same as above; or confirm real traffic on the NIC |
| HTTPS decryption `attached:0` | missing `cap_bpf,cap_perfmon` (§4) |
| 5173/5174 won't open | they start only with `./start.sh --dev` |
| port already in use | `./start.sh stop`; clean up 8080/8081/5173/5174 if needed |

---

## 10. Reference test environment

The host this project is actually developed and tested on, for comparison:

### Hardware

| Item | Spec |
|---|---|
| CPU | AMD Ryzen 9 9950X (16 cores / 32 threads, x86_64) |
| Memory | 61 GiB |
| GPU | NVIDIA GeForce RTX 2080 Ti (11 GiB, driver 580.173.02) |

### Software

| Component | Version |
|---|---|
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 7.0.0-28-generic (BTF present) |
| Go | go1.26.4 |
| clang | 18.1.3 |
| bpftool | v7.7.0 |
| Node.js / npm | v22.17.1 / 10.9.2 |
| CUDA (nvcc) | release 12.8, V12.8.93 |
| tshark | 4.2.2 |

### Measured results on this environment

- `make smoke`: **24 passed, 0 failed**
- Colour-field backend: **CUDA (RTX 2080 Ti)**, pixel-identical to the CPU path (worst delta 1/255)
- Live capture: AF_PACKET, `kernel_drops: 0`
- HTTPS decryption: **2 crypto libraries** attached by default (OpenSSL + GnuTLS), decrypting curl/wget plaintext live
- Crypto-library detection: 44 processes on OpenSSL, 30 on GnuTLS, both ✓ attachable

> Note: the kernel reads as `7.0.0` (a newer/custom kernel on this host); the
> project's actual floor is 5.8 with BTF, and TCX attach needs 6.6.
