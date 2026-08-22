# 蜂眼 BeeEye — 全新主机从零搭建指南

> 面向**一台全新、干净的 Linux 主机**，从系统依赖到跑起来的完整步骤。
> 官网：https://www.beeeye.dev/
> English: [INSTALL.md](INSTALL.md) · 使用手册：[USAGE.md](USAGE.md) · 架构：[ARCHITECTURE.md](ARCHITECTURE.md)

**最后更新**：2026-08-19

---

## 0. 环境要求一览

| 组件 | 最低要求 | 说明 |
|---|---|---|
| 操作系统 | Linux，内核 ≥ 5.8 且带 BTF | `/sys/kernel/btf/vmlinux` 必须存在；TCX 挂载需 ≥ 6.6 |
| 架构 | x86_64 / arm64 | eBPF 目标架构自动推导 |
| Go | ≥ 1.25 | 编译两个后端二进制 |
| clang | ≥ 11 | 编译 eBPF 程序 |
| bpftool | 任意 | 生成 `vmlinux.h` |
| libbpf 头文件 | 任意 | eBPF 编译依赖 |
| Node.js | ≥ 18 | 构建两个前端 |
| CUDA 工具链 | 可选 | 流量色场 GPU 渲染；无则走 CPU，画面相同 |
| tshark | 可选 | Chrome/AdsPower 的 SSLKEYLOGFILE 解密链路 |

---

## 1. 安装系统依赖（Ubuntu / Debian）

```bash
sudo apt update
sudo apt install -y \
  clang llvm libbpf-dev \
  linux-tools-common linux-tools-$(uname -r) \
  libcap2-bin \
  nodejs npm \
  git make curl \
  tshark            # 可选：浏览器 SSLKEYLOGFILE 解密

# 校验 bpftool 可用（linux-tools 提供）
bpftool version
```

> **其它发行版**：
> - Fedora/RHEL：`sudo dnf install clang llvm libbpf-devel bpftool nodejs npm make git`
> - Arch：`sudo pacman -S clang llvm libbpf bpf nodejs npm make git`

### 安装 Go（≥ 1.25）

系统仓库的 Go 往往偏旧，建议从官网装：

```bash
GO_VER=1.25.0
curl -fsSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -o /tmp/go.tgz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
export PATH=$PATH:/usr/local/go/bin
go version   # 应 ≥ go1.25
```

### （可选）CUDA 工具链

仅在有 NVIDIA 显卡、想用 GPU 渲染流量色场时需要。没有也能跑，自动回退 CPU：

```bash
# 参考 https://developer.nvidia.com/cuda-downloads
# 装好后确认：
/usr/local/cuda/bin/nvcc --version
```

---

## 2. 前置检查

```bash
# 内核必须带 BTF（CO-RE eBPF 的前提）
test -r /sys/kernel/btf/vmlinux && echo "BTF 可用" || echo "❌ 内核无 BTF，无法编译 CO-RE eBPF"

# 内核版本
uname -r    # 需 ≥ 5.8（TCX 需 ≥ 6.6）
```

若 `/sys/kernel/btf/vmlinux` 不存在，说明内核未开启 BTF —— 换一个带 `CONFIG_DEBUG_INFO_BTF=y` 的内核（主流发行版的通用内核默认都带）。

---

## 3. 获取并构建

```bash
git clone https://github.com/cn0xroot/BeeEye.git BeeEye
cd BeeEye

# 一键：预检工具链 → 生成 vmlinux.h → 编译 eBPF → 构建两个后端 → 构建两个前端 → 启动
./start.sh
```

`start.sh` 会自动完成全部构建。首次约需 1–3 分钟（含 `npm install`），之后只重建过期部分，几秒即起。

打开：
- **总览 UI**：http://localhost:8080
- **实时分析器**：http://localhost:8081

---

## 4. 授予抓包与解密权限（免 root）

不配权限也能跑（如实标注为「无数据」，不存在模拟数据兜底），但要抓真实流量和解密 HTTPS，需要授予 capability：

```bash
./start.sh --setcap
```

它等价于：

```bash
# 抓包（agent 的 eBPF + 分析器的 AF_PACKET）
sudo setcap cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-agent
sudo setcap cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-gui
# HTTPS 解密工具（uprobe）
sudo setcap cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-tlspeek
```

授权后 `./start.sh restart` 重启。分析器状态栏显示 `Source: af_packet` 即真实抓包生效；顶栏总览显示「● 实时」绿标。

> `cap_bpf,cap_perfmon` 是 HTTPS 默认解密（uprobe 挂 OpenSSL/GnuTLS）所需。

---

## 5. 配置网卡

编辑 `config/config.yaml`，把接口名改成本机真实网卡（用 `ip link` 查看）：

```yaml
interfaces:
  mode: explicit
  explicit_list:
    - name: wlan0        # ← 改成你的真实网卡
      role: wifi_ap
```

挂 **LAN 侧**而非 WAN 侧 —— 经 NAT 后设备级身份就没了。若配置里的网卡本机不存在，程序会自动回退到默认路由网卡，而不是对一张根本不存在的网卡静默报告"无数据"。

---

## 6. 验证安装

```bash
make smoke          # 端到端检查两个服务的每个端点，应输出 24 passed, 0 failed
make test           # Go 单元测试
```

也可手动检查四个端口（`--dev` 模式下才有 5173/5174）：

```bash
./start.sh --dev
for p in 8080 8081 5173 5174; do
  printf "%s: " $p; curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:$p/
done
```

---

## 7. （可选）GeoIP 数据库：准确的省/市/运营商

默认用内置粗表（仅国家级近似）。要显示准确的**省/市/运营商**，把 MaxMind 格式数据库放进 `./data/`：

```bash
mkdir -p data
# 需自备（MaxMind 需注册；GeoCN 面向中国）：
#   data/GeoLite2-City.mmdb   → 国家/省/市
#   data/GeoLite2-ASN.mmdb    → 运营商/ASN
#   data/GeoCN.mmdb           → 中国境内更细
```

程序启动时自动发现 `./data/`、`/usr/share/GeoIP/` 以及 Clash 的 `Country.mmdb`。全部离线查询，绝不向第三方在线接口逐个发送 IP（隐私要求）。

---

## 8. （可选）解密浏览器 HTTPS（Chrome / AdsPower / Node）

默认的 uprobe 解密覆盖**动态链接 OpenSSL/GnuTLS 的进程**（curl、wget、git、apt、python 等）。Chrome、AdsPower、Node 静态链接 strip 过的 BoringSSL，用 SSLKEYLOGFILE 路径：

```bash
# 一条命令：抓包 + 启动浏览器 + 解密（需 root 或 CAP_NET_RAW 抓包）
sudo ./scripts/tls-decrypt.sh capture --app chrome --url https://example.com/
sudo ./scripts/tls-decrypt.sh capture --app adspower

# 检测本机哪些加密库可被 uprobe 解密：
./BeeEye-agent/bin/BeeEye-tlspeek -detect
```

详见 [TLS-DECRYPT.md](TLS-DECRYPT.md) 与 [USAGE.md](USAGE.md) 第 9 节。

---

## 9. 常见问题

| 现象 | 解决 |
|---|---|
| `/sys/kernel/btf/vmlinux missing` | 内核未开 BTF，换通用内核 |
| `bpftool: command not found` | `apt install linux-tools-$(uname -r)` |
| `go: command not found` 或版本过旧 | 按 §1 从官网装 Go ≥ 1.25 |
| 分析器点 Start 报权限错误 | 无抓包权限，跑 `./start.sh --setcap` 后 `restart` |
| 总览无设备/连接 | 同上；或确认网卡上有真实流量 |
| HTTPS 解密 `attached:0` | 缺 `cap_bpf,cap_perfmon`，见 §4 |
| 5173/5174 打不开 | 它们只在 `./start.sh --dev` 时启动 |
| 端口被占用 | `./start.sh stop`，必要时手动清理 8080/8081/5173/5174 |

---

## 10. 本机测试环境（本文档验证所依据的真实环境）

以下是本项目实际开发与测试的主机配置，供对照参考：

### 硬件

| 项 | 配置 |
|---|---|
| CPU | AMD Ryzen 9 9950X（16 核 32 线程，x86_64） |
| 内存 | 61 GiB |
| GPU | NVIDIA GeForce RTX 2080 Ti（11 GiB 显存，驱动 580.173.02） |

### 软件

| 组件 | 版本 |
|---|---|
| 操作系统 | Ubuntu 24.04.4 LTS |
| 内核 | 7.0.0-28-generic（BTF 可用） |
| Go | go1.26.4 |
| clang | 18.1.3 |
| bpftool | v7.7.0 |
| Node.js / npm | v22.17.1 / 10.9.2 |
| CUDA (nvcc) | release 12.8, V12.8.93 |
| tshark | 4.2.2 |

### 该环境下的实测结果

- `make smoke`：**24 项全过，0 失败**
- 流量色场渲染后端：**CUDA（RTX 2080 Ti）**，与 CPU 实现逐像素一致（最大偏差 1/255）
- 实时抓包：`wlp9s0` 上 AF_PACKET，`kernel_drops: 0`
- HTTPS 解密：默认挂载 **2 个加密库**（OpenSSL + GnuTLS），实时解密 curl/wget 等明文
- 加密库检测：44 进程用 OpenSSL、30 进程用 GnuTLS，均 ✓ 可挂载

> 注：内核显示为 `7.0.0`（该主机所用的自定义/较新内核）；项目对内核的实际下限是 5.8（带 BTF），TCX 挂载需 6.6。
