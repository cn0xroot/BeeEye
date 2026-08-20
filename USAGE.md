# 蜂眼 BeeEye — 安装与使用手册

> 本手册覆盖安装、运行、两个 UI 的日常使用，以及 TLS 明文解密。
> 需求与设计见 [program.md](program.md)，架构见 [ARCHITECTURE.md](ARCHITECTURE.md)，进度见 [PROGRESS.md](PROGRESS.md)。
> English README: [README.md](README.md) · 中文 README: [README.zh-CN.md](README.zh-CN.md)

**最后更新**：2026-08-19

---

## 目录

1. [五分钟上手](#1-五分钟上手)
2. [环境要求与安装](#2-环境要求与安装)
3. [一键脚本 start.sh 详解](#3-一键脚本-startsh-详解)
4. [抓真实的包（权限配置）](#4-抓真实的包权限配置)
5. [配置文件](#5-配置文件)
6. [总览 UI（:8080）用法](#6-总览-ui8080用法)
7. [实时分析器（:8081）用法](#7-实时分析器8081用法)
8. [显示过滤器语法](#8-显示过滤器语法)
9. [TLS 明文解密（BeeEye-tlspeek）](#9-tls-明文解密beeeye-tlspeek)
10. [开发模式与热更新](#10-开发模式与热更新)
11. [故障排查](#11-故障排查)

---

## 1. 五分钟上手

```bash
cd BeeEye
./start.sh              # 预检工具链 + 增量构建 + 启动两个服务
```

然后浏览器打开：

| 地址 | 是什么 |
|---|---|
| http://localhost:8080 | **总览 UI** —— 设备、告警、按 IP / 按协议视图、流量趋势 |
| http://localhost:8081 | **实时分析器** —— Wireshark 式包列表 + 协议树 + 十六进制 + 流量色场 |

停止：`./start.sh stop`　查看状态：`./start.sh status`　跟日志：`./start.sh logs`

> **数据来源**：两个 UI 现在都基于**本机真实 AF_PACKET 抓包**，描述同一个真实网络。无抓包权限或加 `-simulate` 时 agent 回退到模拟场景并在启动日志标注（F43）。详见 [PROGRESS.md §0](PROGRESS.md)。

---

## 2. 环境要求与安装

### 依赖

| | 最低版本 | 安装 |
|---|---|---|
| 内核 | Linux ≥ 5.8 且带 BTF | 需 `/sys/kernel/btf/vmlinux`；TCX 挂载需 ≥ 6.6 |
| Go | 1.25 | https://go.dev/dl/ |
| clang | ≥ 11 | `apt install clang` |
| bpftool | 任意 | `apt install linux-tools-common linux-tools-$(uname -r)` |
| libbpf 头文件 | 任意 | `apt install libbpf-dev` |
| Node | ≥ 18 | `apt install nodejs npm` |
| CUDA 工具链 | 可选 | GPU 色场渲染；无则自动走 CPU，画面完全相同 |

### 安装

不需要单独的安装步骤 —— `start.sh` 会在首次运行时完成所有构建：

```bash
git clone <仓库地址> && cd BeeEye
./start.sh
```

它会依次：检查工具链 → 缺 `vmlinux.h` 时用 bpftool 生成 → 编译 eBPF → 构建两个 Go 二进制 → 构建两个前端 → 启动服务。第二次运行只重建过期的部分，通常几秒完成。

如果你想手动分步（等价于 `start.sh` 做的事）：

```bash
make bpf          # 编译 eBPF 程序
make build        # 构建 BeeEye-agent 与 BeeEye-gui
make frontends    # 构建两个前端（npm install + vite build）
make run          # 后台启动两个服务
make smoke        # 端到端验证每个端点（24 项）
```

---

## 3. 一键脚本 start.sh 详解

```
用法: ./start.sh [命令] [选项]

命令：
  start（默认）   构建过期部分，然后启动服务
  stop            停止服务（含开发服务器）
  restart         先停后起
  status          显示运行状态
  logs            跟踪 .run/ 下所有日志

选项：
  --dev           额外启动两个 Vite 开发服务器（热更新，:5173 / :5174）
  --rebuild       强制全量重建
  --no-build      只启动已构建的产物，不构建
  --iface 网卡名  分析器的抓包网卡（默认自动选默认路由网卡）
  --setcap        给二进制授予抓包 capability（用 sudo）
  -h, --help      帮助
```

**增量构建怎么判断**：用 `find -newer` 对比源码与产物的时间戳，只重建真正过期的部分；`npm install` 只在 `package-lock.json` 比 `node_modules` 新时才跑，避免每次启动白等 install。

**日志与 pid**：都在 `.run/` 下（`agent.log`、`gui.log`，`--dev` 时还有 `web.log`、`guiweb.log`），重启不丢。

---

## 4. 抓真实的包（权限配置）

eBPF 路径和分析器的 AF_PACKET 套接字都需要权限。**没有权限也不会失败** —— 分析器会回退到合成流量，并在状态栏用明确文字标注「模拟」。它永远不会把模拟包当作真实抓包呈现。

不用 root 也能真实抓包，一条命令搞定：

```bash
./start.sh --setcap
```

它等价于：

```bash
sudo setcap cap_net_raw,cap_net_admin+ep         BeeEye-agent/bin/BeeEye-gui
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep BeeEye-agent/bin/BeeEye-agent
```

授权后 `./start.sh restart` 重启即可。分析器状态栏出现 `Source: af_packet` 且 `real_capture: true` 表示真实抓包生效。

---

## 5. 配置文件

`config/config.yaml` 控制 agent 的行为。关键项：

```yaml
listen_addr: ":8080"          # 总览 API 监听地址

interfaces:
  mode: explicit              # explicit=只采集下列接口；auto=自动发现
  explicit_list:
    - name: wlan0             # ⚠ 改成你本机真实网卡名！
      role: wifi_ap           #    role 决定 access_type（wireless/wired）
    - name: eth0
      role: wan_uplink
  auto_discover:
    exclude_patterns: [lo, "docker*", "veth*", "br-*"]

detection:                    # 检测引擎阈值，全部可调
  beacon:
    min_samples: 6            # 少于该样本数不做信标判定
    cv_threshold: 0.15        # 间隔变异系数阈值，越小越"规律"
    min_interval_s: 10        # 低于此间隔视为流式，不算信标
    max_interval_s: 3600
    window_min: 120           # 滑动窗口（分钟）
  risk_thresholds:            # 加权评分分级
    high: 50
    medium: 30
    low: 15
  auto_block: false           # F38 高危自动阻断，默认关闭仅告警

simulate_seed: 42             # 模拟场景的随机种子（可复现）
port_service_map_file: "./config/port-service-map.yaml"
```

> **务必修改** `interfaces.explicit_list` 里的网卡名 —— 默认写的是 `wlan0` / `eth0`，用 `ip link` 查你本机真实网卡（如 `wlp9s0`）。挂 **LAN 侧**而非 WAN 侧：经过 NAT 后设备级身份就没了。

---

## 6. 总览 UI（:8080）用法

七个页签，顶栏可切换：

| 页签 | 内容 |
|---|---|
| **Overview 总览** | 设备数、连接数、流量、告警四张卡片；流量趋势折线；按设备类别 / 按协议 / 按国家三张分布图；告警列表 |
| **Devices 设备** | 每台设备的 MAC / IP / 厂商 / 类别 / 接入方式 / 最后出现时间；新设备有「确认」按钮（F8） |
| **Connections 连接** | 连接级流水，支持按设备 / IP / 协议 / 端口范围 / 时间范围任意组合检索（F30） |
| **By IP 按 IP** | 以 IP 为中心聚合：域名、地理、涉及设备、协议、端口、字节数（F25） |
| **By protocol 按协议** | 以协议为中心聚合（F26） |
| **DNS** | DNS 查询记录与域名映射（F21） |
| **Alerts 告警** | 风险事件，按严重度分级；页签上的红色数字是高危事件数 |

**顶栏控件**：
- **日 / 月按钮** —— 浅色（米黄纸感）/ 深色主题切换。跟随系统时会高亮当前实际生效的一侧。
- **EN / 中文** —— 语言即时切换，不刷新页面。

---

## 7. 实时分析器（:8081）用法

三窗格布局，Wireshark 用户熟悉：上方包列表，下方左协议字段树、右十六进制。选中一个字段会精确高亮它对应的字节。

### 顶部工具栏

| 控件 | 作用 |
|---|---|
| **Interface 接口** | 选择抓包网卡；`any` 抓所有接口（网关推荐） |
| **Promiscuous 混杂** | 是否置网卡为混杂模式 |
| **开始 / 停止** | 启停抓包 |
| **Export pcap** | 导出当前包为 pcap，可用 Wireshark/tcpdump 打开（F44） |
| **日 / 月** | 米黄 / 深色外观切换 |
| **EN / 中文** | 语言切换 |

### 显示过滤器

工具栏下方的过滤框在你输入时就用**服务端解析器**实时校验：合法转绿、非法转红并给出错误。`Templates 模板` 菜单提供现成过滤器（按协议、按地址、排查场景、降噪），选中会与当前表达式取 AND 并保持可编辑。语法见下一节。

### 包列表 —— 列点选排序

八列（序号 / 时间 / 源地址 / 目标地址 / 协议 / 进程 / 长度 / 摘要）**全部可点排序**，仿 Wireshark：

- 点表头 → 按该列升序；再点 → 降序；第三次 → 回到抓包顺序
- **地址按数值排**，不按字典序（`192.168.1.9` 不会排到 `192.168.1.10` 后面）
- IPv4 / IPv6 / MAC 各自成一整块
- 无本机进程的包沉底
- 一旦排序，自动滚动自动释放（列表不在抓包顺序时跟随末尾没有意义）

### 自动滚动

包列表标题旁的 **Auto-scroll** 开关控制是否跟随最新包。关闭后可以安心翻看历史，新数据到达不会把你看的位置顶走。向上滚动会自动关闭它。

### 进程归属

「进程」列：本机 socket 的流量会显示持有它的进程名+pid（如 `chrome 351980`）；其他设备之间的流量显示 `Not this host`（诚实留白，而不是猜）。**想看这些本机进程的 TLS 明文，见第 9 节。**

### 抓包持久化（详情不丢失）

分析器启动时会把实时抓包**持久化到磁盘**（默认 `/tmp/BeeEye/capture-*.pcap`）。这样点开任意一个包看详情时，即使它已经被内存环形缓冲淘汰，也能从磁盘读回原始字节重新解剖，而不再报 "That packet is no longer buffered"。

- 内存环只保留最近约 2 万个包（详情快），磁盘文件保留得多得多（默认每文件 512 MiB、保留当前+上一个共两份，约数十万包）。
- 状态栏/`/api/status` 的 `capture_file` 字段显示当前保存路径。
- 保存的是标准 pcap，可直接用 Wireshark/tcpdump 打开。
- 相关参数（`cmd/BeeEye-gui`）：`-capture-dir`（默认 `/tmp/BeeEye`，设为空字符串关闭）、`-capture-max-mb`（默认 512）；或环境变量 `BEEEYE_CAPTURE_DIR`。

### 流量色场

包列表上方的实时瀑布图：每协议一行，**色相=身份、亮度=量级**。右上角徽章标明实际渲染后端（CUDA GPU 或 CPU）。

---

## 8. 显示过滤器语法

Wireshark 语法的一个有意子集：

```
tcp.port == 443 && !mdns
ip.addr == 192.168.1.0/24 and dns.qry.name contains "tuya"
tls.handshake.extensions_server_name matches "^ota\."
dns.flags.rcode == 3 || (tcp.flags.syn == 1 && tcp.flags.ack == 0)
```

| 类别 | 支持 |
|---|---|
| 逻辑 | `&&` `\|\|` `!`（或 `and` `or` `not`）、括号 |
| 比较 | `==` `!=` `>` `<` `>=` `<=` |
| 字符串 | `contains`、`matches`（正则） |
| 地址 | CIDR，如 `ip.addr == 10.0.0.0/8` |
| 存在性 | 裸协议名，如 `tls`、`mqtt` |

> **与 Wireshark 唯一的有意分歧**：这里 `a != b` 表示*没有任何* `a` 等于 `b`。Wireshark 的 `!=` 表示*存在某个*值不等，于是 `tcp.port != 443` 对每个包都成立（对端端口永远不是 443）。等价写法：`!(a == b)`。

---

## 9. TLS 明文解密（BeeEye-tlspeek）

> 参考 [gojue/ecapture](https://github.com/gojue/ecapture) 的 uprobe 方案。完整设计与边界见 [TLS-DECRYPT.md](TLS-DECRYPT.md)。

### 它能做什么、不能做什么

BeeEye-tlspeek 给 OpenSSL 库的 `SSL_write`/`SSL_read` 挂 uprobe，在加密前 / 解密后读出明文缓冲区。

| 目标 | 能否解密 |
|---|---|
| **网关本机上的进程**（curl、浏览器、你自己的服务） | ✅ 能 |
| 摄像头 / 门锁 / 电视 / 手机 | ❌ **不能** —— 它们的 TLS 库跑在自己的硬件上，本机的 uprobe 够不着 |

它是分析器「进程归属」的内容级搭档：能解密的进程集合，恰好就是「进程」列里显示进程名（而非 `Not this host`）的那批。

> **隐私**：这是 BeeEye 唯一读取应用**内容**的功能。因此它被做成**独立命令、默认关闭**：启动前什么都不抓，且必须显式指定目标。

### 构建与授权

```bash
make tlspeek                                              # 构建 bin/BeeEye-tlspeek
sudo setcap cap_bpf,cap_perfmon+ep BeeEye-agent/bin/BeeEye-tlspeek   # 授权（免 root）
```

### 用法

```bash
cd BeeEye-agent

# 1) 先看有哪些进程在用 OpenSSL 库
./bin/BeeEye-tlspeek -list

# 2) 只抓某个进程（推荐，范围最小）
./bin/BeeEye-tlspeek -pid 12345

# 3) 抓所有使用某个库的进程
./bin/BeeEye-tlspeek -lib /usr/lib/x86_64-linux-gnu/libssl.so.3

# 4) 不指定则自动选最繁忙的库（会打印选了哪个）
./bin/BeeEye-tlspeek
```

| 参数 | 含义 |
|---|---|
| `-list` | 列出当前在用的 OpenSSL 系列库及其进程，然后退出 |
| `-pid N` | 只抓进程 N |
| `-lib 路径` | 指定要挂的 TLS 库（默认自动发现） |
| `-max N` | 每条明文打印前 N 字节（默认 512；实际最多捕获 2047） |
| `-raw` | 打印原始字节，不转义不可见字符 |

### 输出示例

对一次真实的 `curl https://example.com`：

```
14:38:11.164 → curl  pid=598947  117B
PRI * HTTP/2.0

SM
...
14:38:11.461 ← curl  pid=598947  568B
...<!doctype html><html lang="en"><head><title>Example Domain</title>...
```

`→` 是发出（SSL_write，加密前），`←` 是收到（SSL_read，解密后）。`(+N more)` 表示该次调用的数据超过捕获上限被截断。

### 边界说明

- 目前覆盖 **OpenSSL / BoringSSL** 系列（`libssl`/`libcrypto`）。GnuTLS、NSS、Go 的 `crypto/tls` 未覆盖。
- 只做 **text 模式**（直接看明文）。keylog 导出、pcapng+内嵌密钥、分析器 UI 面板均属后续阶段，见 [TLS-DECRYPT.md](TLS-DECRYPT.md)。
- 静态链接自带 OpenSSL 的二进制：`-pid` 自动发现可能找不到独立的库映射，可用 `-lib` 直接指向该可执行文件。

### 解密 Chrome / AdsPower（SSLKEYLOGFILE 路径）

**Chrome、AdsPower 无法用 BeeEye-tlspeek 解密** —— 它们把 BoringSSL 静态链进主二进制并 strip 了符号，没有 `SSL_write`/`SSL_read` 可挂。对这类 Chromium/Electron 浏览器，用它们自带支持的 SSLKEYLOGFILE 机制，工具是 `scripts/tls-decrypt.sh`：

```bash
# 一条命令：抓包 + 启动 Chrome + 解密（需要 root 或 CAP_NET_RAW 抓包）
sudo ./scripts/tls-decrypt.sh capture --app chrome --url https://example.com/

# 解密 AdsPower：先确保 AdsPower 没在运行，然后由脚本启动它
sudo ./scripts/tls-decrypt.sh capture --app adspower
#   → 脚本启动 AdsPower，你正常浏览，关闭窗口后自动解密

# 指定任意 Chromium/Electron 二进制
sudo ./scripts/tls-decrypt.sh capture --app "/opt/AdsPower Global/adspower_global"

# 只对已保存的抓包+密钥重新解密（自动取 .run/tls 下最新的一对）
./scripts/tls-decrypt.sh decrypt
./scripts/tls-decrypt.sh decrypt --pcap 某.pcap --keys 某.log --filter http2
```

**关键前提**：SSLKEYLOGFILE 只覆盖**脚本启动之后**新建的 TLS 会话。对一个已经在运行、且当初启动时没带该变量的 Chrome，因 TLS 前向保密**无法事后解密** —— 必须由脚本启动或重启目标。

**输出**（对真实 Chrome 实测）：

```
── decrypted SNI ──
  clientservices.googleapis.com
  example.com
── decrypted HTTP/2 requests ──
  GET clientservices.googleapis.com /chrome-variations/seed?osname=linux&channel=stable...
── decrypted HTTP/2 responses ──
  302 text/html; charset=UTF-8 ClientMapServer
```

抓包与密钥保存在 `.run/tls/`，可随时用 Wireshark 打开（`编辑→首选项→Protocols→TLS→(Pre)-Master-Secret log filename` 指向 `keys-*.log`）。

**两条路径怎么选**：

| 目标 | 用哪个 |
|---|---|
| curl、动态链接 OpenSSL 的服务 | `BeeEye-tlspeek`（实时逐条明文） |
| Chrome、AdsPower、Chromium、Electron、Firefox | `scripts/tls-decrypt.sh`（SSLKEYLOGFILE） |

完整对照与原理见 [TLS-DECRYPT.md](TLS-DECRYPT.md)。

---

## 9.5 离线数据包导入分析

除了实时抓包，总览 UI 顶栏的 **Analysis（抓包分析）** 页签可以**导入 pcap 文件做离线分析**——把导出的抓包、或别处采集的 pcap 拖进来（或点击选择），在内存里跑与实时分析相同的引擎，产出取证级报告。

**用法**：
1. 打开 http://localhost:8080 → 点顶栏 **Analysis / 抓包分析**
2. 把 `.pcap` 文件拖到上传区，或点击选择
3. 报告分九个页签：
   - **Summary 摘要**：包数、字节、时长、唯一 IP/MAC、链路类型
   - **Protocols 协议**：各协议占比
   - **Talkers**：流量最大的端点（带地理）
   - **Conversations 会话**：五元组会话统计
   - **Sessions**：重组的应用层会话
   - **Credentials 凭证**：明文协议里发现的账号口令
   - **Files 文件**：从流量里提取（carve）的文件，可下载
   - **Security 安全发现**：启发式检出的可疑行为
   - **Geography 地理**：目标地理分布

**与实时抓包的关系**：跑的是同一套 `analyze` 引擎，所以同一段流量无论实时看还是导出后再导入，结论一致。配合分析器的 **Export pcap**（F44）可形成「导出 → 深度离线分析」闭环。上传的文件仅在内存分析，不落盘。

支持标准 libpcap 格式；pcapng 需先 `editcap -F pcap in.pcapng out.pcap` 转换。

---

## 10. 开发模式与热更新

改前端时用 `--dev`：

```bash
./start.sh --dev
```

会额外启动两个 Vite 开发服务器：

| 地址 | 对应 | 代理到 |
|---|---|---|
| http://localhost:5173 | 总览 UI（热更新） | :8080 |
| http://localhost:5174 | 分析器 UI（热更新） | :8081 |

改一行 CSS/JSX 立即生效，不用重新构建，也不会打断正在跑的抓包。**生产环境不需要这两个端口** —— Go 二进制直接伺服构建好的 `dist/`。

---

## 11. 故障排查

| 现象 | 原因与解决 |
|---|---|
| 总览无设备/连接 | agent 无抓包权限时回退模拟。授权：`./start.sh --setcap` 后 `restart`；或检查是否有真实流量经过网卡 |
| 分析器状态栏显示「模拟」/ `real_capture: false` | 没有抓包权限。运行 `./start.sh --setcap` 后 `restart` |
| `./start.sh` 报某工具 not found | 按提示装对应工具；`vmlinux.h` 相关需 `bpftool` 且内核带 BTF |
| 5173/5174 打不开 | 它们只在 `--dev` 时启动；确认用了 `./start.sh --dev` |
| `BeeEye-tlspeek` 报权限错误 | 需要 `cap_bpf,cap_perfmon`，见第 9 节授权命令 |
| `BeeEye-tlspeek -list` 找不到某进程的库 | 该进程可能静态链接了 OpenSSL，用 `-lib` 指向其可执行文件 |
| Chrome/AdsPower 用 tlspeek 挂不上 | 正常，它们静态链接 strip 过的 BoringSSL。改用 `scripts/tls-decrypt.sh`（SSLKEYLOGFILE） |
| `tls-decrypt.sh` 密钥为空 | 目标浏览器在脚本启动前就已运行。先完全退出它，再由脚本启动 |
| 改了网卡还抓不到 | 确认 `config/config.yaml` 的接口名与 `ip link` 一致，且挂的是 LAN 侧 |
| 端口被占用 | `./start.sh stop` 后确认 `.run/*.pid`；必要时手动清理 8080/8081/5173/5174 |

验证整套是否正常：

```bash
make smoke        # 端到端检查两个服务的每个端点，应输出 24 passed, 0 failed
```
