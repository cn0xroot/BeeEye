# 蜂眼 BeeEye — 实现进度

> 本文件与代码同步更新。需求编号对应 [program.md](program.md) §2.4；设计章节引用同一文档。
> 英文版：[PROGRESS.en.md](PROGRESS.en.md) · 架构说明：[ARCHITECTURE.md](ARCHITECTURE.md)

**最后更新**：2026-08-19

## 状态口径

| 记号 | 含义 |
|---|---|
| ✅ 已完成 | 功能可运行，且有自动化测试覆盖或已在本机实测验证 |
| 🟡 部分完成 | 核心路径可用，但存在下表"缺口"列中写明的明确差距 |
| 🔵 进行中 | 正在实现，尚不可用 |
| ⬜ 未开始 | 未动工 |

---

## 〇、数据来源：已接入真实抓包

**agent 现在默认对真实流量抓包**，不再是模拟场景。`BeeEye-agent/main.go` 走 `internal/livesource`，用与分析器相同的 AF_PACKET 抓包，把结果聚合成设备/连接/DNS/告警写入 SQLite。

| 进程 | 端口 | 数据来源 | 是否真实 |
|---|---|---|---|
| `BeeEye-agent` | :8080 | `internal/livesource`（AF_PACKET） | ✅ **真实抓包** |
| `BeeEye-gui` | :8081 | `internal/live`（AF_PACKET） | ✅ **真实抓包** |

于是**总览 UI 和分析器 UI 现在描述的是同一个真实网络**（本机网段，如 `192.168.x.x`），两边数据一致。

**降级仍然诚实（F43）**：无抓包权限（缺 `CAP_NET_RAW`）或传 `-simulate` 时，agent 回退到内置模拟场景，并在启动日志中明确标注 `SIMULATED traffic`，绝不把模拟当真实。

**接口选择（F16）**：`captureIface` 依次尝试 config 里存在的接口 → 默认路由网卡 → `any`，所以 config 写的 `wlan0`/`eth0` 与本机不符时会自动落到真实网卡，而不是静默回退模拟。

**关于 `internal/ebpf`**：该包（CO-RE TC 程序 + ringbuf 读取）仍然独立存在、有挂载测试，但当前的真实抓包走的是 AF_PACKET 路径（与分析器一致、复用已测的 dissect 聚合链），而非 eBPF ringbuf。两条采集路径都能拿到真实流量；接入 eBPF ringbuf 作为更高效的采集源是后续优化项。

---

## 一、总体进度

| 层 | 状态 | 说明 |
|---|---|---|
| 实时采集 | ✅ | agent 与分析器均通过 AF_PACKET 实时抓包（`internal/livesource` / `internal/live`）。eBPF CO-RE 程序独立可用并有挂载测试，作为更高效采集源待接入 ringbuf |
| 用户态 Agent 核心 | ✅ | 实时抓包 → 解剖 → 聚合 → 检测 → 落库全链路打通（`internal/livesource`，507 行） |
| 协议解析器 | ✅ | 以太网/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP + DNS/mDNS/TLS/HTTP/MQTT/SSDP/DHCP，分析器端到端在用 |
| 显示过滤器引擎 | ✅ | Wireshark 兼容子集，含 CIDR 与正则；前端校验与实际过滤共用同一个解析器 |
| 存储层 | 🟡 | SQLite 全部表已落地并在用；InfluxDB 时序库未接入 |
| 检测引擎 | 🟡 | 九类加权信号已实现并产出事件；行为基线建模未开始 |
| REST API | ✅ | 设备/连接/DNS/事件/按IP/按协议/TopN/时序/导出 全部就绪，冒烟测试逐个验证 |
| Web 总览前端 | ✅ | 六视图 + 双语 + 主题全部可用；实测展示真实网络（本机网段、真实设备/协议/告警） |
| 实时分析 GUI | ✅ | 三窗格 + 显示过滤器 + 色场 + pcap 导出，实测真实抓包 |
| 部署与本地测试环境 | ✅ | `start.sh` 一键 + `scripts/dev.sh` + `Makefile` + `docker-compose.yml` + `smoke.sh`（24 项全过） |

---

## 二、逐条功能状态

### P0 必须实现

| 编号 | 功能 | 状态 | 证据 / 缺口 |
|---|---|---|---|
| F1 | 设备发现与身份识别 | 🟡 | `internal/identity` 做 OUI + hostname 推断；内核态已上报 DHCP Option 55/60、mDNS、SSDP 原始报文，`internal/dissect/app.go` 已解析出指纹字段。**缺口**：未接入 Fingerbank 类指纹库做型号匹配（真实抓包下多数设备 OUI 未命中，类别显示 unknown） |
| F2 | 连接级流量统计 | 🟡 | 内核 `flows` LRU 流表 + 周期快照上报已实现；`internal/store` `connections` 表持久化，实时抓包数据在用 |
| F3 | TLS 握手信息提取 | ✅ | SNI / ALPN / JA3 已实现（`internal/dissect/app.go`），JA3 稳定性有测试覆盖；分析器对真实流量端到端在用 |
| F4 | 明文协议解析 | ✅ | MQTT / HTTP / SSDP / mDNS / DNS / DHCP 已实现。**缺口**：CoAP 仅识别未逐字段解析 |
| F5 | 设备分级监控策略 | 🟡 | 分级已下沉到内核态：门锁/摄像头逐流上报，其余走聚合快照（`bpf/BeeEye.bpf.c`）。**缺口**：分级依赖 eBPF 内核路径，当前 AF_PACKET 路径未用分级 |
| F6 | 异常检测规则引擎 | ✅ | `internal/detect`：威胁情报、信标、扇出、横向、DNS 异常、地域、非常规时段，实测产出 38 条风险事件 |
| F7 | Web 可视化界面 | ✅ | 总览/设备/连接/按IP/按协议/DNS/告警 七个视图全部可用；实测逐页截图，页面报错为空 |
| F8 | 新设备接入告警 | ✅ | `device_registry.is_new` 记录未确认状态，UI 有"确认"按钮；实时抓包下新设备实测入库。eBPF 的 `EVT_NEWDEV` 路径独立可用 |
| F16 | 多网卡可配置采集 | 🟡 | 接口名全部来自 `config/config.yaml`；`captureIface` 依次尝试 config 接口→默认路由网卡→any，config 与本机不符时自动落到真实网卡（F16 已在 AF_PACKET 路径生效） |
| F17 | 采集流量来源接口标识 | 🟡 | `ifindex` 进入内核 flow_key 与每条事件；连接与设备记录携带来源接口名，实时抓包下在用 |
| F18 | Web UI 中英文切换 | ✅ | 后端只返回枚举 key（category/event_type 从不返回本地化字符串），两个 UI 各自带 `locales/zh-CN` 与 `en-US`，顶栏 EN/中文 即时切换 |
| F19 | Web UI 多主题配色 | 🟡 | 6 套主题 token 全部实现并可用（light 已改为米黄纸感、dark、tech-blue、warm-amber、forest-green、high-contrast）。**缺口**：顶栏开关按需求改为日/月两态，其余四套主题目前只能通过 `localStorage` 选中，UI 上不可达 |
| F21 | DNS 查询记录与域名映射 | ✅ | 解析器处理压缩指针与 A/AAAA/CNAME；`dns_records` 表 + `DomainForIP` 反查；分析器对真实流量实测解析出域名 |
| F22 | 服务器 IP 地理位置标注 | 🟡 | `internal/geoip` 全离线查询，私有/CGNAT 正确标注为本地。**缺口**：内置的是首字节粗表，未接 MaxMind GeoLite2 .mmdb |
| F23 | 通信协议识别与展示 | ✅ | 按 §3.5.4 优先级链实现，识别不出时如实标注 unknown |
| F24 | 端口与服务名映射 | ✅ | `config/port-service-map.yaml` 可配置，启动时加载 24 条覆盖内置表 |
| F25 | 按 IP 维度视图 | ✅ | `GET /api/views/ip` 聚合域名/地理/设备/协议/端口/流量；冒烟测试覆盖 |
| F26 | 按协议维度视图 | ✅ | `GET /api/views/protocol`；冒烟测试覆盖 |
| F34 | 内网东西向流量监控 | ✅ | 内网目的地不被过滤；`connections.internal` 标记 + `detect` 横向检测器，实测 1335 条东西向流 |
| F35 | 信标(C2心跳)检测 | ✅ | 间隔变异系数算法，阈值来自配置 |
| F36 | 扇出/扫描检测 | ✅ | 滑动窗口唯一目标计数，按设备类别差异化阈值 |
| F40 | 实时抓包分析 GUI | ✅ | 三窗格（包列表/协议树/十六进制）联动高亮、显示过滤器、模板菜单、色场、进程归属、**列点选排序**全部可用；实测在 `wlp9s0` 上抓到 6.9 万包、0 丢包 |
| F41 | 显示过滤器表达式 | ✅ | `internal/dfilter`：逻辑/比较/contains/matches/CIDR/存在性，语法错误即时报错；前端不做第二套解析，校验与过滤同一个裁决者 |
| F42 | 双 UI 运行隔离 | ✅ | 双二进制双端口；冒烟测试专门验证"挂起分析器后总览 API 仍应答" |
| F43 | 采集源降级与如实标注 | 🟡 | `live.Open` 优先级降级并返回"是否真实"标志；分析器状态栏标注 `Source: af_packet`，agent 无抓包权限时启动日志标注 SIMULATED。**缺口**：总览 UI 页面上尚无"模拟/真实"角标（仅启动日志） |

### P1 建议实现

| 编号 | 功能 | 状态 | 证据 / 缺口 |
|---|---|---|---|
| F9 | 门锁/摄像头出站白名单 | ⬜ | 需 XDP 程序，未开始 |
| F10 | 设备行为基线建模 | ⬜ | 未开始 |
| F11 | 按需精细抓包 | ⬜ | 未开始。注意与 F44 区分：F44 的**导出**已完成，F11 的**触发式抓包**未做 |
| F20 | 接口热插拔自动发现 | ⬜ | 配置里已有 `auto` 模式与排除规则，netlink 监听未实现 |
| F27 | Top N 流量排行 | ✅ | `GET /api/views/topn?dim=device\|ip\|country\|domain`；冒烟测试覆盖 |
| F28 | 异常地理位置告警 | ✅ | `detect` 的 geo_anomaly 信号 |
| F29 | 域名/IP 威胁情报比对 | 🟡 | 比对逻辑已实现并接入评分。**缺口**：情报源由调用方注入，未接公开黑名单与本地缓存更新 |
| F30 | 多维组合检索 | ✅ | `GET /api/connections` 支持设备/IP/协议/端口范围/时间范围任意组合 |
| F37 | 多信号加权评分 | ✅ | 九类信号加权求和，阈值可配置，分级 高/中/低 |
| F38 | 高危事件自动响应联动 | ⬜ | 配置开关 `auto_block` 已预留且默认关闭，阻断动作未实现 |
| F44 | PCAP 导出 | ✅ | `GET /api/export/pcap`；冒烟测试导出后用 `tcpdump -r` 实际读回验证 |

### P2 可选实现

| 编号 | 功能 | 状态 |
|---|---|---|
| F12 流量分类模型 / F13 移动端推送 / F32 地图可视化 / F39 恶意下载特征 | ⬜ 未开始 |
| F14 TLS 明文捕获 | 🟡 **阶段一已实现**：`internal/tlspeek` + `cmd/BeeEye-tlspeek`，uprobe 挂 OpenSSL 的 `SSL_write`/`SSL_read`，`TestCapturesRealTLSPlaintext` 从真实 TLS 会话捞回明文；命令行实测还原真实 `curl https` 的 HTTP/2 内容。**两条路径均已实现**：(A) `BeeEye-tlspeek` uprobe 解密动态链接 OpenSSL 进程；(B) `scripts/tls-decrypt.sh` 用 SSLKEYLOGFILE 解密 **Chrome/AdsPower 等 Chromium/Electron**（实测还原明文 SNI + HTTP/2 请求响应）。**边界**：路径 A 只限本机、且需符号未 strip；路径 B 需由脚本启动目标。**缺口**：pcapng+DSB 导出、GnuTLS/NSS/Go crypto/tls、分析器 UI 面板未做 |
| F15 主动 MITM | ⬜ 未开始，且建议不做：对目标 IoT 设备无效，需在设备上装证书，与"无需在任何设备上装 agent"直接冲突 |
| F31 通信记录导出(CSV/JSON) | ✅ `GET /api/export?format=csv\|json`，CSV 带 UTF-8 BOM 以便 Excel 正确读取中文 |
| F33 DNS 异常检测 | 🟡 NXDOMAIN 高频（疑似 DGA）已实现；DNS 隧道特征未实现 |

---

## 三、已验证的关键事实

这些不是设计意图，是在本机实测通过的结果：

**内核与解析**

- **eBPF 程序可加载**：`bpftool prog loadall` 与 Go loader 均通过验证器，内核 `7.0.0-28-generic`，BTF 可用。
- **TCX 双向挂载生效**：`attach_test.go` 在 `lo` 上挂载后发出 UDP/53 报文，ringbuf 收到 `EVT_DNS` 且负载与发送内容逐字节一致。
- **内核/用户态结构体布局一致**：`TestEventLayoutMatchesBTF` 从编译产物的 BTF 读取真实字段偏移，与 Go 解码器的硬编码偏移逐字段比对，而不是靠人工对齐。
- **解析器对截断数据不崩溃**：`TestTruncatedPacketsDoNotPanic` 对同一个 ClientHello 帧的每一个前缀长度都跑一遍解析。
- **JA3 语义正确**：同一客户端多次握手（random/session id 不同）指纹一致，cipher 列表不同则指纹不同。
- **进程归属宁可留白**：`internal/procmap` 验证其他设备的流量返回**未归属**，而不是硬安在某个巧合的本机进程上。

**端到端**
- **离线 pcap 导入端到端可用**：`POST /api/pcap/upload` 跑 `analyze.Analyze` 返回完整报告（协议/talkers/会话/凭证/提取文件/安全发现/地理）；总览 UI 的「抓包分析」页签上传文件并渲染全部九个报告面板（实测：713 包的抓包解析并展示）。
- **抓包持久化到磁盘**：分析器把实时抓包写入 `/tmp/BeeEye/*.pcap`；`TestPcapSinkRoundTrip` 与实测确认——内存环淘汰 791 个包后，取包 #1 详情仍返回 HTTP 200（从磁盘读回重解剖），不再报 "no longer buffered"。

- **两个服务全部端点应答**：`scripts/smoke.sh` **24 项全过，0 失败**，覆盖总览 12 个端点、分析器 11 项（含 SSE 开流、过滤器合法/非法两路、pcap 导出经 `tcpdump` 读回）、以及 F42 进程隔离。
- **真实抓包**：分析器在 `wlp9s0` 上以 AF_PACKET 抓到 69300 包 / 66 MB，`kernel_drops: 0`。
- **CUDA 与 CPU 渲染器一致**：`TestBackendsAgree` 用同一输入分别在 RTX 2080 Ti 和 Go 实现上渲染，**最大通道偏差 1/255**，均值 0.00001。
- **色场调色板与前端一致**：`TestPaletteCSSMatchesChannels` 逐槽比对 `PaletteCSS()` 与 `ChannelColors`，防止包列表的色块和色场的通道色对不上。
- **自动滚动不再被动漂移**：关闭状态下 214 行新数据到达（内容高度 +6170px），`scrollTop` 保持 41909 不变、视口顶部仍是同一个包；开启状态紧跟末尾且页面自身零滚动。
- **列排序正确**：停止抓包后在 2966 行 IPv4 上零逆序，三个地址族（IPv4/IPv6/MAC）各成一整块。

---

## 四、下一步

按优先级：

1. **把 eBPF ringbuf 接为 agent 的采集源** —— agent 已用 AF_PACKET 实时抓包（§0），eBPF CO-RE 程序也独立可用；把 `internal/ebpf` 接成第二采集源可获得内核态分级（F5）与更低开销，但不再是"总览拿不到真实数据"的阻塞点。
2. **给总览 UI 加"模拟/真实"角标** —— 目前只有启动日志标注降级，页面上还没有像分析器状态栏那样的角标（F43）。
3. **F19 的其余四套主题** —— 顶栏改成日/月两态后，tech-blue / warm-amber / forest-green / high-contrast 在 UI 上不可达，需要一个二级入口。
4. GeoLite2 .mmdb 接入（F22）、威胁情报源接入（F29）、CoAP 逐字段解析（F4）。
5. 行为基线建模（F10）、按需触发抓包（F11）、接口热插拔（F20）。
6. TLS 明文捕获**阶段二/三**：pcapng+DSB 导出、按 OpenSSL 版本的 keylog 偏移表、以及接入分析器 UI 的「明文」面板。阶段一（text 模式）已完成，见 [TLS-DECRYPT.md](TLS-DECRYPT.md)。
