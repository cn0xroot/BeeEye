# 蜂眼 BeeEye — 实现进度

> 官网：https://www.beeeye.dev/
> 本文件与代码同步更新。需求编号对应 [program.md](program.md) §2.4；设计章节引用同一文档。
> 英文版：[PROGRESS.en.md](PROGRESS.en.md) · 架构说明：[ARCHITECTURE.md](ARCHITECTURE.md)

**最后更新**：2026-08-21

## 状态口径

| 记号 | 含义 |
|---|---|
| ✅ 已完成 | 功能可运行，且有自动化测试覆盖或已在本机实测验证 |
| 🟡 部分完成 | 核心路径可用，但存在下表"缺口"列中写明的明确差距 |
| 🔵 进行中 | 正在实现，尚不可用 |
| ⬜ 未开始 | 未动工 |

---

## 〇、数据来源：已接入真实抓包

**agent 现在默认对真实流量抓包**，不再是模拟场景。`BeeEye-agent/main.go` 走 `internal/livesource`，通过 `internal/capsource` 的优先级链选采集源，把结果聚合成设备/连接/DNS/告警写入 SQLite。

| 进程 | 端口 | 数据来源 | 是否真实 |
|---|---|---|---|
| `BeeEye-agent` | :8080 | `internal/capsource` → eBPF ringbuf（优先）或 AF_PACKET（回退） | ✅ **真实抓包** |
| `BeeEye-gui` | :8081 | `internal/live`（AF_PACKET，见下方"为何分析器不用 eBPF"） | ✅ **真实抓包** |

于是**总览 UI 和分析器 UI 现在描述的是同一个真实网络**（本机网段，如 `192.168.x.x`），两边数据一致。

**无抓包时诚实地显示"无数据"，而不是伪造（F43，2026-08-21 起彻底移除模拟回退）**：模拟场景（agent 侧固定十设备的 `capture.GenerateSimulated`、分析器侧持续生成合成包的 `live.OpenSimulated`）已连同 `-simulate` 参数和 `simulate_seed` 配置一起从代码库中删除。无抓包权限，或 eBPF/AF_PACKET 均不可用时，`live.Open`/`capsource.Open` 直接返回错误——agent 以无采集流水线的方式继续运行，分析器的 Start 直接失败——总览和分析器都诚实地显示"无数据/不可用"，不存在任何可以把假流量当真实展示的代码路径。总览 UI 顶栏角标（`source-badge`）标注当前是 `ebpf`/`af_packet`/`unavailable` 三者之一。

**接口选择（F16）**：`captureIface` 依次尝试 config 里存在的接口 → 默认路由网卡 → `any`，所以 config 写的 `wlan0`/`eth0` 与本机不符时会自动落到真实网卡，而不是对一张根本不存在的网卡静默报告"无数据"。

**`internal/ebpf` 现状（2026-08-19 更新）**：CO-RE TC 程序已改造为支持"全量抓包模式"——新增 `EVT_RAW_FRAME` 事件类型 + `CFG_RAW_FRAME_MODE` 开关，开启后每个包无条件镜像完整原始帧（不再局限于 DNS/TLS 等选择性协议头），通过 `internal/ebpf.OpenEBPF` 包装成标准 `live.Source`，与 AF_PACKET 完全同构，可以直接喂给现有 dissect 流水线。`internal/capsource` 实现"eBPF 优先，失败回退 AF_PACKET"的两级链，两者均不可用时直接报错，不存在第三级模拟器兜底；`internal/livesource`（agent）已接入。

**为何分析器（`internal/gui`）不用 eBPF**：实测发现（`bpftool prog show` 的 `run_cnt` 逐一核对）——本机内核上，TCX 链虽然允许多个独立程序同时 attach 到同一网卡的同一方向，但**只有最先 attach 的那个真正被内核调用**，第二个 attach"成功"（无报错）却永远收不到包（`run_cnt` 始终为 0，双方向交叉验证一致）。因此让 agent（常驻服务，最需要 eBPF 的低开销）独占 eBPF，分析器（按需启动的诊断工具）继续用一直稳定支持多读者的 AF_PACKET，而不是给这个内核特定的行为构建探测/重试/降级的自愈逻辑。详见 `internal/capsource/capsource.go` 与 `internal/gui/session.go` 里的对应注释。

---

## 一、总体进度

| 层 | 状态 | 说明 |
|---|---|---|
| 实时采集 | ✅ | agent 通过 `internal/capsource` 优先用 eBPF ringbuf（全量镜像模式），失败回退 AF_PACKET；分析器固定用 AF_PACKET（原因见 §0）。两条路径均实测跑通，`internal/ebpf` 的 `EVT_RAW_FRAME` 端到端验证通过 |
| 用户态 Agent 核心 | ✅ | 实时抓包 → 解剖 → 聚合 → 检测 → 落库全链路打通（`internal/livesource`，507 行） |
| 协议解析器 | ✅ | 以太网/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP + DNS/mDNS/TLS/HTTP/MQTT/SSDP/DHCP，分析器端到端在用 |
| 显示过滤器引擎 | ✅ | Wireshark 兼容子集，含 CIDR 与正则；前端校验与实际过滤共用同一个解析器 |
| 存储层 | 🟡 | SQLite 全部表已落地并在用；InfluxDB 时序库未接入 |
| 检测引擎 | ✅ | 十类加权信号已实现并产出事件，含行为基线建模（z-score，F10）；威胁情报（F29）已接入真实公开黑名单 |
| REST API | ✅ | 设备/连接/DNS/事件/按IP/按协议/TopN/时序/导出 全部就绪，冒烟测试逐个验证 |
| Web 总览前端 | ✅ | 六视图 + 双语 + 主题全部可用；实测展示真实网络（本机网段、真实设备/协议/告警） |
| 实时分析 GUI | ✅ | 三窗格 + 显示过滤器 + 色场 + pcap 导出，实测真实抓包 |
| 部署与本地测试环境 | ✅ | `start.sh` 一键 + `scripts/dev.sh` + `Makefile` + `docker-compose.yml` + `smoke.sh`（24 项全过） |

---

## 二、逐条功能状态

### P0 必须实现

| 编号 | 功能 | 状态 | 证据 / 缺口 |
|---|---|---|---|
| F1 | 设备发现与身份识别 | 🟡 | `internal/identity` 做 OUI + hostname 推断，现已扩展为 `Fingerprint`（DHCP option 55/60、HTTP User-Agent、SSDP `Server:` 头，`internal/livesource/pipeline.go` 的 `seeFingerprint` 打通了从解析层到 `Identify` 的整条链路，DHCP 用自带 `chaddr` 定位设备）。**缺口**：仍是手工建的小规模指纹表（比照现有 19 条 OUI 表的规模），不是 Fingerbank 完整数据库，覆盖率有限 |
| F2 | 连接级流量统计 | 🟡 | 内核 `flows` LRU 流表 + 周期快照上报已实现；`internal/store` `connections` 表持久化，实时抓包数据在用 |
| F3 | TLS 握手信息提取 | ✅ | SNI / ALPN / JA3 已实现（`internal/dissect/app.go`），JA3 稳定性有测试覆盖；分析器对真实流量端到端在用 |
| F4 | 明文协议解析 | ✅ | MQTT / HTTP / SSDP / mDNS / DNS / DHCP / **CoAP**（RFC 7252 头部+token+Uri-Path/Uri-Query/Content-Format/Observe 等选项逐字段解析，`TestDissectCoAP` + 截断 fuzz 测试覆盖）均已实现 |
| F5 | 设备分级监控策略 | ✅ | 分级最早下沉到内核态（门锁/摄像头逐流上报，其余走聚合快照，`bpf/BeeEye.bpf.c`），现已在 AF_PACKET 路径同步实现：`internal/livesource/pipeline.go` 新流建立时对高敏感类别（`Sensitivity()==3`）立即上报连接事件，不再依赖 eBPF；`TestTieredDeviceFlowReportsImmediately`/`TestUntieredDeviceFlowOnlyAggregates` 覆盖 |
| F6 | 异常检测规则引擎 | ✅ | `internal/detect`：威胁情报、信标、扇出、横向、DNS 异常、地域、非常规时段，实测产出 38 条风险事件 |
| F7 | Web 可视化界面 | ✅ | 总览/设备/连接/按IP/按协议/DNS/告警 七个视图全部可用；实测逐页截图，页面报错为空。**新增**：告警列表新增"关联目标"列（目的 IP、域名、地理位置），`GET /api/events` 后端同步富化——之前 `detail.dst_ip` 只是埋在原始 JSON 里，现在是一等字段 |
| F8 | 新设备接入告警 | ✅ | `device_registry.is_new` 记录未确认状态，UI 有"确认"按钮；实时抓包下新设备实测入库。eBPF 的 `EVT_NEWDEV` 路径独立可用 |
| F16 | 多网卡可配置采集 | 🟡 | 接口名全部来自 `config/config.yaml`；`captureIface` 依次尝试 config 接口→默认路由网卡→any，config 与本机不符时自动落到真实网卡（F16 已在 AF_PACKET 路径生效） |
| F17 | 采集流量来源接口标识 | 🟡 | `ifindex` 进入内核 flow_key 与每条事件；连接与设备记录携带来源接口名，实时抓包下在用 |
| F18 | Web UI 中英文切换 | ✅ | 后端只返回枚举 key（category/event_type 从不返回本地化字符串），两个 UI 各自带 `locales/zh-CN` 与 `en-US`，顶栏 EN/中文 即时切换 |
| F19 | Web UI 多主题配色 | ✅ | 9 套主题（system、light 米黄纸感、dark、midnight-neon、matrix、tech-blue、warm-amber、forest-green、high-contrast）全部实现并可用；顶栏日/月按钮是浅色/深色快捷切换，紧邻的齿轮图标菜单（`Settings.jsx`）以九宫格色块暴露全部主题，双语标签齐全，全部可从 UI 直接点选，无需手改 `localStorage` |
| F21 | DNS 查询记录与域名映射 | ✅ | 解析器处理压缩指针与 A/AAAA/CNAME；`dns_records` 表 + `DomainForIP` 反查；分析器对真实流量实测解析出域名 |
| F22 | 服务器 IP 地理位置标注 | ✅ | `internal/geoip/mmdb.go`：接入标准 MaxMind mmdb（`geoip2-golang`），自动发现 `./data/`、`/usr/share/GeoIP/`、Clash 的 `Country.mmdb`；有 City 库则解析国家/省/市，有 ASN 库则解析运营商，均全离线查询，实测本机 Clash 库正确识别 `114.114.114.114`→CN、`8.8.8.8`→country=GOOGLE（伪代码，非真实地理国家码）。新增 `GET /api/geoip/status` 暴露当前精度等级（`city`/`country`/`builtin`），总览 By-IP 页新增精度徽章（`GeoAccuracyBadge.jsx`）如实告知用户当前是否只有国家级粗糙定位。新增 `scripts/geoip-setup.sh`：引导下载 GeoLite2-City/ASN（需用户自备免费 MaxMind 账号），下载本身不算在线逐 IP 查询，下载完成后的每次查询仍 100% 本地（§3.9 隐私要求不受影响）。`TestGetStatusReflectsAccuracy`/`TestReadVersionStringOnRealLibraries`（后者见 F14）覆盖 |
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
| F43 | 采集源降级与如实标注 | ✅ | 2026-08-21：彻底删除模拟回退（`capture.GenerateSimulated`、`live.OpenSimulated`、`-simulate`、`simulate_seed`）。`live.Open`/`capsource.Open` 打不开真实源时直接返回错误，agent 以无采集流水线继续运行、分析器 Start 直接失败；总览顶栏角标与分析器状态栏都只会显示 `ebpf`/`af_packet`/`pcap-file`/`unavailable`，不存在能把假数据当真实展示的代码路径 |

### P1 建议实现

| 编号 | 功能 | 状态 | 证据 / 缺口 |
|---|---|---|---|
| F9 | 门锁/摄像头出站白名单 | ⬜ | 需 XDP 程序，未开始 |
| F10 | 设备行为基线建模 | ✅ | `internal/detect.Engine.Baseline`：按设备+小时分桶，用 Welford 在线算法对同一小时桶的历史天数做均值/标准差，今天该小时的流量字节数用 z-score 判定离群（默认 `min_days=5`、`z_threshold=3.0`），产出新信号 `baseline_deviation`（权重 15）。保持与其它检测器一致的纯函数风格，不持久化模型，重启即重新学习。`TestBaselineFlagsVolumeOutlier`/`TestBaselineIgnoresNormalVariation`/`TestBaselineRequiresMinimumHistory` 覆盖 |
| F11 | 按需精细抓包 | ✅ | 新增 `internal/tcapture`：按 MAC 触发一次限时/限字节数的定向抓包（区别于 F44 对已有环形缓冲的**导出**，这是从触发时刻起的**全新**抓包），直接旁路进 `livesource.Pipeline` 的抓包热路径写盘，不占用内存。`POST /api/capture/targeted` 触发、`GET .../{id}` 查状态、`GET .../{id}/download` 下载。**实测**：对真实网关 MAC 触发 15 秒定向抓包，抓到 1811 帧/1.6MB，下载后 `tcpdump` 读回全部 1811 帧无一例外命中目标 MAC |
| F20 | 接口热插拔自动发现 | ✅ | 新增 `internal/live/hotplug.go`：原始 AF_NETLINK 套接字订阅 `RTMGRP_LINK`，解析 `RTM_NEWLINK`/`RTM_DELLINK`（不用 unsafe 指针，纯字节偏移解析，截断消息不 panic）。`auto_discover.exclude_patterns` 从"配置里存在但从未被消费"变成真正生效的 `autoDiscoverIface`。`main.go` 的 `hotplugSupervisor` 收到事件后重新算 `captureIface`，若与当前不同则关闭旧 pipeline、开新 pipeline，并重新挂 threat-intel/targeted-capture 回调。**实测**：用真实 dummy 网卡验证了内核事件能被正确捕获，以及 `captureIface`/`autoDiscoverIface` 在网卡出现前后返回正确结果（`main_test.go`） |
| F27 | Top N 流量排行 | ✅ | `GET /api/views/topn?dim=device\|ip\|country\|domain`；冒烟测试覆盖 |
| F28 | 异常地理位置告警 | ✅ | `detect` 的 geo_anomaly 信号 |
| F29 | 域名/IP 威胁情报比对 | ✅ | 新增 `internal/threatintel`：接入 Spamhaus DROP 公开黑名单（CIDR 段，免注册），启动时同步加载本地缓存（不阻塞抓包）、后台按 `refresh_hours`（默认 24h）定期刷新，失败时沿用旧缓存并只打日志警告。`detect.ThreatIntel` 新增 `BadCIDRs` + `MatchIP`（先查精确匹配再查 CIDR 命中）。**实测**：真实拉取到 1693 条 CIDR 段，缓存文件落盘 `data/threatintel/spamhaus_drop.txt` |
| F30 | 多维组合检索 | ✅ | `GET /api/connections` 支持设备/IP/协议/端口范围/时间范围任意组合 |
| F37 | 多信号加权评分 | ✅ | 九类信号加权求和，阈值可配置，分级 高/中/低 |
| F38 | 高危事件自动响应联动 | ⬜ | 配置开关 `auto_block` 已预留且默认关闭，阻断动作未实现 |
| F44 | PCAP 导出 | ✅ | `GET /api/export/pcap`；冒烟测试导出后用 `tcpdump -r` 实际读回验证 |

### P2 可选实现

| 编号 | 功能 | 状态 |
|---|---|---|
| F12 流量分类模型 / F13 移动端推送 / F39 恶意下载特征 | ⬜ 未开始 |
| F32 地图可视化 | ✅ **2026-08-20 由 3D 地球改为 2D 世界地图**（`BeeEye-web/src/components/WorldMap.jsx`，原 `Globe.jsx` 已删除，按用户明确要求"地球改成2D吧 增加GPU渲染色彩"）：等距圆柱投影，GPU 路径用 WebGL2 片段着色器把每个目的地画成**加法混合的径向辉光**（多个目的地/多次访问在同一片区域会自然叠出更亮的热力，而不是简单的点大小变化），着色器直接从主题 CSS 变量取色（`--accent`/`--series-N`），换主题地图跟着变，不需要重新编译。**新增 Canvas2D 兜底路径**：无 WebGL2 的环境（锁定的企业浏览器、某些远程桌面/无头场景）会自动切到 Canvas2D 渲染器，用径向渐变模拟同样的辉光叠加效果和弧线动画，保证地图在任何浏览器都能显示点，不是"要么完整要么报错"的二选一。后端 `GET /api/views/geopairs` 与地理经纬度两级兜底表（`internal/geoip/centroid.go`）沿用不变。**实测**：真实产生跨 3 个域名（example.com/github.com/cloudflare.com）的外联流量后，地图显示"4 destinations"、正确画出经纬网格和从示意锚点出发的弧线（Canvas2D 路径下验证，因本沙箱环境的 Chrome 无法打开 X 显示、拿不到 WebGL2；WebGL2 主路径在有 GPU 的真实浏览器里渲染，代码走标准 WebGL2 API，未在真实独立显卡上截图验证渲染细节）。**缺口**：只有目的地点，没有真实的本机地理坐标；WebGL2 路径未在真实 GPU 上截图验证（仅 Canvas2D 兜底路径实测截图）。 |
| F14 TLS 明文捕获 | 🟡 **阶段一已实现且默认开启**：分析器启动即挂 uprobe 解密网关本机 HTTPS（`internal/gui/decrypt.go`），不需要额外操作。**加密库支持改为声明式规则表**（`internal/tlspeek/rules.go`）：一条 `LibraryRule{Name, SONAME正则, WriteSym, ReadSym}` 覆盖一个库家族，加新库=加一行规则，SONAME 用正则匹配跨版本/跨发行版文件名（`libssl.so.3`、`.so.1.1` 等同一条规则命中，`TestMatchRuleCoversVersionedSONAMEs` 覆盖）；已收录 **OpenSSL** 和 **GnuTLS**（curl/wget 走前者，部分工具走后者），实机同时挂载两族共 **116 个进程**（44 OpenSSL + 72 GnuTLS）。**新增加密库检测**（`internal/tlspeek/detect.go` + `BeeEye-tlspeek -detect` + `GET /api/decrypt/libs`）：用 ELF 动态符号表判定某条库是否真的可挂载（区分"库存在"与"符号未被 strip 因而可挂"），并**从库文件内嵌的版本横幅字符串探测确切版本号**（如 `OpenSSL 3.0.13`、`GnuTLS 3.8.3`），实机同时探测到系统 `OpenSSL 3.0.13` 与 anaconda 环境 `OpenSSL 3.0.16` 两个不同版本并行工作，`TestReadVersionStringOnRealLibraries` 在真实库文件上验证解析不被库内其它含数字的字符串污染（曾误匹配 GnuTLS 错误信息表里的 "GnuTLS error: %s"，已修正为要求版本号后紧跟数字）。**两条路径均已实现**：(A) `BeeEye-tlspeek`/分析器内置 uprobe 解密动态链接 OpenSSL/GnuTLS 进程；(B) `scripts/tls-decrypt.sh` 用 SSLKEYLOGFILE 解密 **Chrome/AdsPower 等 Chromium/Electron**（静态链接 strip 过的 BoringSSL，路径 A 挂不上）。**边界**：路径 A 只限本机、且需符号未 strip；路径 B 需由脚本启动目标。**缺口**：pcapng+DSB 导出、Go crypto/tls（需 CO-RE，与 OpenSSL/GnuTLS 走不同架构）、按 OpenSSL 具体版本的 masterkey 偏移表（keylog 模式，工程量大，eCapture 为此维护 39 张版本偏移表）、分析器 UI 里的实时明文面板（后端 `/api/plaintext` 已就绪，前端 `Plaintext.jsx` 已接入包详情按 pid 展示，但流式关联仍偏弱——见下方 F14 实测记录）未做完整。参考 [eCapture](https://github.com/gojue/ecapture) 源码（`kern/`、`internal/probe`、`internal/output`）梳理出的具体技术路线见下方"待借鉴细节"，其中"①版本探测+偏移表"一项的**版本探测半步已经落地**（见上），偏移表本身未做 |
| F14 待借鉴细节（对 eCapture 源码的调研，非 README 摘要） | ⬜ **① OpenSSL/GnuTLS 多版本兼容走"版本探测 + 预测量偏移表"，不是 CO-RE**：eCapture 为 OpenSSL 39 个具体发布版本（1.0.2a→3.5.0）、GnuTLS 7 个版本各自维护一份纯字段偏移常量表（如 `#define SSL_CONNECTION_ST_SESSION 0x880`），运行时探测库版本号选择匹配的偏移表，探针逻辑本身通用。原因：CO-RE 依赖 BTF，系统装的用户态 .so 库几乎不内置 BTF，CO-RE 只解决内核结构体跨版本问题，解决不了用户态库的。`internal/tlspeek` 目前大概率只适配了本机装的这一个 OpenSSL 版本，要做多版本兼容，这是唯一可行路线，不必等/幻想 CO-RE。**② GoTLS 反过来用 CO-RE**：`gotls_kern.c` 只有一份、不分版本，`go_argument.h` 用 `BPF_CORE_READ` 按架构（x86 读 `ax`/`bx`/…寄存器，arm64 走 `PT_REGS_PARMx_CORE`）抽象 Go 1.17+ 寄存器传参 ABI；且引用 `tc.h`，因为 uprobe 挂在应用层拿不到 socket 五元组，需要 TC 程序在网络层关联回来——uprobe（明文）+TC（五元组）组合是 Go crypto/tls 支持的可行架构参考。**③ 输出层 writer/encoder 分离**：`internal/output/writers`（file/stdout/**tcp**/**websocket**/logger）与 `encoders`（json/plain/protobuf）正交组合，是"明文事件实时转发给外部工具"（如转发到本地分析脚本或第三方消费者）的可选能力架构参考，可选、非必需，跟 pcapng+DSB 导出走不同的消费路径。 |
| F15 主动 MITM（无差别，对全部设备） | ⬜ 未开始，且建议不做：对目标 IoT 设备无效，需在设备上装证书，与"无需在任何设备上装 agent"直接冲突 |
| F45 手机端可选 MITM 解密（用户自愿，类 Surge/Burp/mitmproxy） | ✅ 新增 `internal/mitm`：本地生成根 CA（ECDSA P-256，私钥 0600 权限落盘不外传）、按 SNI 动态签发叶子证书（共用叶子私钥，只换证书）、HTTP CONNECT 代理终止客户端 TLS 后向真实源站发起**完全校验**的 TLS 转发（无 `InsecureSkipVerify`）。范围有意限定在 CONNECT/HTTPS，普通 HTTP 直接 400。API：`GET /api/mitm/status`、`GET /api/mitm/ca.pem`、`GET /api/mitm/ca.mobileconfig`（iOS 一键安装描述文件）、`GET /api/mitm/exchanges[/{id}]`（内存环形缓冲，重启清空，不落盘——本项目目前处理过最敏感的数据）。默认关闭（`mitm.enabled: false`），需显式打开并重启。**实测**（非模拟）：对真实网站 `https://example.com` 完整走一遍——受信任的 curl 拿到解密后的真实响应体，不信任该 CA 的 curl 被正确拒绝（fail-closed，非静默明文透传）；`.mobileconfig` 用 Python `plistlib` 验证是合法的 Apple 配置描述文件。四类单元测试（端到端解密、未信任客户端拒绝、明文 HTTP 拒绝、mobileconfig 内容校验）`-race` 通过。总览 UI 新增「证书与解密」页面（`BeeEye-web/src/components/Mitm.jsx`）：代理地址/证书指纹/已解密请求数三个数据块、PEM 与 `.mobileconfig` 两个下载按钮、五个平台的"装了证书还要手动做什么"对照表，中英文双语。**缺口**：走的是显式代理（CONNECT），不是透明重定向/iptables 下发，用户需要手动在设备上配置代理地址；解密后的请求/响应列表现已有前端面板（`Mitm.jsx` 新增「Decrypted requests」表格，点击一行展开请求头/响应头/响应体三块，body 按可打印字符显示、二进制字节渲染为 `·` 占位，避免二进制内容破坏面板）；**实测**（非模拟，真实开启 MITM 走一遍完整链路）：信任 CA 的 curl 通过代理访问 `https://example.com` 得到 HTTP 200，该请求实时出现在列表里，展开后能看到完整解密的响应体 `<!doctype html>...Example Domain...`、响应头（`Cf-Cache-Status: HIT`、`Server: cloudflare` 等）与请求头（`User-Agent: curl/8.12.1`）。仍是显式代理（CONNECT），非透明重定向。详见 [TLS-DECRYPT.md §5](TLS-DECRYPT.md)（含四个平台"装了证书之后还要手动信任"的差异表）。 |
| F31 通信记录导出(CSV/JSON) | ✅ `GET /api/export?format=csv\|json`，CSV 带 UTF-8 BOM 以便 Excel 正确读取中文 |
| F33 DNS 异常检测 | ✅ NXDOMAIN 高频（疑似 DGA）已实现；DNS 隧道特征检测已实现——`model.DNSRecord` 新增 `QType`，`internal/detect.DNSTunnel` 检测 TXT/NULL 查询突增+查询名过长+高度集中于单一顶级域名，`TestDNSTunnelFlagsTXTBurstToOneDomain`/`TestDNSTunnelIgnoresOrdinaryBrowsing` 覆盖 |

---

## 二点五、需求之外的补充交付物

### BeeEye-desktop —— 分析器的原生窗口壳

`BeeEye-desktop/src-tauri`：一个约 200 行的 Tauri 2 壳层，把已有的 `BeeEye-gui` Web UI 包装成一个原生窗口。**不复制、不重写**任何前端代码——窗口本质是指向 `http://127.0.0.1:8081` 的浏览器外壳。启动时：若该端口已有后端在跑（如通过 `scripts/dev.sh` 手动起的）就直接连接；否则自动定位并拉起 `BeeEye-gui`/`BeeEye-gui-cuda` 二进制（用 `ip route get` 选默认路由网卡，逻辑与 `scripts/dev.sh` 的 `default_iface()` 一致），关窗口时只杀自己拉起的子进程，不影响用户已有的后端实例。

**与 program.md 里 F40 的设计取向并不冲突**：需求文档反对的是"给 headless 网关本机装原生窗口"（网关没有桌面环境）；这里做的是相反的场景——给**有桌面环境的运维工作站**（Mac/Windows/Linux 桌面）提供一个比浏览器标签页更像原生应用的形态，连接到的后端可以是本机的，也可以是远程网关转发过来的。两者服务不同的部署位置，不矛盾。

**实测**：`cargo build --release` 在真机上编译通过（Ubuntu 24.04，Rust 1.97.1，tauri 2.11.5 + webkit2gtk 依赖链），产出可执行的 ELF 二进制。未做自动化测试（I/O 集成逻辑为主，端口探测/子进程生命周期管理）。

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

**2026-08-19 新增（F10/F11/F20/F29）**
- **威胁情报真实拉取**：`internal/threatintel` 在真机上实测拉取 Spamhaus DROP，得到 **1693 条 CIDR 段**，缓存文件正确落盘到 `data/threatintel/spamhaus_drop.txt`；拉取过程不阻塞 agent 启动（先同步读本地缓存，网络拉取在后台协程）。
- **按需定向抓包端到端可用**：对局域网真实网关 MAC 发起一次 15 秒定向抓包（`POST /api/capture/targeted`），实测抓到 **1811 帧 / 1.6MB**，超时后正确关闭会话；下载得到的 pcap 文件被系统 `file`/`tcpdump` 正确识别读取，且 **1811 帧全部命中目标 MAC**（`tcpdump -e` 逐帧核对，零误判）。
- **接口热插拔对真实内核事件生效**：创建/删除一张 dummy 网卡，`internal/live.WatchLinks` 通过真实 AF_NETLINK 套接字正确收到 `RTM_NEWLINK`/`RTM_DELLINK`；`captureIface`/`autoDiscoverIface` 在网卡出现前后返回正确结果（`main_test.go`，同样用真实 dummy 网卡验证，而非合成数据）。
- **热插拔改动引入的数据竞争已被 `go test -race` 抓到并修复**：`tcapture.Session` 的 deadline 定时器回调与 `Start()` 对 `s.timer` 字段的赋值存在未加锁的并发读写；`api.Server` 的 `SetSource`/`SetTargetedCapture` 在引入热插拔前只在启动时调用一次，从未视为并发场景，现已改为整体原子替换（`atomic.Pointer`），避免读到不一致的三元组。`go test -race ./...` 全绿。
- **回归**：`make smoke` 在本轮改动后重新跑 **24 项全过，0 失败**，确认新功能未破坏既有端点。

**2026-08-19 新增（eBPF 全量抓包）**
- **内核程序编译期真实限制与解法**：`struct BeeEye_event` 因 `PAYLOAD_MAX` 从 512 提到 1536 而超过约 1KB，clang 对 BPF target 直接拒绝内联展开这么大的 `__builtin_memcpy`/`__builtin_memset`（"A call to built-in function 'memcpy' is not supported"）。用手写的 8 字节字长拷贝循环（`#pragma unroll`，205 次迭代，纯线性指令，验证器无需做归纳证明）替代大块 `memcpy`，用 `offsetof` 把 `memset` 范围限制到不含 payload 数组的头部 104 字节。两处改动均已通过 `make bpf-verify` 的真实内核验证器验证。
- **精细截断反而丢数据**：`load_payload` 原本为"选择性上报"设计的离散级联（1536/384/256/…/48/32/16/8）在全量镜像模式下会把恰好落在两档之间的帧过度截断（实测一个 63 字节的完整 DNS 查询帧被砍到 48 字节，DNS 头都不够 12 字节，导致 dissect 解析失败）。改用运行时长度 `len = min(skb->len, PAYLOAD_MAX)` 精确拷贝——验证器通过值域收窄（两次比较后 `len` 被证明落在 `[0, PAYLOAD_MAX]`）接受了这次动态长度的 `bpf_skb_load_bytes`，与代码里旧注释"长度必须是编译期常量"的说法不符，实测证明在本机内核上是可行的。
- **eBPF 数据源端到端验证**：`internal/ebpf.OpenEBPF` 在 `lo` 上抓到真实构造的 DNS 查询，`live.Packet.CapLen` 精确等于原始帧长（63 字节，含以太网头+IP头+UDP头+DNS消息，而非只有协议 payload），re-dissect 结果与 AF_PACKET 路径完全一致。
- **重要的内核行为发现**：`bpftool prog show` 的 `run_cnt` 证实，本机内核上 TCX 链虽然允许多个独立程序同时 attach 到同一网卡同一方向，但**只有第一个 attach 的程序真正被调用**，第二个"成功" attach（无报错）却 `run_cnt` 永远为 0。这直接决定了架构：只让 agent 用 eBPF，分析器继续用 AF_PACKET，而不是让两个进程抢同一个网卡的 eBPF 挂载点。
- **真实网卡端到端验证**：`wlp9s0` 上 agent 通过 `/api/source` 确认 `source: "ebpf"`，`connection_count` 持续增长（28218→28233，15 秒内 +15）；分析器通过 `/api/status` 确认 `source: "af_packet"`，`captured` 持续增长（3602→6227）；F11 定向抓包在 eBPF 数据源下同样验证通过（186 帧/37KB）。
- **回归**：`go test -race ./...` 全绿，`make smoke` 24 项全过。

---

## 四、下一步

> 2026-08-19 更新：GeoLite2 接入、威胁情报公开黑名单接入、CoAP 逐字段解析、行为基线建模、按需触发抓包、接口热插拔、总览"模拟/真实"角标、F19 主题二级入口、**eBPF ringbuf 接入 agent 采集源** —— 以上均已完成，详见上表逐条状态与 §0。以下是重新核对后仍然真实存在的下一步。

按优先级：

1. **TLS 明文捕获阶段二/三** —— pcapng+DSB 导出、GnuTLS/NSS/Go crypto/tls、以及接入分析器 UI 的「明文」面板。技术路线已从 eCapture 源码调研清楚（版本探测+偏移表 vs GoTLS 走 CO-RE，见 §二 F14 条目），不是空泛参考。阶段一（text 模式）已完成，见 [TLS-DECRYPT.md](TLS-DECRYPT.md)。
2. ~~F45 手机端可选 MITM 解密~~ **已实现**（`internal/mitm` + 总览 UI「证书与解密」页面），见 §二 F45 条目与 [TLS-DECRYPT.md §5](TLS-DECRYPT.md)。剩余：解密请求列表的可视化面板、透明重定向（当前是显式代理）。
3. Fingerbank 类型号指纹库接入（F1 缺口）、DNS 隧道特征检测（F33 缺口，NXDOMAIN/DGA 已做）。
4. 门锁/摄像头出站白名单需要 XDP 程序（F9）、高危事件自动阻断联动（F38，开关已预留默认关闭）、剩余 P2 项（F12 流量分类模型 / F13 移动端推送 / F39 恶意下载特征）均未开始。F32 地图可视化已实现，见 §二。
5. （可选，低优先级）排查本机内核 TCX 多程序链只调用第一个 attach 者的行为，判断是这台机器内核的特有限制还是更广泛的现象；如果能解除，分析器也可以在 agent 已经用 eBPF 时改用一种"共享 ringbuf reader"的模式而不必完全放弃 eBPF。目前的收益（分析器继续用久经验证的 AF_PACKET）大于深挖这个内核细节的收益，先如实记录在 §0。
