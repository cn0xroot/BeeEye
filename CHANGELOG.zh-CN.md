# 更新日志

本文件记录 BeeEye 的所有重要变更。

[English](CHANGELOG.md)

## [未发布]

## [1.1.0] — 2026-08-20

### 新增

- **HTTPS 解密默认开启**：分析器启动即自动挂解密 uprobe（`internal/gui/decrypt.go`），不再需要单独手动操作——实测对真实 curl 流量实时解密。
- **加密库支持改为声明式规则表**：`internal/tlspeek/rules.go`——一条规则（家族名+SONAME 正则+读写符号）用正则跨版本/跨发行版覆盖整个库家族；加一个库家族只需加一行。**GnuTLS** 现与 **OpenSSL** 并列支持（参考机上同时挂载 72 个 GnuTLS 进程 + 44 个 OpenSSL 进程）。
- **加密库检测**：`BeeEye-tlspeek -detect` + `GET /api/decrypt/libs` 逐库报告 ELF 符号是否真的存在（区分"装了"与"可挂载"），并**从库文件内嵌的版本横幅解析出确切版本号**（如 `OpenSSL 3.0.13`、`GnuTLS 3.8.3`），能正确区分同一台机器上不同环境安装的两个不同 OpenSSL 版本。
- **F22 真正接入 GeoIP 数据库**：`internal/geoip/mmdb.go` 加载标准 MaxMind 格式 `.mmdb`（`geoip2-golang`），自动发现 `./data/`、`/usr/share/GeoIP/`、Clash 的 `Country.mmdb`；有 City 库解析国家/省/市，有 ASN 库解析运营商。新增 `GET /api/geoip/status` 与总览 UI 精度徽章（`GeoAccuracyBadge.jsx`），告知当前是精确定位、仅国家级还是内置粗表兜底。新增 `scripts/geoip-setup.sh` 引导下载 GeoLite2-City/ASN（需用户自备免费 MaxMind 账号）——下载本身不违反"不做在线逐 IP 查询"的隐私要求，文件落地后每次查询都是本地的。
- **F45 解密请求列表 UI**：MITM 代理的 `/api/mitm/exchanges` API 现在有前端面板（`Mitm.jsx`）——实时更新的解密请求表格，点击展开请求/响应头与正文（二进制字节渲染为 `·` 占位）。实测端到端 MITM 会话：受信任客户端解密后的 `GET https://example.com` 出现在列表中，完整响应体可见。
- **F32 世界地图由 3D 地球改为 2D + GPU 渲染**，按用户明确要求实现：`WorldMap.jsx` 取代已删除的 `Globe.jsx`。WebGL2 片段着色器把目的地渲染成**加法混合的径向辉光**（重复/叠加的流量会自然更亮）与动画弧线；配色实时读取当前主题的 CSS 变量。新增 Canvas2D 兜底渲染器（同样的径向渐变视觉语言），覆盖没有 WebGL2 的浏览器/环境，地图在任何情况下都有画面而不是报错。
- **两个 UI 新增外观设置面板**：带实时预览色板的主题选择器（总览 UI 9 套、分析器 5 套，含两套新的高饱和度主题——**午夜霓虹**与**矩阵绿**）、字体选择器（系统/科技等宽/圆润/衬线，每个选项用其自身字体渲染）、字号选择器（S/M/L/XL，CSS zoom 实现）。三项均按浏览器持久化，两个 UI 各自独立记忆。
- 新增 `INSTALL.md` / `INSTALL.zh-CN.md`：面向全新干净主机的从零搭建指南，含本项目实际开发测试所用的真实硬件/软件版本。
- 新增双语 `USAGE.en.md`，与 `USAGE.md` 保持同步，英文 README 已链接。

### 修复

- **分析器布局 bug**：选中一个包后，详情区会遮盖包列表，导致看不到其它流量。根因：端点信息条和解密明文面板被当作 grid 的隐式子元素插入，破坏了原本的 2 列/3 列结构。修法：把详情区整体包进一个 flex 容器作为 grid 的第二行，下半区改为显式 3 列（字段树/十六进制/明文），每个面板内部独立滚动，绝不会撑大到遮住上方的包列表。
- 新增版本探测功能时发现并修复两个加密库检测 bug：GnuTLS 的标记字符串可能匹配到库里含 "GnuTLS" 字样但无关的字符串（它自己的错误信息表）而非版本横幅——修法是要求标记后紧跟一个数字；OpenSSL 的版本字符串通常在 `libcrypto` 里，即使 `libssl` 是独立文件也是如此——修法是在给定 `libssl` 路径找不到时，回退去它同目录的 `libcrypto` 文件里找。
- **解密挂载 bug**：曾尝试对 `libcrypto`（不导出 `SSL_write`/`SSL_read`，只有 `libssl` 才有）挂 uprobe，以及对从 `/proc/*/maps` 发现、但挂载时磁盘上已不存在的库路径（进程已退出，或路径在挂载命名空间之外）尝试挂载——均已修复：只挂规则匹配的 libssl 家族路径，且跳过 `os.Stat` 失败的路径。

- **F10 设备行为基线建模**：`internal/detect.Engine.Baseline` 按设备+小时分桶学习流量分布（对该小时桶历史天数用 Welford 在线算法求均值/标准差），今天该小时的流量超过可配置的 z-score 阈值即判定离群——例如一台只在 09:00–18:00 通信的 NAS 突然在 03:00 活跃。与其它检测器保持一致的纯函数风格，不持久化模型。
- **F11 按需精细抓包**：`internal/tcapture` + `POST /api/capture/targeted` 触发一次全新的、按 MAC 过滤的限时/限字节数抓包，区别于 F44 对既有环形缓冲的导出。已对真实网关 MAC 实测：抓到 1811 帧/1.6MB，下载后的 pcap 逐帧回读全部命中目标 MAC。
- **F20 接口热插拔自动发现**：原始 AF_NETLINK 监听（`internal/live/hotplug.go`）在网卡出现/消失时无需重启即可响应；`auto_discover.exclude_patterns`（配置里从项目之初就存在但从未被消费）现在真正驱动接口选择。已用真实 dummy 网卡验证内核事件解析与网卡出现前后的接口选择逻辑。
- **F29 真实威胁情报源**：`internal/threatintel` 把"调用方注入一切"换成真实的 Spamhaus DROP 黑名单拉取、本地磁盘缓存与后台定期刷新，绝不因网络拉取阻塞抓包。`detect.ThreatIntel` 在既有精确匹配集合之外新增 CIDR 段匹配（`BadCIDRs` + `MatchIP`）。实测：拉取并缓存了 1693 条 CIDR 段。
- **F4 CoAP 逐字段解析**：完整实现 RFC 7252 解析（头部、token、delta 编码选项——Uri-Path、Uri-Query、Content-Format、Observe 等），而不仅仅是协议识别。
- **eBPF ringbuf 接为 agent 采集源**：内核 CO-RE 程序新增全量镜像模式（`EVT_RAW_FRAME` + `CFG_RAW_FRAME_MODE`），无差别镜像每个包的完整原始帧，由 `internal/ebpf.OpenEBPF` 包装成与 AF_PACKET 结构完全一致的标准 `live.Source`。`internal/capsource` 实现"eBPF → AF_PACKET → 模拟器"三级回退链，`internal/livesource`（agent）已接入。实测在真实网卡上验证：`source: "ebpf"`，`connection_count` 实时增长。
- README 新增**参考与致谢**章节，列出 BeeEye 设计上借鉴的项目（Wireshark、[eCapture](https://github.com/gojue/ecapture)、[Pcap-Analyzer](https://github.com/HatBoy/Pcap-Analyzer)）以及代码所依赖的开源库。
- **BeeEye-desktop**：约 200 行的 Tauri 2 壳层（`BeeEye-desktop/src-tauri`），把已有的 `BeeEye-gui` Web UI 包装成运维人员桌面上的原生窗口——连接已在运行的后端，或自己拉起一个，关窗口只杀自己拉起的子进程。不复制任何前端代码。实测在参考机上编译出可用二进制。

### 修复

- `tcapture.Session` 的定时器超时处理存在数据竞争（`s.timer` 赋值时未持有回调读取它时所用的锁），已被 `go test -race` 在合并前抓到并修复。
- `api.Server` 的数据来源与定向抓包状态（`SetSource`/`SetTargetedCapture`）在热插拔 supervisor 开始在运行时多次调用它们后，存在被并发读到"更新一半"状态的风险；现已改为对不可变快照做整体原子替换，而不是各自独立的普通字段，避免并发读者看到不一致的组合。
- `dns.id` 字段被注册了两次、两种不同格式（十进制与 `0x` 十六进制），导致过滤/回读该字段会拿到两个值；现已统一为只注册一次（十六进制，与协议树里的展示值一致）。

### 说明

- 发现但不算需要修复的 bug，记一笔：本机内核上，TCX 只会真正调用挂在同一网卡同一方向上**第一个** attach 的 eBPF 程序；第二个"成功" attach（不报错）却永远不会被调用（用 `bpftool prog show` 的 `run_cnt` 证实）。因此只有 agent 使用 eBPF，分析器有意保持用 AF_PACKET，避免两个进程抢同一张网卡的挂载点。

## [1.0.0] — 2026-08-19

首个正式标记版本。BeeEye 是面向家庭 IoT 网关的流量分析系统：两套互不影响的
独立 UI（常驻的总览界面 + Wireshark 风格的实时分析器），均由真实抓包驱动，
另含离线 pcap 分析、eBPF/AF_PACKET 采集、CUDA 加速可视化渲染，以及基于多信号
加权的检测引擎。

### 新增

**采集与内核态**
- eBPF CO-RE 采集程序（`BeeEye-agent/bpf/BeeEye.bpf.c`），通过 TCX 双向挂载，
  配合 ringbuf 事件通道、LRU 流表，以及按设备类别的差异化上报策略（门锁/摄像头
  逐流上报，其余类别走聚合快照）。
- AF_PACKET 原始套接字抓包（`internal/live`、`internal/livesource`）作为两个
  二进制的默认真实流量来源——不依赖 libpcap，不使用 CGO。
- `any` 伪接口：一次性跨全部网卡抓包，并按包还原出真实来源接口名。
- 如实降级：仅在无法进行原始抓包时才回退到内置模拟场景，并始终在启动日志与
  分析器状态栏中明确标注，绝不把模拟流量当真实流量呈现（F43）。
- `BeeEye-tlspeek`（`cmd/BeeEye-tlspeek`、`internal/tlspeek`）：基于 uprobe 对
  动态链接的 OpenSSL 进程做 TLS 明文捕获；另配 `scripts/tls-decrypt.sh` 通过
  `SSLKEYLOGFILE` 解密 Chromium/Electron 应用流量。详见 `TLS-DECRYPT.md`。

**协议解析与过滤**
- 分层协议解析器：以太网/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP，以及
  DNS/mDNS/TLS/HTTP/MQTT/SSDP/DHCP 应用层解析。
- TLS 指纹：SNI、ALPN、JA3（按 RFC 8701 剔除 GREASE 值）。
- 兼容 Wireshark 语法子集的显示过滤器语言（`internal/dfilter`）：`&&`/`||`/`!`、
  比较运算符、`contains`、`matches`（正则）、地址字段 CIDR、协议存在性判断——
  前端校验与实际过滤共用同一个解析器，不存在两套语法互相漂移的问题。
- 过滤器模板菜单：内置协议、IP 及其它常用过滤规则，选中后立即生效。

**检测引擎**
- 九类加权检测信号（`internal/detect`）：威胁情报比对、信标（基于时间间隔变异
  系数的 C2 心跳检测）、扇出/扫描、横向（东西向）移动、DNS 异常、地域异常、
  非常规时段活动，阈值可配置，风险分级为 高/中/低。

**归属与映射**
- 进程归属（`internal/procmap`）：通过 `/proc/net/{tcp,udp}` + `/proc/*/fd` 将
  实时流量映射到本机拥有该连接的进程，且对其它设备的流量正确地拒绝归属，而
  不是硬安在某个巧合的本机进程上。
- IP↔主机名/域名关联（`internal/namemap`）：从 DNS、TLS SNI、HTTP Host、mDNS
  流量中实时学习，按来源可信度排序；绝不发起反向 DNS 查询（会向第三方解析器
  泄露访问目的地）。
- 离线 GeoIP（`internal/geoip`）：全离线查询，私有地址/CGNAT 正确标注为本地。

**离线与实时 pcap 分析**
- pcap 文件读取器（`internal/pcapfile`）与分析引擎（`internal/analyze`）：
  协议/会话双方/会话统计、TCP 流重组、明文凭证提取
  （FTP/POP3/IMAP/SMTP/HTTP Basic/HTTP 表单/Telnet）、按魔数做文件提取，以及
  启发式攻击模式检测（SQL 注入/XSS/目录遍历/命令注入/webshell/扫描器/IoT
  漏洞利用）——每条发现都显式标注 `Heuristic: true`。
- `POST /api/pcap/upload` 及配套报告接口，后端为纯内存存储（报告可能包含明文
  凭证，因此绝不落盘）。
- 总览 UI 新增「抓包分析」视图，参考 Pcap-Analyzer：拖拽上传、九个报告页签
  （摘要、协议、会话方、会话、TCP 流、凭证、提取文件、安全发现、地理位置），
  并在界面上明确提示提取出的凭证/文件应视为已泄露/不可信。
- 同一套分析引擎已接入实时分析器，供实时流量使用。

**可视化**
- CUDA 加速的流量场渲染（`BeeEye-agent/cuda/BeeEye_render.cu`）：色相承载协议
  身份，亮度承载流量大小；无 GPU 时自动回退到与 CUDA 结果逐位一致的 Go CPU
  实现（`internal/render`）。包列表、字段树、流量场统一使用经对比度与色觉障碍
  分离度校验过的彩色调色板（分类色板 + 顺序色板）。
- 实时分析器新增亮/暗主题切换；总览 UI 提供六套主题（light、dark、tech-blue、
  warm-amber、forest-green、high-contrast）。

**界面**
- 双前端、双进程、双端口，仅在编译期共享源码，运行期互不依赖（`smoke.sh` 中
  通过挂起分析器进程、验证总览 API 仍能正常应答来证明这一点——F42）。
- 两套前端均通过 `react-i18next` 实现完整中英文切换，顶栏即时生效。
- 实时分析器：包列表/协议字段树/十六进制视图三窗格联动选中、选中数据包自动
  展开详情；列可排序；自动滚动改为持久化的开关状态（而非临时状态）；新增
  进程归属列；支持 PCAP 导出（F44）。
- 总览 UI：总览、设备、连接、按 IP、按协议、DNS、告警、抓包分析共八个视图，
  另有 Top N 排行榜及带 UTF-8 BOM 的 CSV/JSON 导出（便于 Excel 正确显示中文）。

**部署与文档**
- `start.sh` 一键启动、`scripts/dev.sh`（start/stop/restart/status/logs）、
  `Makefile`、`docker-compose.yml`，以及 `scripts/smoke.sh`——24 项端到端检查，
  覆盖两套 UI、SSE 推流、过滤器校验、经 `tcpdump` 回读验证的 pcap 导出，以及
  双进程隔离性。
- 中英文双语文档：`README.md`/`README.zh-CN.md`、
  `INSTALL.md`/`INSTALL.zh-CN.md`、`PROGRESS.md`/`PROGRESS.en.md`、
  `program.md`/`program.en.md`，另有 `ARCHITECTURE.md`、`USAGE.md`、
  `TLS-DECRYPT.md`。

### 修复

- 选中数据包后详情面板空白：字节切片在 JSON 中被序列化为 base64 字符串，前端
  却当字节数组处理；已通过 `decodeBytes()` 修复。
- 中英文切换不生效：i18next 通过 `languageOnly` 把 `zh-CN` 归一到 `zh`，但语言
  资源却以 `zh-CN` 为键，导致每次查找都静默回退英文；现已统一改为 `en`/`zh`
  两个键。
- 选中数据包后协议字段树未自动展开，仍需手动点击。
- 关闭自动滚动后，下一次滚动事件会把它悄悄重新打开；现已改为真正的开关状态，
  跨会话保持，并会忽略分析器自身触发的程序化滚动。
- 在没有匹配明文流量的真实局域网抓包下，过滤器模板看起来"不生效"：模板选中
  后已改为立即生效，并且空状态现在会区分"过滤器命中零个数据包"与"尚未抓到
  任何数据包"两种情况。
- 网卡选择器缺少 "any"（全部网卡）选项。
- 时间戳未按系统本地时间显示。
- `dev.sh restart` 偶发报 "address already in use"：stop 在进程真正退出前就
  返回了；现已改为轮询等待进程退出后再允许 restart。
- 四色图层调色板未通过色觉障碍校验（红色盲下两个色相难以区分）；已替换为三个
  校验通过的色相加一个中性灰，并全程配文字标签，避免颜色单独承载身份信息。
- 内核态与用户态事件结构体字段顺序调整后可能悄悄错位；现已加入基于 BTF 的
  布局测试，一旦错位即导致构建失败。

[English changelog →](CHANGELOG.md)
