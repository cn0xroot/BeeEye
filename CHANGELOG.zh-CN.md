# 更新日志

本文件记录 BeeEye 的所有重要变更。

[English](CHANGELOG.md)

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
