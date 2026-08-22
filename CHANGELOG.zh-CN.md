# 更新日志

本文件记录 BeeEye 的所有重要变更。

[English](CHANGELOG.md)

## [1.3.1] — 2026-08-22

### 移除

- **彻底移除了模拟抓包回退机制**（F43 贯彻到底）：agent 侧一次性的、固定十个虚构设备的演示场景（`internal/capture.GenerateSimulated`）和分析器侧持续生成合成数据包的生成器（`internal/live.OpenSimulated`）都已删除，连带 `-simulate` 参数和 `simulate_seed` 配置项一并去掉。`internal/live.Open`/`internal/capsource.Open` 现在在找不到真实抓包源时直接返回错误，而不是退化成合成数据——总览和分析器会诚实地显示"无数据/不可用"，而不是伪造流量。这也顺带修复了背后真正的 bug：`internal/gui.Session.Start` 之前即使 `live.Open` 失败也会无条件调用 `startWith`，导致真实抓包打不开时分析器会悄悄跑在假数据包上——现在会直接把这个错误原样返回。两端前端状态栏里的"模拟数据"徽章也都换成了诚实的"不可用/非实时"提示。

### 修复

- **过期的模拟场景数据会永久污染真实设备列表**：在上面这次移除之前，只要同一个磁盘数据库曾经有一次因为打开真实抓包源瞬时失败（或者跑过 `-simulate`）而回退到模拟场景，它固定的十个虚构设备（`front-door-lock`、`kitchen-echo`、`synology-nas` 等）就会被写进和真实抓包完全同一套 `device_registry`/`connections`/`dns_records`/`events` 表，落盘之后没有任何字段能区分它是不是真的——于是总览会一直混着这些从来没在网络里出现过的幽灵设备。`main.go` 里的 `legacySimulatedMACs` 仅为这一次性迁移清理保留了这份固定的、已知的 MAC 列表：agent 一确认真实抓包在正常工作，就会调用 `store.PurgeByMAC` 把这些行清掉——在这台机器自己的数据库上验证过：设备数从 18（10 个假的 + 8 个真的）降到 8 个真实设备，`/api/devices` 里那些虚构主机名也一并消失了。

## [1.3.0] — 2026-08-21

### 新增

- **设备分级连接事件记录，AF_PACKET 路径也生效了**（F5）：门锁/摄像头类设备（`DeviceCategory.Sensitivity() == 3`）新连接建立的瞬间就单独记一条事件，不用再等下一次 5 秒聚合刷新才出现——之前只有 eBPF 内核路径有这个待遇，现在 agent 的 AF_PACKET 回退路径和 `BeeEye-gui` 也一样实时。
- **被动设备指纹终于接到了 `identity.Identify`**（F1）：DHCP 选项 55/60、HTTP User-Agent、SSDP 的 `Server:` 头解析器早就有了，但从没被送到包详情树以外的地方。`internal/identity` 新增 `Fingerprint` 参数（vendor-class/user-agent/SSDP 提示按由强到弱依次生效，只在分类未知时才采纳），DHCP 自带的 `chaddr` 字段用来把指纹归属到正确设备，即便这台设备还没分到 IP。
- **DNS 隧道检测**（F33 的另一半缺口——NXDOMAIN/DGA 检测早就有了）：`model.DNSRecord` 新增 `QType` 字段（同样从解析层打通），`internal/detect.DNSTunnel` 检测 TXT/NULL 查询突增、查询名异常长、以及高度集中在单一顶级域名下的设备——这是一条正常工作的隐蔽信道会有的形状，仅靠 DGA/NXDOMAIN 启发式看不出来。
- **世界地图：点击目的地可以固定详情面板**——之前悬浮才有提示框，鼠标一移开就消失，完全没有点击交互。现在点击会固定面板（点空白处取消固定），新增坐标行，加载了 ASN 级 GeoIP 库时还会显示目的地的网络运营商（如"China Telecom (AS4134)"）——`geoip.Lookup` 早就解析出这个字段了，只是一直没传进 `GET /api/views/geopairs`。
- **Traffic Field 新增 SIP/SCTP/GTP/SIM 显示行**——这几个协议解析器上一个版本就有了，但色场固定的 8 通道分类器（`internal/gui.RenderChannels`）一直没跟上，这类流量全部悄悄落进了"other"。现在扩展到 12 通道，新增经色觉障碍校验的配色，同步到全部四套分析器主题（dark/light/midnight-neon/matrix）以及包列表用的 CSS 端 `protocolSlot` 分类器，保证包列表行颜色和色场行颜色始终一致。
- **Traffic Trend：GPU 辉光回来了，作为背景氛围叠在可读的 SVG 图表之下**——之前那次把图表重写成带真实坐标轴/网格线/数字的 SVG 没有改动，仍然是回答"具体多少字节"的地方；但仍然支持 CUDA 的 `GET /api/render/traffic.png`（重写之后一直被晾在那没人用）现在以低透明度叠加混合的方式铺在 SVG 背后，图例旁边也加了 GPU/CPU 渲染后端角标（和分析器自己的渲染角标同一套诚实原则——绝不冒充没有真的在用的 GPU 渲染）。
- **Traffic Field：离线抓包新增协议占比**——一份导入完成的离线抓包是固定、完整的东西，"这份文件到底由什么协议构成"比看一个再也不会有新包进来的实时滚动色场更有用。新增 `GET /api/render/totals`，暴露一个不会衰减的、按通道统计的字节数累计总量（`Session.channelBytes`，和色场自己那个只有约 82 秒窗口的滚动历史是分开的——不然一份早就导入完的文件的数据用不了一分钟就会被滚出窗口）。协议图例现在给每一行显示占比百分比和一条按比例填充的底色条，行的顺序不变（还是 RenderChannels 固定顺序），因为它要和色场图像本身逐行对应。

- **Traffic Trend：曲线平滑、渐变填充、KB/MB/s 单位显示修正**：折线/面积路径改用 Catmull-Rom 转贝塞尔曲线，不再是样本点之间的直线段；面积填充改为向基线渐隐，不再是一块平色；折线本身加了一圈同色的柔光。图例的实时速率和 Y 轴刻度都从 `formatBytes`（没有针对速率场景的下限处理）换成 `formatRate`，近乎空闲的链路现在显示"0.2 KB/s"，而不是"187.8095245361328 B/s"这种带一堆小数位的怪数字。
- **抓包分析报告（program.md 里致谢的 [Pcap-Analyzer](https://github.com/HatBoy/Pcap-Analyzer) 那套功能形态）从总览搬进了分析器**，和打开一次实时抓包一样，用工具栏的"打开文件"即可触发，在包列表旁边新增一个"报告"标签页——概要/协议/通信主机/会话对/会话内容/明文凭据/传输文件/安全发现/地理分布,总览原来那个上传页签的九个视图一个不少。总览那边这个页签换成了一个"在分析器中打开 ↗"链接，毕竟文件现在是在分析器里看的。
- **新增 GPU 渲染的柱状图**（`render.Renderer.RenderBars`，`cuda/BeeEye_render.cu` 新增 `beeeye_render_bars` kernel + 对应 CPU 回退实现，`TestBarsBackendsAgree` 覆盖——在真实 RTX 2080 Ti 上验证过像素级一致，最大通道偏差为 0）：报告里的协议/通信主机/会话对三个面板现在都以一条会发光的排名柱状图打头，配色和视觉语言与 `Render`/`RenderCurve` 完全一致，用的是色场和包列表同一套调色板，而不是 Pcap-Analyzer 原本的纯表格——`GET /api/report/bars.png?kind=protocols|talkers|conversations`。
- **`./start.sh`现在也能编译、启动 BeeEye-desktop 了**：`--desktop` 在 Rust 源码过期时自动重新编译原生窗口壳（和脚本里其它构建步骤同一套"没过期就跳过"规则），编译完在两个后端起来之后顺带启动它。之前唯一有文档记录的构建方式是 `scripts/build-deb.sh` 里那次性的 `cargo build --release`。
- **BeeEye-desktop：默认/第一个标签页换成了分析器，和总览对调**——窗口打开后直接进包级视图，而不是总览仪表盘。

### 修复

- **网卡卡片的实时速率可能显示成"卡住不动"**：`/api/iface/info` 没设 `Cache-Control`，导致 fetch 有可能复用缓存响应；现在后端和前端轮询都显式禁用缓存，确保每 2 秒都拿到真实新值。
- **网卡卡片文字过于局促、偏小**：标签和数值字体都调大，间距也放宽了。
- **左右拉伸会导致 Traffic Field 显示内容跟着变形/错位**：色场画面是服务端渲染的固定分辨率位图，`height: auto` 导致拉伸宽度时图片的*显示高度*也跟着变。现在高度固定为请求时的像素值，只有宽度随容器变化，回到设计初衷。
- **`formatBytes` 在小于 1KB 时会显示未取整的原始小数**（如"187.8 B"）——现在和其它数量级一样先取整。
- **打开离线抓包，Traffic Field 什么都不显示**：离线文件是能读多快就重放多快，不是按真实时间节奏播放的，所以 `Session.consume()` 往往在导入开始后的一个状态轮询周期内，就已经把每个包写进色场历史、又把 `status.running` 翻回 `false`——比前端能观察到 `running` 变 `true` 还快。`TrafficField.jsx` 之前只在 `running` 为真时才去取新帧，于是压根没请求过能反映这次导入内容的帧，反而用"空闲"提示把屏幕上原有的画面盖住了。现在改为在 `running` 从真变假的那个瞬间也补一次请求，"空闲"提示也只在还从没成功加载过任何一帧时才显示。
- **世界地图对本来就没法定位的流量显示"0 destinations"，看起来像坏了**：对照真实运行中的 agent 验证过——GSMTAP/SIM 读卡器抓包（`internal/dissect/gsmtap.go` 解析的那类流量）走的是本机回环（两端都是 `127.0.0.1`），根本没有对外的 IP 目的地可以画在地图上，`GET /api/views/geopairs` 按设计正确地把它过滤掉了（`c.Internal`/`geo.Local`）。这和真正的故障从外观上完全分不清。现在目的地数为 0 时地图会显示说明文字，而不是一块沉默的空白画布。
- **Traffic Field 每行太短，看不清楚**：高度原来固定 168px，是还只有 8 个通道时定下的比例（每行 21px）；后来扩到 12 个通道（SIP/SCTP/GTP/SIM）却没人跟着改高度，直接被挤到每行 14px。现在高度按实际通道数计算（每行 24px，夹在 168～420px 之间）——12 个通道正好落在 `render.DefaultHeight`（288px）上，这不是巧合。
- **设备可能被错误分类为有线/无线，尤其是本项目自己的开发机从没遇到过的网卡**：`isWireless` 原来是靠网卡名字猜的（"以 `wl` 开头"、"包含 `wlan`"）——覆盖了常见的 systemd 可预测命名和老式 `wlanN` 命名，但遇到自定义 udev 改名的网卡、或者某些老驱动自己的命名习惯（`ath0`、`ra0` 等）就会猜错。现在改成读 `/sys/class/net/<网卡名>/phy80211`——和 `iw dev` 自己判断"这是不是无线网卡"用的是同一个、和名字无关的信号，不再猜名字。`TestIsWirelessAsksTheKernelNotTheName` 对着运行测试这台机器上真实存在的每一个网卡核对同一条 sysfs 路径，而不是断言某种命名规律。
- **BeeEye-desktop 的"总览"标签页可能永远卡在"尚未就绪"**：桌面壳之前只会自动拉起分析器后端（BeeEye-gui，:8081），"总览"标签页真正要用的 BeeEye-agent（:8080）留给 `start.sh`/`systemd` 单独启动——通过 `./start.sh --desktop` 打开没问题，但如果是单独打开这个 app（最典型的场景：装了 `.deb` 之后点桌面图标），从来没人叫 agent 启动过，自然一直不显示。这和关闭窗口时的清理逻辑本来就不一致——那边早就是不管两个后端是不是自己启动的、统一都杀掉。现在改成对称地把两个后端都自动拉起来，和"关闭时对称地都杀掉"保持一致——端到端验证过：单独启动桌面二进制、启动前这台机器上没有任何 BeeEye 进程在跑，`:8080` 和 `:8081` 最终都自己起来了。

## [1.2.0] — 2026-08-21

### 新增

- **BeeEye-desktop 合并为单窗口标签页**：桌面客户端不再在总览和分析器两个 UI 之间跳转导航，`dist-placeholder/index.html` 改为常驻的标签切换外壳，两个 Web UI 都以懒加载探测的 iframe 承载。关闭窗口时无论桌面客户端自己启动的是哪个后端，总览和分析器两个后端进程都会一并退出——进程定位改用各自的 `.run/<name>.pid` 文件，而不是 `ss -tlnp`（后者无法向其他用户报告 setcap、不可 ptrace 的进程 PID）。
- **离线分析现在支持 pcapng，不再只支持经典 pcap**：新增完整的 pcapng 读取器（`internal/pcapfile/pcapng.go`）——Section Header Block 字节序探测、Interface Description Block（时间戳精度*与*链路层类型)、Enhanced/Simple Packet Block，接入与经典 pcap 相同的 `pcapfile.Open` 自动识别。
- **导入抓包现在会同步更新总览，而不只是分析器**：`livesource.ImportFile` 把文件重放走与实时抓包完全相同的设备/连接/DNS 聚合流程，分析器里打开的文件不再和总览显示的内容对不上。由于导入文件自身的数据包时间戳可能很旧，会被总览按时间倒序的默认视图挤出实时流量的窗口，受影响的接口（`geopairs`、`summary`、`views/protocol`、`views/topn`）新增了按 `iface` 限定单次导入批次的能力，总览世界地图也新增了导入选择器，90 秒内新导入的批次会自动切换过去。
- **新增协议解析**：SIP（请求/状态行、From/To/Call-ID/CSeq/Via/Contact，兼容 RFC 3261 §7.3.3 压缩头）、SCTP（chunk 类型、DATA 的 TSN/流 ID/载荷协议标识)、GTP-U/GTP-C 隧道解封装（自动递归解析 G-PDU 内层的 IPv4/IPv6 包，隧道内设备真正在做什么——TLS、HTTP、SIP、DNS——不再被"UDP 2152"这一层遮住)。已用一份包含 GTP 内嵌 SIP/SCTP/TLS 流量的真实抓包端到端验证。
- **世界地图**：新增海岸线轮廓、只要流量持续就一直脉冲的光点动画（不再只在目的地首次出现时触发一次）、脉冲方向按实际上下行流量哪边更多决定（不再总是朝外扩散）、悬浮提示显示连接两端可解析到的国家/省份/城市（非本地一端有真实地理坐标时，比如 GTP 隧道解开之后)。
- **TRAFFIC TREND 改为纯前端 SVG 图表**（`TrafficTrendChart.jsx`），带真实的 Y 轴字节数刻度线、X 轴时间刻度、图例——取代此前 GPU 渲染的发光图（好看但看不出具体数值)。上行（本网关发送）与下行（接收）以公共基线镜像展开、共享同一坐标刻度，尺寸与世界地图卡片保持一致。
- 新增顶层 `ErrorBoundary`（按当前标签页重新挂载），某个页面渲染出错不会再把整个导航栏一起拖垮。
- 分析器不再打开就自动开始抓包；新增 `-autostart` 参数给需要旧的"立即开始抓包"行为的脚本化/无人值守部署使用。
- **新增 GSMTAP/SIM 解析器**，离线导入现在能解析 SIMtrace 一类的抓包：完整的 ISO/IEC 7816-4 APDU 解析（CLA/INS/P1/P2、SELECT 按 AID 还是按路径——依据 ETSI TS 102.221 §11.1.1 由 P1 区分，而不是靠数据长度/形状，后者并不可靠、SELECT、READ/UPDATE BINARY/RECORD、VERIFY/CHANGE/UNBLOCK CHV、RUN GSM ALGORITHM、STATUS、GET RESPONSE 等)、57 个 (U)SIM 文件名对照表（MF/DF/EF）、状态字含义解读——每个字段都对照 `tshark` 对同一份真实抓包的解析结果逐一核对过，不是凭记忆猜的。
- **分析器明文面板新增中英双语的协议用途说明**（针对 SIM/GTP/SCTP）：这几类协议本来就不可能有网关自己能解密的 HTTPS 明文，之前这个面板只会显示"无内容可解密"，现在会同时用中英文说明选中的消息实际是做什么的（比如 SIM 的 `RUN GSM ALGORITHM` 或 GTP 的 `Create PDP Context Request` 各自的作用)。
- **总览页新增彩色网卡信息卡片**：显示当前抓包所用网卡的 IP、MAC、直接读取内核网卡计数器得到的实时上下行速率、累计流量，以及（无线网卡时）通过 `iw` 获取的 SSID/信道/信号强度——每项信息用不同的鲜艳颜色，类 conky 风格。
- 导入范围限定（按导入批次的 `iface` 筛选）现在也覆盖了"通信记录""按 IP""DNS"这几个视图，与已经支持的世界地图/总览卡片/按协议视图保持一致；DNS 记录新增了自己的 `iface` 字段，一条 DNS 查询也能追溯回它来自哪次抓包。

### 修复

- **Raw IP / Linux cooked capture 链路层类型被当成以太网解析**：在隧道/VPN 类接口上抓的文件根本没有链路层头，解析器却把 IP 头自己的字节读成了一对 12 字节的假 MAC 地址——真实的源/目的地址变成乱码，后面的层全部无法解析。`dissect.Packet` 现在会根据抓包实际的链路层类型（`LINKTYPE_RAW`/`DLT_RAW`/`LINKTYPE_LINUX_SLL`）分支处理，而不是无条件当成以太网。
- **"That packet is no longer buffered" 频繁出现**：根因是数据目录被静默地归属到了与抓包进程不同的用户，导致环形缓冲区淘汰旧包后本该读取的磁盘兜底被禁用。
- **StatusBar 的 "Displayed" 计数**此前用的是浏览器本地包列表长度（会被前端保留上限截断），而不是服务端权威的、经过过滤器匹配的计数——现在直接读取轮询到的 `status.displayed` 字段。
- **世界地图渲染崩溃可能导致面板永久黑屏**：Canvas2D 兜底渲染器（WebGL2 不可用时使用）在某些情况下会把非法数值传给 `createRadialGradient`，而它的渲染循环只在自己最后一行代码里重新调度下一帧——一帧出错就导致动画永久停止。现在 Canvas2D 和 WebGL 两条渲染路径都会捕获单帧内的异常并继续调度，另外也直接加固了几个具体的非法值来源（布局尚未完成时画布尺寸为 0、退化的弧线数据）。
- 离线回放中的一处并发竞态（`Session.startWith`）：刚停止的抓包的尾部写入可能落进刚重置的环形缓冲区，最明显的表现是刚打开的文件其"已捕获/已缓冲"计数对不上。
- **世界地图流量光点不再跳动**：一条弧线的"出生时间"（有新流量时记录）和渲染循环自己的时钟用的是两套不同的计时起点——一个从页面加载算起，一个从地图组件挂载了多久算起——地图挂载超过一瞬间之后，弧线算出来的年龄就会永远是负数。脉冲点因此被死死卡在弧线起点，弧线本身也永远不会过期。现在 Canvas2D 和 WebGL 两条渲染路径都改成了与"新建弧线"那次轮询用同一套时钟计算年龄。
- **前端旧版本可能会在重新部署后继续运行很久**：`index.html` 之前完全没设置 `Cache-Control`，浏览器可以按自己的启发式策略把它（以及它指向的旧版带哈希 JS/CSS）缓存相当长一段时间。现在 `index.html` 每次请求都强制重新校验；它指向的带哈希 `/assets/*` 文件（内容一变文件名必换）则可以放心让浏览器长期缓存，本来就是安全的。
- **`/api/summary` 有时要好几秒，页面看起来像卡住/空白**：之前是把 connections 表*全部*读到 Go 里再手动求和，每个打开的标签页每 3 秒轮询一次——表只有几百行时没问题，长时间抓包攒到几万行后就变成了每次几秒的卡顿。现在改成用一条 SQL 聚合查询（`ConnectionTotals`）让 SQLite 自己算好，只返回一行，与表大小无关。
- 世界地图的 WebGL 上下文现在会在组件卸载时主动释放（`deleteProgram`/`deleteBuffer`/`WEBGL_lose_context`），不再留给浏览器自行回收——这是针对某些 WebView 引擎在反复挂载/卸载（比如快速切换标签页）时容易出现 GPU 上下文释放崩溃的一次防御性加固，也是目前对"桌面客户端里页面变黑屏、导航失灵"这个还未确认根因的报告的主要怀疑方向。

### 备注

- 仍在排查：HTTPS 解密偶尔会在挂载时报 `opening mem: open /proc/self/mem: permission denied`，即便进程持有预期的能力位。已经定位到具体触发条件——`cilium/ebpf` 只有在加载 `Kprobe` 类型的程序（uprobe 也算)时才会做一次会打开 `/proc/self/mem` 的内核版本探测，所以这是解密这条路径特有的，不是通用的权限问题——但这次 open 本身失败的根本原因还没找到。
- 仍在排查：桌面客户端（Tauri 窗口，Linux 上用的是 WebKitGTK 而不是本项目其它测试全程使用的 Chromium 内核）特有的一个间歇性"页面变黑屏、其它标签也点不动"的报告。上面的 GPU 上下文释放加固是基于原理分析的合理缓解措施，不是已确认的修复——在纯 Chromium 测试环境里既无法复现也无法验证。

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
