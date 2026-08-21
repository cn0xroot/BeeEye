// protocolExplain.js — bilingual (English + 中文) plain-language explanations
// of what a specific SIM/GTP/SCTP protocol message actually does. These
// protocols never carry the gateway's own decryptable HTTPS (they are not
// TLS, and most of them are not even IP), so the Plaintext pane has nothing
// to decrypt for them — this stands in for that pane's "nothing to show"
// state with something actually useful: what the selected message's purpose
// is, in both languages at once (an analyst reading a capture may want the
// exact term in either language regardless of which one the UI itself is
// currently in).
//
// Keyed to match each dissector's own naming exactly:
//   - SIM (ISO/IEC 7816-4, ETSI TS 102.221, 3GPP TS 51.011): by INS name,
//     see BeeEye-agent/internal/dissect/gsmtap.go's simInsName().
//   - GTP: by the numeric message type, see app.go's gtpMessageTypeName().
//   - SCTP: by chunk name, see dissect.go's sctpChunkName().

export const SIM_INS_EXPLAIN = {
  'SELECT': {
    en: 'Selects a file or application (MF/DF/EF, or an AID) as the card’s current context for the commands that follow.',
    zh: '选择一个文件或应用（MF/DF/EF，或应用标识符 AID），作为后续命令的当前操作对象。',
  },
  'READ BINARY': {
    en: 'Reads raw bytes from a transparent (binary) EF at a given offset.',
    zh: '从透明结构（二进制）EF 文件的指定偏移处读取原始字节数据。',
  },
  'UPDATE BINARY': {
    en: 'Writes bytes into a transparent EF at a given offset — e.g. changing a stored counter or flag.',
    zh: '向透明结构 EF 文件的指定偏移处写入数据 —— 例如修改存储的计数器或标志位。',
  },
  'READ RECORD': {
    en: 'Reads one record from a linear-fixed or cyclic EF (e.g. an SMS storage slot, a phonebook entry).',
    zh: '从线性定长或循环结构的 EF 文件中读取一条记录（如短信存储槽位、电话簿条目）。',
  },
  'UPDATE RECORD': {
    en: 'Writes one record into a linear-fixed or cyclic EF.',
    zh: '向线性定长或循环结构的 EF 文件写入一条记录。',
  },
  'VERIFY CHV': {
    en: 'Verifies the PIN (CHV1/CHV2) entered by the user against the one stored on the card, unlocking PIN-protected operations.',
    zh: '校验用户输入的 PIN 码（CHV1/CHV2）是否与卡内存储的一致，用于解锁受 PIN 保护的操作。',
  },
  'CHANGE CHV': {
    en: 'Changes the stored PIN to a new value, after verifying the old one.',
    zh: '在校验旧 PIN 后，将卡上存储的 PIN 修改为新值。',
  },
  'DISABLE CHV': {
    en: 'Turns off PIN verification for this card.',
    zh: '关闭该卡的 PIN 校验功能。',
  },
  'ENABLE CHV': {
    en: 'Turns on PIN verification for this card.',
    zh: '开启该卡的 PIN 校验功能。',
  },
  'UNBLOCK CHV': {
    en: 'Unblocks a PIN that was locked after too many wrong attempts, using the PUK (unblock code).',
    zh: '使用 PUK（解锁码）解锁因多次输错而被锁定的 PIN。',
  },
  'INCREASE': {
    en: 'Adds a value to a binary EF that holds a counter (e.g. a prepaid unit counter).',
    zh: '对存储计数器的二进制 EF 文件做加值操作（如预付费单位计数器）。',
  },
  'MANAGE CHANNEL': {
    en: 'Opens or closes a logical channel, letting the terminal talk to more than one card application (ADF) at once.',
    zh: '打开或关闭逻辑信道，使终端可以同时与卡上多个应用（ADF）通信。',
  },
  'RUN GSM ALGORITHM / AUTHENTICATE': {
    en: 'Feeds a RAND challenge to the SIM’s A3/A8 algorithm; the card returns the SRES response and Kc ciphering key — the core step of GSM network authentication.',
    zh: '向 SIM 卡的 A3/A8 算法输入 RAND 挑战值，卡片返回 SRES 认证响应和 Kc 加密密钥 —— 这是 GSM 网络鉴权的核心步骤。',
  },
  'SEARCH RECORD': {
    en: 'Searches the records of a linear-fixed EF for a matching pattern.',
    zh: '在线性定长 EF 文件的各条记录中查找匹配的内容。',
  },
  'GET RESPONSE': {
    en: 'Retrieves data the card announced was available (SW1=0x61) after a previous command — e.g. a file’s own header after SELECT.',
    zh: '取回卡片在上一条命令后通过 SW1=0x61 提示可用的数据 —— 例如 SELECT 之后文件本身的头部信息。',
  },
  'ENVELOPE': {
    en: 'Wraps a proactive-SIM related event (an incoming SMS-PP, a call setup, …) for the card’s Toolkit application to act on.',
    zh: '封装与主动式 SIM（SIM Toolkit）相关的事件（如收到的 SMS-PP、呼叫建立等），交由卡上的 Toolkit 应用处理。',
  },
  'STATUS': {
    en: 'Asks the card for the status of the currently selected file/directory.',
    zh: '查询卡片当前选中文件/目录的状态信息。',
  },
  'DEACTIVATE FILE': {
    en: 'Deactivates (soft-disables) a file without deleting it.',
    zh: '停用（软禁用）一个文件，但不将其删除。',
  },
  'TERMINAL PROFILE': {
    en: 'Tells the card which SIM Toolkit features this terminal supports.',
    zh: '告知卡片该终端支持哪些 SIM Toolkit（主动式 SIM）功能。',
  },
  'FETCH': {
    en: 'Asks the card for the next proactive command it wants the terminal to perform (display text, send an SMS, set up a call, …).',
    zh: '向卡片查询下一条希望终端执行的主动命令（如显示文本、发送短信、建立呼叫等）。',
  },
  'TERMINAL RESPONSE': {
    en: 'Reports back to the card the result of a proactive command the terminal just carried out.',
    zh: '向卡片回报刚刚执行的主动命令的结果。',
  },
}

export const GTP_MSGTYPE_EXPLAIN = {
  '1': {
    en: 'Keepalive/reachability probe between two GTP peers (e.g. SGSN↔GGSN, or eNB↔SGW over GTP-U).',
    zh: '两个 GTP 对端之间的保活/可达性探测（如 SGSN↔GGSN，或 GTP-U 中的 eNB↔SGW）。',
  },
  '2': {
    en: 'Reply to an Echo Request, confirming the peer is reachable.',
    zh: '对 Echo Request 的应答，确认对端可达。',
  },
  '16': {
    en: 'Establishes a new PDP context (a mobile data session) — carries the subscriber’s IMSI/APN and negotiates the tunnel endpoints.',
    zh: '建立一个新的 PDP 上下文（即移动数据会话）—— 携带用户的 IMSI/APN，并协商隧道端点。',
  },
  '17': {
    en: 'Reply to a Create PDP Context Request, confirming the negotiated tunnel (or rejecting it).',
    zh: '对 Create PDP Context Request 的应答，确认（或拒绝）协商的隧道。',
  },
  '18': {
    en: 'Modifies an existing PDP context — typically after the mobile moves to a new SGSN (a handover).',
    zh: '修改已存在的 PDP 上下文 —— 通常在终端切换到新的 SGSN（移动/切换）时使用。',
  },
  '19': {
    en: 'Reply to an Update PDP Context Request.',
    zh: '对 Update PDP Context Request 的应答。',
  },
  '20': {
    en: 'Tears down an existing PDP context, ending that data session.',
    zh: '拆除已存在的 PDP 上下文，结束该数据会话。',
  },
  '21': {
    en: 'Reply to a Delete PDP Context Request, confirming the session is gone.',
    zh: '对 Delete PDP Context Request 的应答，确认该会话已结束。',
  },
  '26': {
    en: 'Reports that a data packet (G-PDU) arrived for a tunnel endpoint (TEID) the receiver does not recognise — usually a stale or mismatched tunnel.',
    zh: '报告收到的数据包（G-PDU）所对应的隧道端点标识（TEID）在接收方处不存在 —— 通常意味着隧道信息过期或不匹配。',
  },
  '31': {
    en: 'Announces which GTP extension headers this node supports.',
    zh: '通告该节点支持哪些 GTP 扩展头。',
  },
  '255': {
    en: 'The actual encapsulated user-data packet (the tunnelled IP packet itself) — not a GTP control message.',
    zh: '被封装的实际用户数据包（隧道内的 IP 报文本身），并非 GTP 控制消息。',
  },
}

export const SCTP_CHUNK_EXPLAIN = {
  'DATA': {
    en: 'Carries user data for one stream — SCTP’s basic payload chunk.',
    zh: '承载某个流（stream）的用户数据 —— SCTP 的基本载荷分片。',
  },
  'INIT': {
    en: 'Starts a new SCTP association (like TCP’s SYN).',
    zh: '发起一个新的 SCTP 关联（类似 TCP 的 SYN）。',
  },
  'INIT_ACK': {
    en: 'Acknowledges an INIT and proposes association parameters back (like TCP’s SYN-ACK).',
    zh: '对 INIT 的确认，并回传关联参数（类似 TCP 的 SYN-ACK）。',
  },
  'SACK': {
    en: 'Selective acknowledgment — reports which DATA chunks (by TSN) have been received, including any gaps.',
    zh: '选择性确认 —— 按 TSN 报告已收到哪些 DATA 分片，包括其中的缺口。',
  },
  'HEARTBEAT': {
    en: 'Keepalive probe for an idle path.',
    zh: '对空闲路径的保活探测。',
  },
  'HEARTBEAT_ACK': {
    en: 'Acknowledges a HEARTBEAT, confirming the path is still reachable.',
    zh: '对 HEARTBEAT 的确认，确认该路径仍然可达。',
  },
  'ABORT': {
    en: 'Immediately and ungracefully terminates the association (like TCP’s RST).',
    zh: '立即、非优雅地终止该关联（类似 TCP 的 RST）。',
  },
  'SHUTDOWN': {
    en: 'Gracefully closes the association once all outstanding data has been acknowledged.',
    zh: '在所有未确认数据都被确认后，优雅地关闭该关联。',
  },
  'SHUTDOWN_ACK': {
    en: 'Acknowledges a SHUTDOWN, completing the graceful close.',
    zh: '对 SHUTDOWN 的确认，完成优雅关闭流程。',
  },
  'ERROR': {
    en: 'Reports a protocol error without necessarily closing the association.',
    zh: '报告一个协议错误，但不一定关闭该关联。',
  },
  'COOKIE_ECHO': {
    en: 'Third step of SCTP’s four-way handshake — echoes back the state cookie from INIT_ACK.',
    zh: 'SCTP 四次握手的第三步 —— 回传 INIT_ACK 中的状态 cookie。',
  },
  'COOKIE_ACK': {
    en: 'Fourth step of the handshake — confirms the association is now established.',
    zh: 'SCTP 四次握手的第四步 —— 确认关联建立完成。',
  },
  'SHUTDOWN_COMPLETE': {
    en: 'Confirms the association has been fully torn down.',
    zh: '确认该关联已完全拆除。',
  },
}

// explainFor inspects a packet detail's dissected fields and returns the
// bilingual explanation for whichever of SIM/GTP/SCTP it recognises, or null
// if this packet is none of those (or its specific code isn't one this table
// covers — a raw "type 0x.."/"chunk type N" fallback name from the
// dissector, meaning that fallback name simply is not a key here).
export function explainFor(fields) {
  if (!fields) return null
  const ins = fields['gsm_sim.apdu.ins']?.[0]
  if (ins && SIM_INS_EXPLAIN[ins]) {
    return { kind: 'SIM', label: ins, ...SIM_INS_EXPLAIN[ins] }
  }
  const gtpType = fields['gtp.message_type']?.[0]
  if (gtpType && GTP_MSGTYPE_EXPLAIN[gtpType]) {
    return { kind: 'GTP', label: fields['gtp.message_type']?.[0], ...GTP_MSGTYPE_EXPLAIN[gtpType] }
  }
  const chunk = fields['sctp.chunk_type']?.[0]
  if (chunk && SCTP_CHUNK_EXPLAIN[chunk]) {
    return { kind: 'SCTP', label: chunk, ...SCTP_CHUNK_EXPLAIN[chunk] }
  }
  return null
}
