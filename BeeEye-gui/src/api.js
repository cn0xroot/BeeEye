// Thin client for the BeeEye-gui API. Everything is same-origin in production
// (the Go binary serves this bundle); in dev Vite proxies /api through.

async function req(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    // The server sends {"error": "..."} for anything it can explain; surfacing
    // that text beats a bare status code, especially for filter syntax errors.
    let detail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      if (body && body.error) detail = body.error
    } catch {
      /* non-JSON error body; the status is all we have */
    }
    throw new Error(detail)
  }
  return res.json()
}

// decodeBytes turns the packet's raw bytes into a Uint8Array.
//
// Go marshals a []byte as a base64 string, not as a JSON array — so the hex
// pane has to decode before it can index anything. Treating the string as an
// array is silently wrong: .slice() returns a string and .map() is not a
// function on it, which takes the whole detail pane down with it.
export function decodeBytes(raw) {
  if (!raw) return new Uint8Array(0)
  if (raw instanceof Uint8Array) return raw
  if (Array.isArray(raw)) return Uint8Array.from(raw)
  try {
    const bin = atob(raw)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
  } catch {
    return new Uint8Array(0)
  }
}

export const api = {
  interfaces: () => req('/api/interfaces'),
  status: () => req('/api/status'),
  renderInfo: () => req('/api/render/info'),
  renderTotals: () => req('/api/render/totals'),

  start: (opts) => req('/api/capture/start', { method: 'POST', body: JSON.stringify(opts) }),
  stop: () => req('/api/capture/stop', { method: 'POST' }),

  // Not built on req(): a multipart upload needs the browser to set its own
  // Content-Type (with the boundary), which req()'s default JSON header
  // would stomp on.
  openFile: async (file) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch('/api/pcap/open', { method: 'POST', body: form })
    if (!res.ok) {
      let detail = `HTTP ${res.status}`
      try {
        const body = await res.json()
        if (body && body.error) detail = body.error
      } catch {
        /* non-JSON error body; the status is all we have */
      }
      throw new Error(detail)
    }
    return res.json()
  },

  // Best-effort: folds the same file into the overview app's own store (a
  // separate process, normally on :8080) so it stops showing only its live
  // database once a historical capture has been opened here — the two UIs
  // otherwise had no way to agree on "the data" for an imported file, only
  // for live traffic. Silently ignored on failure (wrong port, overview not
  // running, CORS blocked) since this is a bonus, not the primary import the
  // analyzer itself just did.
  importToOverview: (file) => {
    const form = new FormData()
    form.append('file', file)
    const url = `${location.protocol}//${location.hostname}:8080/api/pcap/import`
    fetch(url, { method: 'POST', body: form }).catch(() => {})
  },

  setFilter: (filter) => req('/api/filter', { method: 'POST', body: JSON.stringify({ filter }) }),
  validateFilter: (filter) =>
    req('/api/filter/validate', { method: 'POST', body: JSON.stringify({ filter }) }),

  packets: (limit = 2000) => req(`/api/packets?limit=${limit}`),
  packet: async (no) => {
    const d = await req(`/api/packets/${no}`)
    return { ...d, hex: decodeBytes(d.hex) }
  },

  decryptStatus: () => req('/api/decrypt'),
  setDecrypt: (enabled) => req('/api/decrypt', { method: 'POST', body: JSON.stringify({ enabled }) }),
  plaintext: (pid = 0, limit = 100) => req(`/api/plaintext?pid=${pid}&limit=${limit}`),

  pcapURL: (limit = 0) => `/api/export/pcap${limit ? `?limit=${limit}` : ''}`,
  frameURL: (h) => `/api/render/frame.png?h=${h}&t=${Date.now()}`,

  // report is the capture-report view (program.md's Pcap-Analyzer-shaped
  // summary/protocols/talkers/conversations/credentials/files/findings/geo
  // breakdown) for whichever file OpenFile most recently opened — null while
  // idle or mid-live-capture.
  report: () => req('/api/report'),
  reportBarsURL: (kind, { count = 8, h = 220 } = {}) =>
    `/api/report/bars.png?kind=${kind}&count=${count}&h=${h}&t=${Date.now()}`,
  reportFileURL: (fid) => `/api/report/files/${encodeURIComponent(fid)}`,
}

// streamPackets opens the SSE feed. Returns a close function.
//
// EventSource reconnects on its own, which is exactly the behaviour wanted
// here: a restarted analyzer should repopulate the list without the operator
// having to reload the page mid-investigation.
export function streamPackets({ onPackets, onStatus, onError }) {
  const es = new EventSource('/api/stream')

  es.addEventListener('packets', (e) => {
    try {
      onPackets(JSON.parse(e.data))
    } catch (err) {
      onError?.(err)
    }
  })

  es.addEventListener('status', (e) => {
    try {
      onStatus?.(JSON.parse(e.data))
    } catch {
      /* a malformed keepalive is not worth surfacing */
    }
  })

  es.onerror = () => onError?.(new Error('stream disconnected'))

  return () => es.close()
}

// formatBytes renders a byte count compactly. Locale-independent on purpose:
// these are technical readouts sitting next to hex, and a thousands separator
// that changes with the UI language makes them harder to compare, not easier.
export function formatBytes(n) {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`
}

// layerRole maps a dissected layer's protocol key onto a colour role used by
// the field tree and the hex pane.
//
// Only three hues are used, because only three of the categorical slots stay
// separable for colour-vision-deficient readers when all of them are on screen
// at once. The link layer takes a neutral grey instead of a fourth hue — it is
// framing, not something anyone reasons about — and every coloured region also
// carries its protocol name as text, so colour is never the only cue.
export function layerRole(proto) {
  switch (proto) {
    case 'eth':
    case 'vlan':
      return 'link'
    case 'ip':
    case 'ipv6':
    case 'arp':
      return 'net'
    case 'tcp':
    case 'udp':
    case 'icmp':
    case 'icmpv6':
      return 'transport'
    default:
      return 'app'
  }
}

// protocolSlot maps a protocol name onto one of the fixed colour slots —
// mirrors internal/gui/session.go's renderChannel, which is the field's own
// classifier; this must stay in step with it (RenderChannels/ChannelColors)
// or a packet's row colour and its field-heatmap row would disagree. The
// mapping is by identity, never by rank: applying a filter that removes
// every DNS packet must not repaint TLS in DNS's colour.
export function protocolSlot(proto) {
  const p = (proto || '').toLowerCase()
  if (p.includes('tls') || p.includes('https') || p.includes('http/2') || p.includes('http/3')) return 'tls'
  if (p.includes('http')) return 'http'
  if (p.includes('dns')) return 'dns'
  if (p.includes('mqtt')) return 'mqtt'
  if (p.includes('sip')) return 'sip'
  if (p.includes('sctp')) return 'sctp'
  if (p.includes('gtp')) return 'gtp'
  if (p.includes('sim') || p.includes('gsmtap')) return 'sim'
  if (p.includes('arp')) return 'arp'
  if (p.includes('icmp')) return 'icmp'
  if (p === 'tcp') return 'tcp'
  return 'other'
}
