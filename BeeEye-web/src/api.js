// Client for the BeeEye-agent REST API (:8080).

async function get(path) {
  const res = await fetch(path)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

// toQuery turns a filter object into the query string every list endpoint
// understands. Empty values are dropped so an unset filter never narrows the
// result by accident.
export function toQuery(filter = {}, extra = {}) {
  const q = new URLSearchParams()
  const put = (k, v) => {
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0)) return
    q.set(k, Array.isArray(v) ? v.join(',') : String(v))
  }
  put('mac', filter.macs)
  put('ip', filter.ip)
  put('proto', filter.protos)
  put('port_min', filter.portMin)
  put('port_max', filter.portMax)
  put('since', filter.since)
  put('until', filter.until)
  if (filter.internalOnly) q.set('internal', '1')
  for (const [k, v] of Object.entries(extra)) put(k, v)
  return q.toString()
}

export const api = {
  health: () => get('/api/health'),
  config: () => get('/api/config'),
  geoipStatus: () => get('/api/geoip/status'),
  source: () => get('/api/source'),
  summary: () => get('/api/summary'),
  devices: () => get('/api/devices'),
  ackDevice: (mac) => post(`/api/devices/${encodeURIComponent(mac)}/ack`),
  setCategory: (mac, category) => post(`/api/devices/${encodeURIComponent(mac)}/category`, { category }),

  connections: (filter, limit = 500) => get(`/api/connections?${toQuery(filter, { limit })}`),
  dns: (mac, limit = 500) => get(`/api/dns?${toQuery({}, { mac, limit })}`),
  events: (limit = 500) => get(`/api/events?limit=${limit}`),
  ackEvent: (id) => post(`/api/events/${id}/ack`),

  ipView: () => get('/api/views/ip'),
  protocolView: () => get('/api/views/protocol'),
  topN: (dim, n = 10) => get(`/api/views/topn?dim=${dim}&n=${n}`),
  timeseries: (filter, bucket = 900, split = '') =>
    get(`/api/timeseries?${toQuery(filter, { bucket, split })}`),

  exportURL: (filter, format) => `/api/export?${toQuery(filter, { format })}`,

  mitmStatus: () => get('/api/mitm/status'),
  mitmCAUrl: () => '/api/mitm/ca.pem',
  mitmMobileConfigUrl: () => '/api/mitm/ca.mobileconfig',
  mitmExchanges: (limit = 100) => get(`/api/mitm/exchanges?limit=${limit}`),
  mitmExchange: (id) => get(`/api/mitm/exchanges/${encodeURIComponent(id)}`),

  geoPairs: (limit = 150) => get(`/api/views/geopairs?limit=${limit}`),
}

export function formatBytes(n) {
  if (!n) return '0 B'
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

export function formatTime(ts, locale) {
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString(locale, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}
