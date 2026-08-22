import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatBytes, formatRate } from '../api'

// A conky-style strip: every stat in its own vivid, distinct color, read at
// a glance rather than as a form. Cycled rather than hand-assigned per field
// so a wireless card (more fields) does not need its own separate palette.
const COLORS = ['#ff5f56', '#ffbd2e', '#27c93f', '#22d3ee', '#818cf8', '#f472b6', '#facc15', '#34d399', '#fb923c', '#c084fc']

function Stat({ label, value, color }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <span className="iface-stat" style={{ color }}>
      <span className="iface-stat-label">{label}</span>
      <span className="iface-stat-value">{value}</span>
    </span>
  )
}

export default function InterfaceInfo() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)

  useEffect(() => {
    let alive = true
    const poll = () => {
      // no-store: this drives a live speed readout, so every 2s tick must
      // hit the server for a fresh sample rather than risk a cached one —
      // same reasoning as the server's own Cache-Control on this endpoint.
      fetch('/api/iface/info', { cache: 'no-store' })
        .then((r) => r.json())
        .then((d) => { if (alive) setData(d) })
        .catch(() => {})
    }
    poll()
    const id = setInterval(poll, 2000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  if (!data?.available) return null
  const nic = data.iface

  const stats = [
    { label: t('iface.ip'), value: nic.ip },
    { label: t('iface.mac'), value: nic.mac },
    { label: t('iface.down'), value: `↓ ${formatRate(nic.rx_per_sec)}` },
    { label: t('iface.up'), value: `↑ ${formatRate(nic.tx_per_sec)}` },
    { label: t('iface.totalDown'), value: formatBytes(nic.rx_bytes) },
    { label: t('iface.totalUp'), value: formatBytes(nic.tx_bytes) },
  ]
  if (nic.wireless) {
    stats.push({ label: t('iface.ssid'), value: nic.ssid })
    if (nic.channel) stats.push({ label: t('iface.channel'), value: nic.channel })
    if (nic.has_signal) stats.push({ label: t('iface.signal'), value: `${nic.signal_dbm} dBm` })
  }

  return (
    <section className="card wide iface-card">
      <h2>{t('iface.title', { name: nic.name })}</h2>
      <div className="iface-stats">
        {stats.map((s, i) => (
          <Stat key={s.label} label={s.label} value={s.value} color={COLORS[i % COLORS.length]} />
        ))}
      </div>
    </section>
  )
}
