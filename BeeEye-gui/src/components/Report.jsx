import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, formatBytes } from '../api'

const TABS = ['summary', 'protocols', 'talkers', 'conversations', 'sessions', 'credentials', 'files', 'findings', 'geo']

// Report is the capture-report view program.md's Pcap-Analyzer
// (https://github.com/HatBoy/Pcap-Analyzer) acknowledgment describes the
// shape of — protocol/talker/conversation stats, credential and file
// carving, security heuristics, geography — now living in the analyzer
// itself rather than the overview app: a file is opened once, through the
// exact same Toolbar "Open file" a live capture's interface picker sits
// next to, and this is what that same file looks like summarized instead of
// packet-by-packet.
//
// The three ranked-list panels (protocols/talkers/conversations) lead with a
// GPU/CPU-rendered bar chart (render.Renderer.RenderBars) sharing the same
// glow/bloom palette the traffic field and packet list already use, rather
// than a plain table — a deliberate step up from Pcap-Analyzer's own plain
// tables, not just a port of them.
export default function Report({ running }) {
  const { t } = useTranslation()
  const [report, setReport] = useState(null)
  const [tab, setTab] = useState('summary')
  const [renderInfo, setRenderInfo] = useState(null)

  useEffect(() => {
    let alive = true
    const poll = () => {
      api.report().then((r) => { if (alive) setReport(r) }).catch(() => { if (alive) setReport(null) })
    }
    poll()
    // Polled rather than fetched once: opening a new file while this tab is
    // already showing the previous one's report should replace it without
    // requiring a manual refresh.
    const id = setInterval(poll, 2000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  useEffect(() => {
    api.renderInfo().then(setRenderInfo).catch(() => setRenderInfo(null))
  }, [])

  if (!report) {
    return (
      <section className="pane report-pane">
        <div className="empty">
          <div className="empty-title">{t('report.none')}</div>
        </div>
      </section>
    )
  }

  const backend = renderInfo?.backend === 'cuda' ? t('status.rendererCuda') : t('status.rendererCpu')

  return (
    <section className="pane report-pane">
      <div className="report-head">
        <div className="report-tabs" role="tablist">
          {TABS.map((tb) => (
            <button
              key={tb}
              role="tab"
              aria-selected={tab === tb}
              className={tab === tb ? 'active' : ''}
              onClick={() => setTab(tb)}
            >
              {t(`report.tabs.${tb}`)}
            </button>
          ))}
        </div>
        <span className="report-filename" title={report.filename}>{report.filename}</span>
      </div>

      {report.warnings?.length > 0 && (
        <div className="report-warnings">
          <b>{t('report.warnings')}:</b> {report.warnings.join(' · ')}
        </div>
      )}

      {tab === 'summary' && <SummaryTab report={report} t={t} />}
      {tab === 'protocols' && <ChartTab kind="protocols" rows={report.protocols} report={report} t={t} backend={backend}
        columns={[
          { key: 'protocol', label: null },
          { key: 'packets', label: t('report.talkers.packets') },
          { key: 'bytes', label: t('report.talkers.bytes'), fmt: formatBytes },
        ]} />}
      {tab === 'talkers' && <ChartTab kind="talkers" rows={report.talkers} report={report} t={t} backend={backend}
        columns={[
          { key: 'ip', label: t('report.talkers.ip') },
          { key: 'packets', label: t('report.talkers.packets') },
          { key: 'bytes', label: t('report.talkers.bytes'), fmt: formatBytes },
          { key: 'sent', label: t('report.talkers.sent'), fmt: formatBytes },
          { key: 'received', label: t('report.talkers.received'), fmt: formatBytes },
          { key: 'location', label: t('report.talkers.location'), get: (r) => geoLabel(r.geo) },
        ]} />}
      {tab === 'conversations' && <ChartTab kind="conversations" rows={report.conversations} report={report} t={t} backend={backend}
        columns={[
          { key: 'a', label: t('report.conv.a'), get: (r) => `${r.a}:${r.a_port}` },
          { key: 'b', label: t('report.conv.b'), get: (r) => `${r.b}:${r.b_port}` },
          { key: 'app', label: t('report.conv.app'), get: (r) => r.app_proto || r.proto },
          { key: 'packets', label: t('report.conv.packets') },
          { key: 'bytes', label: t('report.conv.bytes'), fmt: formatBytes },
        ]} />}
      {tab === 'sessions' && <SessionsTab rows={report.sessions} t={t} />}
      {tab === 'credentials' && <CredentialsTab rows={report.credentials} t={t} />}
      {tab === 'files' && <FilesTab rows={report.files} t={t} />}
      {tab === 'findings' && <FindingsTab rows={report.findings} t={t} />}
      {tab === 'geo' && <GeoTab rows={report.geo_points} t={t} />}
    </section>
  )
}

function geoLabel(geo) {
  if (!geo) return '—'
  return [geo.country, geo.city].filter(Boolean).join(' · ') || (geo.local ? 'LOCAL' : '—')
}

function SummaryTab({ report, t }) {
  const s = report.summary
  const rows = [
    ['packets', s.packets],
    ['bytes', formatBytes(s.bytes)],
    ['duration', formatDuration(s.duration_sec)],
    ['linkType', s.link_type],
    ['uniqueIps', s.unique_ips],
    ['uniqueMacs', s.unique_macs],
    ['first', formatTime(s.first)],
    ['last', formatTime(s.last)],
    ['snaplen', s.snaplen],
  ]
  return (
    <div className="report-summary-grid">
      {rows.map(([key, value]) => (
        <div key={key} className="report-summary-tile">
          <div className="rst-value">{value ?? '—'}</div>
          <div className="rst-label">{t(`report.summary.${key}`)}</div>
        </div>
      ))}
    </div>
  )
}

// ChartTab is shared by protocols/talkers/conversations: a GPU-rendered bar
// chart of the same rows the table below it lists, ranked by bytes — the
// image and the table describe the same ranking, the image just makes the
// shape of it visible at a glance the way a bare table cannot.
function ChartTab({ kind, rows, report, t, backend, columns }) {
  if (!rows || rows.length === 0) {
    return <div className="empty"><div className="empty-title">{t('table.empty', { defaultValue: 'Nothing here' })}</div></div>
  }
  const sorted = [...rows].sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
  const count = Math.min(sorted.length, 8)
  return (
    <div className="report-chart-tab">
      <div className="report-chart-caption">{t('report.chartByBytes', { backend })}</div>
      <img
        className="report-bars"
        alt=""
        src={api.reportBarsURL(kind, { count })}
      />
      <table className="report-table">
        <thead>
          <tr>{columns.map((c) => <th key={c.key}>{c.label ?? ''}</th>)}</tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c.key}>
                  {c.get ? c.get(r) : c.fmt ? c.fmt(r[c.key]) : (r[c.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SessionsTab({ rows, t }) {
  if (!rows || rows.length === 0) return <div className="empty"><div className="empty-title">—</div></div>
  return (
    <table className="report-table">
      <thead>
        <tr>
          <th>{t('report.sessions.client')}</th>
          <th>{t('report.sessions.server')}</th>
          <th>{t('report.sessions.app')}</th>
          <th>{t('report.sessions.request')}</th>
          <th>{t('report.sessions.response')}</th>
          <th>{t('report.sessions.authFailures')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((s) => (
          <tr key={s.id}>
            <td>{s.client}:{s.client_port}</td>
            <td>{s.server}:{s.server_port}</td>
            <td>{s.app || s.transport}</td>
            <td>{formatBytes(s.bytes_c2s)}</td>
            <td>{formatBytes(s.bytes_s2c)}</td>
            <td>{s.auth_failures || 0}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function CredentialsTab({ rows, t }) {
  if (!rows || rows.length === 0) {
    return <div className="empty"><div className="empty-title">{t('report.creds.none')}</div></div>
  }
  return (
    <>
      <div className="report-warning-banner">{t('report.creds.warning')}</div>
      <table className="report-table">
        <thead>
          <tr>
            <th>{t('report.creds.protocol')}</th>
            <th>{t('report.creds.method')}</th>
            <th>{t('report.creds.client')}</th>
            <th>{t('report.creds.server')}</th>
            <th>{t('report.creds.username')}</th>
            <th>{t('report.creds.password')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c, i) => (
            <tr key={i}>
              <td>{c.protocol}</td>
              <td>{c.method}</td>
              <td>{c.client}</td>
              <td>{c.server}</td>
              <td className="mono">{c.username}</td>
              <td className="mono">{c.password}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function FilesTab({ rows, t }) {
  if (!rows || rows.length === 0) {
    return <div className="empty"><div className="empty-title">{t('report.files.none')}</div></div>
  }
  return (
    <>
      <div className="report-warning-banner">
        <b>{t('report.files.warningTitle')}</b> — {t('report.files.warning')}
      </div>
      <table className="report-table">
        <thead>
          <tr>
            <th>{t('report.files.filename')}</th>
            <th>{t('report.files.type')}</th>
            <th>{t('report.files.size')}</th>
            <th>{t('report.files.hash')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => (
            <tr key={f.id}>
              <td>{f.filename}</td>
              <td>{f.content_type}</td>
              <td>{formatBytes(f.size)}</td>
              <td className="mono report-hash">{f.sha256}</td>
              <td><a className="btn ghost tiny" href={api.reportFileURL(f.id)} download>{t('report.files.download')}</a></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

function FindingsTab({ rows, t }) {
  if (!rows || rows.length === 0) {
    return <div className="empty"><div className="empty-title">{t('report.findings.none')}</div></div>
  }
  return (
    <table className="report-table">
      <thead>
        <tr>
          <th>{t('report.findings.kind')}</th>
          <th>{t('report.findings.severity')}</th>
          <th>{t('report.findings.client')}</th>
          <th>{t('report.findings.server')}</th>
          <th>{t('report.findings.evidence')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f, i) => (
          <tr key={i}>
            <td>{f.title || f.kind}{f.heuristic && <span className="report-heuristic" title={t('report.findings.heuristic')}>?</span>}</td>
            <td><span className={`report-sev report-sev-${f.severity}`}>{f.severity}</span></td>
            <td>{f.client}</td>
            <td>{f.server}</td>
            <td className="mono">{f.evidence}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function GeoTab({ rows, t }) {
  if (!rows || rows.length === 0) {
    return <div className="empty"><div className="empty-title">{t('report.geo.none')}</div></div>
  }
  const sorted = [...rows].sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
  return (
    <table className="report-table">
      <thead>
        <tr>
          <th>IP</th>
          <th>{t('report.geo.country')}</th>
          <th>{t('report.geo.city')}</th>
          <th>{t('report.geo.bytes')}</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((g, i) => (
          <tr key={i}>
            <td>{g.ip}</td>
            <td>{g.country}</td>
            <td>{g.city}</td>
            <td>{formatBytes(g.bytes)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function formatDuration(sec) {
  if (!sec && sec !== 0) return '—'
  if (sec < 90) return `${sec.toFixed(1)}s`
  const m = Math.floor(sec / 60)
  if (m < 90) return `${m}m ${Math.round(sec % 60)}s`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

function formatTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return '—'
  return d.toLocaleString()
}
