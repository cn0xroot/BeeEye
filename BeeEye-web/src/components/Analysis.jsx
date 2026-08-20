import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatBytes, formatTime } from '../api'
import { Donut, BarRows } from './Charts'
import { Table } from './Tables'

const TABS = ['summary', 'protocols', 'talkers', 'conversations', 'sessions', 'credentials', 'files', 'findings', 'geo']

// Analysis is the offline capture-file view. It runs the same engine the live
// analyzer runs, so a pcap of some traffic and a live capture of that same
// traffic cannot report different findings.
export default function Analysis() {
  const { t, i18n } = useTranslation()
  const [reports, setReports] = useState([])
  const [report, setReport] = useState(null)
  const [tab, setTab] = useState('summary')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const fileInput = useRef(null)

  const refreshList = useCallback(() => {
    fetch('/api/pcap').then((r) => r.json()).then(setReports).catch(() => setReports([]))
  }, [])

  useEffect(refreshList, [refreshList])

  const upload = useCallback(async (file) => {
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      const body = new FormData()
      body.append('file', file)
      const res = await fetch('/api/pcap/upload', { method: 'POST', body })
      const json = await res.json()
      if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`)
      setReport(json.report)
      setTab('summary')
      refreshList()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }, [refreshList])

  const open = async (id) => {
    setBusy(true)
    try {
      const res = await fetch(`/api/pcap/${id}`)
      const json = await res.json()
      if (!res.ok) throw new Error(json.error)
      setReport(json)
      setTab('summary')
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="view">
      <section className="card wide">
        <h2>{t('analysis.upload')}</h2>
        <div
          className={`dropzone ${dragOver ? 'over' : ''} ${busy ? 'busy' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragOver(false)
            upload(e.dataTransfer.files?.[0])
          }}
          onClick={() => fileInput.current?.click()}
        >
          <div className="drop-icon" aria-hidden="true">📥</div>
          <div>{busy ? t('analysis.uploading') : t('analysis.uploadHint')}</div>
          <input
            ref={fileInput}
            type="file"
            accept=".pcap,.cap,application/vnd.tcpdump.pcap"
            hidden
            onChange={(e) => upload(e.target.files?.[0])}
          />
        </div>
        {error && <div className="banner error" role="alert">{error}</div>}
      </section>

      {reports.length > 0 && (
        <section className="card wide">
          <h2>{t('analysis.recent')}</h2>
          <ul className="report-list">
            {reports.map((r) => (
              <li key={r.id}>
                <button className="btn ghost" onClick={() => open(r.id)}>{t('analysis.openReport')}</button>
                <b>{r.filename}</b>
                <span className="dim">{r.uploaded}</span>
                <span className="dim num">{r.packets} pkts</span>
                {r.credentials > 0 && <span className="pill danger">{r.credentials} 🔑</span>}
                {r.findings > 0 && <span className="pill warn">{r.findings} ⚠</span>}
                {r.files > 0 && <span className="pill">{r.files} 📄</span>}
              </li>
            ))}
          </ul>
        </section>
      )}

      {report && (
        <>
          {report.warnings?.length > 0 && (
            <section className="card wide warn-card">
              <h2>{t('analysis.warnings')}</h2>
              <ul className="plain">
                {report.warnings.map((w, i) => <li key={i}>⚠ {w}</li>)}
              </ul>
            </section>
          )}

          <nav className="tabs">
            {TABS.map((k) => (
              <button key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>
                {t(`analysis.tabs.${k}`)}
                {k === 'credentials' && report.credentials?.length > 0 && <span className="badge">{report.credentials.length}</span>}
                {k === 'findings' && report.findings?.length > 0 && <span className="badge">{report.findings.length}</span>}
                {k === 'files' && report.files?.length > 0 && <span className="badge">{report.files.length}</span>}
              </button>
            ))}
          </nav>

          <TabBody tab={tab} report={report} locale={i18n.resolvedLanguage} />
        </>
      )}
    </div>
  )
}

function TabBody({ tab, report, locale }) {
  const { t } = useTranslation()
  const s = report.summary

  switch (tab) {
    case 'summary':
      return (
        <div className="view">
          <div className="tiles">
            <Tile label={t('analysis.summary.packets')} value={s.packets} />
            <Tile label={t('analysis.summary.bytes')} value={formatBytes(s.bytes)} />
            <Tile label={t('analysis.summary.duration')} value={`${s.duration_sec.toFixed(1)} s`} />
            <Tile label={t('analysis.summary.uniqueIps')} value={s.unique_ips} />
          </div>
          <section className="card wide">
            <table className="data-table">
              <tbody>
                <Row k={t('analysis.summary.linkType')} v={s.link_type} />
                <Row k={t('analysis.summary.snaplen')} v={s.snaplen || '—'} />
                <Row k={t('analysis.summary.first')} v={formatTime(s.first, locale)} />
                <Row k={t('analysis.summary.last')} v={formatTime(s.last, locale)} />
                <Row k={t('analysis.summary.uniqueMacs')} v={s.unique_macs} />
              </tbody>
            </table>
          </section>
        </div>
      )

    case 'protocols':
      return (
        <div className="card-row">
          <section className="card">
            <h2>{t('analysis.tabs.protocols')}</h2>
            <Donut rows={(report.protocols || []).slice(0, 7).map((p) => ({ key: p.protocol, value: p.bytes }))} />
          </section>
          <section className="card">
            <Table
              columns={[{ key: 'p', label: t('filters.protocol') }, { key: 'k', label: t('units.packets') }, { key: 'b', label: t('units.bytes') }, { key: 's', label: '%' }]}
              rows={report.protocols}
              keyOf={(r) => r.protocol}
              renderRow={(r, key) => (
                <tr key={key}>
                  <td><span className="proto">{r.protocol}</span></td>
                  <td className="num">{r.packets}</td>
                  <td className="num">{formatBytes(r.bytes)}</td>
                  <td className="num">{(r.share * 100).toFixed(1)}%</td>
                </tr>
              )}
            />
          </section>
        </div>
      )

    case 'talkers':
      return (
        <section className="card wide">
          <Table
            columns={[
              { key: 'ip', label: t('analysis.talkers.ip') },
              { key: 'loc', label: t('analysis.talkers.location') },
              { key: 'pk', label: t('analysis.talkers.packets') },
              { key: 'tx', label: t('analysis.talkers.sent') },
              { key: 'rx', label: t('analysis.talkers.received') },
            ]}
            rows={report.talkers}
            keyOf={(r) => r.ip}
            renderRow={(r, key) => (
              <tr key={key}>
                <td className="num">{r.ip}</td>
                <td>{r.geo?.local ? t('common.local') : `${r.geo?.country || '?'} ${r.geo?.city || ''}`}</td>
                <td className="num">{r.packets}</td>
                <td className="num">{formatBytes(r.sent)}</td>
                <td className="num">{formatBytes(r.received)}</td>
              </tr>
            )}
          />
        </section>
      )

    case 'conversations':
      return (
        <section className="card wide">
          <Table
            columns={[
              { key: 'a', label: t('analysis.conv.a') },
              { key: 'b', label: t('analysis.conv.b') },
              { key: 'p', label: t('analysis.conv.proto') },
              { key: 'app', label: t('analysis.conv.app') },
              { key: 'k', label: t('analysis.conv.packets') },
              { key: 'by', label: t('analysis.conv.bytes') },
            ]}
            rows={report.conversations}
            keyOf={(r) => `${r.a}:${r.a_port}-${r.b}:${r.b_port}`}
            renderRow={(r, key) => (
              <tr key={key}>
                <td className="num">{r.a}:{r.a_port}</td>
                <td className="num">{r.b}:{r.b_port}</td>
                <td>{r.proto}</td>
                <td><span className="proto">{r.app_proto}</span></td>
                <td className="num">{r.packets}</td>
                <td className="num">{formatBytes(r.bytes)}</td>
              </tr>
            )}
          />
        </section>
      )

    case 'sessions':
      return (
        <div className="view">
          {(report.sessions || []).slice(0, 40).map((sess) => (
            <section className="card wide" key={sess.id}>
              <h2>
                <span className="proto">{sess.app}</span>{' '}
                {sess.client}:{sess.client_port} → {sess.server}:{sess.server_port}
                <span className="count dim">
                  {' '}↑{formatBytes(sess.bytes_c2s)} ↓{formatBytes(sess.bytes_s2c)}
                  {sess.auth_failures > 0 && ` · ${t('analysis.sessions.authFailures')}: ${sess.auth_failures}`}
                </span>
              </h2>
              <div className="stream-grid">
                <div>
                  <h4>{t('analysis.sessions.request')}</h4>
                  <pre className="stream c2s">{sess.request_preview || '—'}</pre>
                </div>
                <div>
                  <h4>{t('analysis.sessions.response')}</h4>
                  <pre className="stream s2c">{sess.response_preview || '—'}</pre>
                </div>
              </div>
            </section>
          ))}
          {(!report.sessions || report.sessions.length === 0) && (
            <section className="card wide"><div className="empty">{t('table.empty')}</div></section>
          )}
        </div>
      )

    case 'credentials':
      return (
        <section className="card wide">
          {report.credentials?.length > 0 && (
            <div className="banner error" role="alert">🔑 {t('analysis.creds.warning')}</div>
          )}
          <Table
            columns={[
              { key: 'p', label: t('analysis.creds.protocol') },
              { key: 'm', label: t('analysis.creds.method') },
              { key: 'c', label: t('analysis.creds.client') },
              { key: 's', label: t('analysis.creds.server') },
              { key: 'u', label: t('analysis.creds.username') },
              { key: 'pw', label: t('analysis.creds.password') },
            ]}
            rows={report.credentials}
            keyOf={(r) => r.session_id + r.method + r.username}
            empty={t('analysis.creds.none')}
            renderRow={(r, key) => (
              <tr key={key} className="sev-row-high">
                <td><span className="proto">{r.protocol}</span></td>
                <td className="dim">{r.method}</td>
                <td className="num">{r.client}</td>
                <td className="num">{r.server}</td>
                <td className="num"><b>{r.username || '—'}</b></td>
                <td className="num cred">{r.password || '—'}</td>
              </tr>
            )}
          />
        </section>
      )

    case 'files':
      return (
        <section className="card wide">
          {report.files?.length > 0 && (
            <div className="banner warn">
              <b>{t('analysis.files.warningTitle')}</b> {t('analysis.files.warning')}
            </div>
          )}
          <Table
            columns={[
              { key: 'f', label: t('analysis.files.filename') },
              { key: 'c', label: t('analysis.files.type') },
              { key: 's', label: t('analysis.files.size') },
              { key: 'h', label: t('analysis.files.hash') },
              { key: 'd', label: '' },
            ]}
            rows={report.files}
            keyOf={(r) => r.id}
            empty={t('analysis.files.none')}
            renderRow={(r, key) => (
              <tr key={key} className={r.suspicious ? 'sev-row-high' : ''}>
                <td>
                  {r.filename}
                  {r.suspicious && <div className="dim small">⚠ {r.suspicious}</div>}
                </td>
                <td className="dim">{r.content_type || '—'}</td>
                <td className="num">{formatBytes(r.size)}</td>
                <td className="num small">{r.sha256?.slice(0, 16)}…</td>
                <td>
                  <a className="btn tiny" href={`/api/pcap/${report.id}/files/${r.id}`} download>
                    {t('analysis.files.download')}
                  </a>
                </td>
              </tr>
            )}
          />
        </section>
      )

    case 'findings':
      return (
        <section className="card wide">
          <Table
            columns={[
              { key: 'sev', label: t('analysis.findings.severity') },
              { key: 'k', label: t('analysis.findings.kind') },
              { key: 'c', label: t('analysis.findings.client') },
              { key: 's', label: t('analysis.findings.server') },
              { key: 'e', label: t('analysis.findings.evidence') },
            ]}
            rows={report.findings}
            keyOf={(r, i) => `${r.kind}-${r.client}-${r.evidence}`}
            empty={t('analysis.findings.none')}
            renderRow={(r, key) => (
              <tr key={key} className={`sev-row-${r.severity}`}>
                <td className={`sev sev-${r.severity}`}>{r.severity}</td>
                <td>
                  {r.title}
                  {r.heuristic && (
                    <div className="dim small" title={t('analysis.findings.heuristic')}>
                      ≈ {t('analysis.findings.heuristic')}
                    </div>
                  )}
                </td>
                <td className="num">{r.client || '—'}</td>
                <td className="num">{r.server || '—'}</td>
                <td className="num small">{r.evidence}</td>
              </tr>
            )}
          />
        </section>
      )

    case 'geo':
      return (
        <section className="card wide">
          <h2>{t('analysis.tabs.geo')}</h2>
          <BarRows
            rows={(report.geo_points || []).slice(0, 15).map((g) => ({
              key: `${g.country} ${g.city} · ${g.ip}`, value: g.bytes,
            }))}
          />
          {(!report.geo_points || report.geo_points.length === 0) && (
            <div className="empty">{t('analysis.geo.none')}</div>
          )}
        </section>
      )

    default:
      return null
  }
}

function Tile({ label, value }) {
  return (
    <div className="tile">
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  )
}

function Row({ k, v }) {
  return (
    <tr>
      <td className="dim">{k}</td>
      <td className="num">{v}</td>
    </tr>
  )
}
