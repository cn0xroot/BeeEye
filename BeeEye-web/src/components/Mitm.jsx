import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'

// Mitm is F45's UI: download the locally-generated CA a phone or computer
// installs to opt into TLS decryption, and the per-platform "installing it
// isn't the same as trusting it" steps that trip people up on every MITM
// tool, not just this one.
export default function Mitm() {
  const { t } = useTranslation()
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const [exchanges, setExchanges] = useState([])
  const [openId, setOpenId] = useState(null)
  const [detail, setDetail] = useState(null)
  const timer = useRef(null)

  const refresh = () => api.mitmStatus().then(setStatus).catch((e) => setError(e.message))
  useEffect(refresh, [])

  // Poll the decrypted request list while MITM is on.
  useEffect(() => {
    if (!status?.enabled) return
    let alive = true
    const poll = async () => {
      try {
        const rows = await api.mitmExchanges(100)
        if (alive) setExchanges(Array.isArray(rows) ? rows : [])
      } catch { /* transient */ }
      timer.current = setTimeout(poll, 2000)
    }
    poll()
    return () => { alive = false; clearTimeout(timer.current) }
  }, [status?.enabled])

  const openExchange = useCallback(async (id) => {
    if (openId === id) { setOpenId(null); setDetail(null); return }
    setOpenId(id); setDetail(null)
    try { setDetail(await api.mitmExchange(id)) } catch (e) { setDetail({ error: e.message }) }
  }, [openId])

  if (error) {
    return (
      <div className="view">
        <div className="banner error" role="alert">{t('common.error')}: {error}</div>
      </div>
    )
  }
  if (!status) return <div className="view"><div className="empty">{t('table.loading')}</div></div>

  return (
    <div className="view">
      <section className="card wide">
        <h2>{t('mitm.title')}</h2>
        <p className="mitm-intro">{t('mitm.intro')}</p>
      </section>

      {!status.enabled ? (
        <section className="card wide">
          <div className="banner warn">
            <b>{t('mitm.disabledTitle')}</b> {t('mitm.disabledBody')}
          </div>
          <pre className="detail-json">{'mitm:\n  enabled: true\n  listen: ":8443"\n  ca_dir: "./data/mitm"'}</pre>
        </section>
      ) : (
        <>
          <section className="card wide">
            <div className="tiles">
              <div className="tile">
                <div className="tile-value mono">{proxyAddress(status.listen_addr)}</div>
                <div className="tile-label">{t('mitm.proxyAddress')}</div>
                <div className="tile-sub">{t('mitm.proxyAddressHint')}</div>
              </div>
              <div className="tile">
                <div className="tile-value mono">{status.fingerprint}</div>
                <div className="tile-label">{t('mitm.fingerprint')}</div>
                <div className="tile-sub">{t('mitm.fingerprintHint')}</div>
              </div>
              <div className="tile">
                <div className="tile-value">{status.exchanges}</div>
                <div className="tile-label">{t('mitm.exchanges')}</div>
              </div>
            </div>
          </section>

          <section className="card wide">
            <h2>{t('mitm.downloadTitle')}</h2>
            <div className="mitm-downloads">
              <a className="btn primary" href={api.mitmCAUrl()} download>
                {t('mitm.downloadPem')}
              </a>
              <a className="btn" href={api.mitmMobileConfigUrl()} download>
                {t('mitm.downloadMobileConfig')}
              </a>
            </div>
            <p className="dim small">{t('mitm.downloadHint')}</p>
          </section>

          <section className="card wide">
            <h2>{t('mitm.exchangesTitle')} <span className="dim small">({exchanges.length})</span></h2>
            {exchanges.length === 0 ? (
              <p className="dim small">{t('mitm.exchangesEmpty')}</p>
            ) : (
              <table className="data-table mitm-exchanges">
                <thead>
                  <tr>
                    <th>{t('mitm.exTime')}</th>
                    <th>{t('mitm.exMethod')}</th>
                    <th>{t('mitm.exHost')}</th>
                    <th>{t('mitm.exStatus')}</th>
                    <th className="num">{t('mitm.exBytes')}</th>
                  </tr>
                </thead>
                <tbody>
                  {exchanges.map((e) => (
                    <>
                      <tr key={e.id} className={`ex-row ${openId === e.id ? 'open' : ''}`} onClick={() => openExchange(e.id)}>
                        <td className="dim mono small">{fmtTime(e.time)}</td>
                        <td><b>{e.method}</b></td>
                        <td className="mono ex-host">{e.host}<span className="dim">{e.path}</span></td>
                        <td><span className={`ex-status s${Math.floor((e.status_code || 0) / 100)}`}>{e.status_code || (e.error ? '×' : '—')}</span></td>
                        <td className="num dim">{e.req_bytes}/{e.resp_bytes}</td>
                      </tr>
                      {openId === e.id && (
                        <tr key={e.id + '-d'} className="ex-detail-row">
                          <td colSpan={5}>
                            {!detail ? (
                              <div className="dim small">{t('table.loading')}</div>
                            ) : detail.error ? (
                              <div className="banner error">{detail.error}</div>
                            ) : (
                              <div className="ex-detail">
                                <div className="ex-col">
                                  <div className="ex-col-title">{t('mitm.exRequest')}</div>
                                  <pre className="ex-headers">{headerLines(detail.req_headers)}</pre>
                                  {detail.req_body_b64 && <pre className="ex-body">{decodeB64(detail.req_body_b64)}</pre>}
                                </div>
                                <div className="ex-col">
                                  <div className="ex-col-title">{t('mitm.exResponse')} · {detail.status_code}</div>
                                  <pre className="ex-headers">{headerLines(detail.resp_headers)}</pre>
                                  {detail.resp_body_b64 && <pre className="ex-body">{decodeB64(detail.resp_body_b64)}</pre>}
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="card wide">
            <h2>{t('mitm.platformTitle')}</h2>
            <table className="data-table">
              <thead>
                <tr>
                  <th>{t('mitm.platform')}</th>
                  <th>{t('mitm.platformCaveat')}</th>
                </tr>
              </thead>
              <tbody>
                {['android', 'ios', 'macos', 'windows', 'firefox'].map((k) => (
                  <tr key={k}>
                    <td><b>{t(`mitm.platforms.${k}.name`)}</b></td>
                    <td>{t(`mitm.platforms.${k}.caveat`)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  )
}

// proxyAddress turns a Go listen address (":8443", "127.0.0.1:8443") into
// what a phone should actually type into its proxy settings — an empty host
// means "all interfaces", which is not itself a reachable address, so it's
// swapped for the hostname this page was loaded from (the gateway's own
// address, from the device's point of view).
function fmtTime(ts) {
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString()
}

function headerLines(h) {
  if (!h) return ''
  return Object.entries(h).map(([k, v]) => `${k}: ${(Array.isArray(v) ? v.join(', ') : v)}`).join('\n')
}

// decodeB64 turns a base64 body into readable text, capped, with non-printable
// bytes shown as · so a binary body cannot scramble the panel.
function decodeB64(b64) {
  try {
    const bin = atob(b64)
    const max = 4000
    let out = ''
    for (let i = 0; i < Math.min(bin.length, max); i++) {
      const c = bin.charCodeAt(i)
      out += (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) ? bin[i] : '·'
    }
    return bin.length > max ? out + `\n… (+${bin.length - max} bytes)` : out
  } catch { return '' }
}

function proxyAddress(listenAddr) {
  if (!listenAddr) return '—'
  const parts = listenAddr.split(':')
  const port = parts[parts.length - 1]
  const host = listenAddr.startsWith(':') ? window.location.hostname : parts.slice(0, -1).join(':')
  return `${host}:${port}`
}