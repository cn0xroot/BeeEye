import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { explainFor } from '../protocolExplain'

// Plaintext shows the decrypted HTTPS of the selected packet's process. The
// gateway can only decrypt its own processes' TLS (uprobes on their OpenSSL
// library), which is exactly the set the packet list attributes to a pid — so
// this pane is shown for a local flow and explains itself for a remote one.
//
// A SIM/GTP/SCTP packet is never going to have decrypted HTTPS to show here —
// it usually is not even IP, let alone TLS — so for those, this same "nothing
// to decrypt" slot shows what the selected message actually does instead, in
// both English and 中文 at once (see protocolExplain.js).
export default function Plaintext({ pid, comm, decryptRunning, fields }) {
  const { t } = useTranslation()
  const explain = !pid ? explainFor(fields) : null
  const [chunks, setChunks] = useState([])
  const [open, setOpen] = useState(null)
  const timer = useRef(null)

  useEffect(() => {
    setChunks([])
    if (!pid) return
    let alive = true
    const poll = async () => {
      try {
        const r = await fetch(`/api/plaintext?pid=${pid}&limit=100`)
        const j = await r.json()
        if (alive) setChunks(j.chunks || [])
      } catch {
        /* transient; the next tick retries */
      }
      timer.current = setTimeout(poll, 1000)
    }
    poll()
    return () => {
      alive = false
      clearTimeout(timer.current)
    }
  }, [pid])

  return (
    <section className="pane pane-plaintext">
      <div className="pane-head">
        <h2>{t('plaintext.title')}</h2>
        <span className={`decrypt-dot ${decryptRunning ? 'on' : 'off'}`}>
          {decryptRunning ? t('plaintext.on') : t('plaintext.off')}
        </span>
      </div>
      <div className="plaintext-body">
        {!pid ? (
          explain ? (
            <div className="empty pt-explain">
              <div className="empty-title">{explain.kind} · {explain.label}</div>
              <p className="pt-explain-lang"><span className="pt-explain-tag">EN</span>{explain.en}</p>
              <p className="pt-explain-lang"><span className="pt-explain-tag">中</span>{explain.zh}</p>
            </div>
          ) : (
            <div className="empty">
              <div className="empty-title">{t('plaintext.remoteTitle')}</div>
              <div className="empty-help">{t('plaintext.remoteHelp')}</div>
            </div>
          )
        ) : chunks.length === 0 ? (
          <div className="empty">
            <div className="empty-title">{t('plaintext.none', { comm: comm || pid })}</div>
            <div className="empty-help">{t('plaintext.noneHelp')}</div>
          </div>
        ) : (
          <ul className="plaintext-list">
            {chunks.map((c, i) => (
              <li key={i} className={`pt-item dir-${c.dir}`} onClick={() => setOpen(open === i ? null : i)}>
                <span className="pt-arrow">{c.dir === 'write' ? '↑' : '↓'}</span>
                <span className="pt-meta">
                  {c.comm}/{c.pid} · {c.bytes}B{c.truncated ? '+' : ''}
                </span>
                <pre className={`pt-text ${open === i ? 'full' : ''}`}>{c.preview}</pre>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
