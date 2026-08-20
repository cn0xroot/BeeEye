import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import PresetMenu from './PresetMenu'
import Settings from './Settings'

// Inline SVG rather than emoji: ☀/🌙 render as someone else's colour picture
// on most platforms, and here the glyph has to take the theme's own colour to
// show which side is active.
function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" focusable="false">
      <circle cx="12" cy="12" r="4.4" fill="currentColor" />
      <g stroke="currentColor" strokeWidth="1.9" strokeLinecap="round">
        <path d="M12 2.3v2.4M12 19.3v2.4M2.3 12h2.4M19.3 12h2.4" />
        <path d="M5.1 5.1l1.7 1.7M17.2 17.2l1.7 1.7M18.9 5.1l-1.7 1.7M6.8 17.2l-1.7 1.7" />
      </g>
    </svg>
  )
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" focusable="false">
      <path d="M20.3 14.6A8.6 8.6 0 0 1 9.4 3.7a8.6 8.6 0 1 0 10.9 10.9z" fill="currentColor" />
    </svg>
  )
}

// Toolbar owns capture control and the display filter.
//
// The filter box validates as you type against the server's own parser rather
// than a second, approximate one in the browser — one grammar, one verdict.
export default function Toolbar({ status, interfaces, onStarted, onStopped, onFilterApplied, resolvedAppearance, onAppearance, appearance, font, onFont, size, onSize }) {
  const { t, i18n } = useTranslation()
  const [iface, setIface] = useState('')
  const [promisc, setPromisc] = useState(true)
  const [filter, setFilter] = useState('')
  const [filterError, setFilterError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const debounce = useRef(null)

  // Default to whatever the server is capturing on, else the first live NIC.
  useEffect(() => {
    if (iface) return
    if (status?.iface) setIface(status.iface)
    else if (interfaces.length) {
      // "any" is the right default on a gateway: the interesting traffic is
      // rarely all on one NIC, and each packet still records where it came in.
      const pick = interfaces.find((i) => i.any) ||
        interfaces.find((i) => i.up && i.name !== 'lo') || interfaces[0]
      setIface(pick.name)
    }
  }, [status?.iface, interfaces, iface])

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current)
    if (!filter.trim()) {
      setFilterError(null)
      return
    }
    debounce.current = setTimeout(async () => {
      try {
        const r = await api.validateFilter(filter)
        setFilterError(r.valid ? null : r.error)
      } catch (e) {
        setFilterError(e.message)
      }
    }, 220)
    return () => clearTimeout(debounce.current)
  }, [filter])

  const start = async () => {
    setBusy(true)
    setError(null)
    try {
      const s = await api.start({ iface, promisc, filter })
      onStarted(s)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    setBusy(true)
    try {
      onStopped(await api.stop())
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const applyFilter = async (e) => {
    e?.preventDefault()
    try {
      const s = await api.setFilter(filter)
      setFilterError(null)
      onFilterApplied(s)
    } catch (err) {
      setFilterError(err.message)
    }
  }

  const running = status?.running

  return (
    <header className="toolbar">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">🐝</span>
        <div>
          <div className="brand-name">{t('app.title')}</div>
          <div className="brand-sub">{t('app.subtitle')}</div>
        </div>
      </div>

      <div className="toolbar-row">
        <label className="field">
          <span className="field-label">{t('toolbar.interface')}</span>
          <select value={iface} onChange={(e) => setIface(e.target.value)} disabled={running}>
            {interfaces.map((i) => (
              <option key={i.name} value={i.name} disabled={!i.up}>
                {i.name}
                {i.any ? ` — ${t('names.anyIface')}` : ''}
                {i.up || i.any ? '' : ' (down)'}
                {i.addrs?.length ? ` — ${i.addrs[0]}` : ''}
              </option>
            ))}
          </select>
        </label>

        <label className="checkbox" title={t('toolbar.promiscuous')}>
          <input
            type="checkbox"
            checked={promisc}
            onChange={(e) => setPromisc(e.target.checked)}
            disabled={running}
          />
          <span>{t('toolbar.promiscuous')}</span>
        </label>

        {running ? (
          <button className="btn btn-stop" onClick={stop} disabled={busy}>
            <span className="glyph">■</span> {t('toolbar.stop')}
          </button>
        ) : (
          <button className="btn btn-start" onClick={start} disabled={busy || !iface}>
            <span className="glyph">▶</span> {t('toolbar.start')}
          </button>
        )}

        <a className="btn btn-ghost" href={api.pcapURL()} download>
          {t('toolbar.exportPcap')}
        </a>

        <div className="spacer" />

        <div className="appearance-switch" role="group" aria-label={t('theme.label')}>
          {[
            ['light', SunIcon],
            ['dark', MoonIcon],
          ].map(([m, Icon]) => (
            <button
              key={m}
              className={resolvedAppearance === m ? 'active' : ''}
              onClick={() => onAppearance(m)}
              title={t(`theme.${m}`)}
              aria-label={t(`theme.${m}`)}
              aria-pressed={resolvedAppearance === m}
            >
              <Icon />
            </button>
          ))}
        </div>

        <Settings mode={appearance} onMode={onAppearance} font={font} onFont={onFont} size={size} onSize={onSize} />

        <div className="lang-switch" role="group" aria-label={t('actions.language')}>
          {[
            ['en', 'EN'],
            ['zh', '中文'],
          ].map(([lng, label]) => (
            <button
              key={lng}
              className={i18n.resolvedLanguage === lng ? 'active' : ''}
              onClick={() => i18n.changeLanguage(lng)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <form className="filter-row" onSubmit={applyFilter}>
        <span className="field-label">{t('toolbar.filter')}</span>
        {/* Picking a template applies it immediately. Only filling the box
            and waiting for Apply reads as "the template did nothing". */}
        <PresetMenu
          current={filter}
          onPick={async (expr) => {
            setFilter(expr)
            try {
              onFilterApplied(await api.setFilter(expr))
              setFilterError(null)
            } catch (err) {
              setFilterError(err.message)
            }
          }}
        />
        <input
          className={`filter-input ${filterError ? 'invalid' : filter ? 'valid' : ''}`}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder={t('toolbar.filterPlaceholder')}
          spellCheck="false"
          autoComplete="off"
        />
        <button className="btn btn-ghost" type="submit" disabled={!!filterError}>
          {t('toolbar.apply')}
        </button>
        <button
          className="btn btn-ghost"
          type="button"
          onClick={() => {
            setFilter('')
            api.setFilter('').then(onFilterApplied).catch(() => {})
          }}
        >
          {t('toolbar.clear')}
        </button>
      </form>

      {filterError && (
        <div className="inline-error" role="alert">
          {t('errors.filterInvalid')}: {filterError}
        </div>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {t('errors.startFailed')}: {error}
        </div>
      )}
    </header>
  )
}
