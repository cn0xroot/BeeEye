import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'
import { combine } from '../filterPresets'
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

// QUICK_FIELDS are shortcuts for the dimensions people look for a packet by
// most (source, destination, protocol, process) — each builds one clause of
// the same display-filter expression the free-text box takes, via `combine`,
// so this is a faster way to type a filter, not a second query language.
const QUICK_FIELDS = [
  { key: 'src', labelKey: 'toolbar.quickSrc', placeholderKey: 'toolbar.quickSrcPlaceholder', build: (v) => `ip.src contains "${v}"` },
  { key: 'dst', labelKey: 'toolbar.quickDst', placeholderKey: 'toolbar.quickDstPlaceholder', build: (v) => `ip.dst contains "${v}"` },
  // A protocol name is a bare presence test (matches the preset menu's own
  // style), not a contains clause — "tls" is a discrete keyword, not text to
  // search for a substring of.
  { key: 'proto', labelKey: 'toolbar.quickProto', placeholderKey: 'toolbar.quickProtoPlaceholder', build: (v) => v },
  { key: 'process', labelKey: 'toolbar.quickProcess', placeholderKey: 'toolbar.quickProcessPlaceholder', build: (v) => `process.comm contains "${v}"` },
]

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
  const fileInputRef = useRef(null)
  const [quick, setQuick] = useState({ src: '', dst: '', proto: '', process: '' })

  // Default to whatever the server is capturing on, else the first live NIC.
  // While offline (replaying a file), status.iface holds the filename, not
  // an interface — must not leak into this picker's value, or "Start" after
  // closing the file would try to open a NIC named "capture.pcap".
  useEffect(() => {
    if (iface) return
    if (status?.iface && !status?.offline) setIface(status.iface)
    else if (interfaces.length) {
      // "any" is the right default on a gateway: the interesting traffic is
      // rarely all on one NIC, and each packet still records where it came in.
      const pick = interfaces.find((i) => i.any) ||
        interfaces.find((i) => i.up && i.name !== 'lo') || interfaces[0]
      setIface(pick.name)
    }
  }, [status?.iface, status?.offline, interfaces, iface])

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

  // Opening a file goes through the exact same onStarted callback a live
  // capture does — the server replays it through the identical pipeline
  // (Session.OpenFile), so "new packets showed up" is the same event either
  // way, just with status.offline now true.
  const openFile = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = '' // so picking the same file twice still fires onChange
    if (!file) return
    setBusy(true)
    setError(null)
    try {
      onStarted(await api.openFile(file))
      // Best-effort: also fold this file into the overview app's own store
      // (see api.importToOverview) so it reflects the import too, not just
      // the analyzer. Never awaited and never surfaced as an error here —
      // the analyzer's own import above is what this button promises.
      api.importToOverview(file)
    } catch (err) {
      setError(err.message)
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

  // A quick-filter field ANDs its clause onto whatever is already in the box
  // and applies immediately — the same "picking it does the thing" contract
  // PresetMenu already established, just parameterised by typed text instead
  // of a fixed template.
  const applyQuick = async (field) => {
    const v = quick[field.key].trim()
    if (!v) return
    const expr = combine(filter, field.build(v))
    setFilter(expr)
    try {
      onFilterApplied(await api.setFilter(expr))
      setFilterError(null)
    } catch (err) {
      setFilterError(err.message)
    }
    setQuick((q) => ({ ...q, [field.key]: '' }))
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
            {/* status.iface can set `iface` before the /api/interfaces fetch
                above it resolves (e.g. the analyzer was already capturing
                when this page loaded) — without a matching <option> yet, a
                native <select> renders blank instead of the name, which
                reads as "my interface got cleared" until the real list
                arrives a moment later. This placeholder keeps the name
                visible the whole time; it is replaced once the fetch
                completes and interfaces actually contains it. */}
            {iface && !interfaces.some((i) => i.name === iface) && (
              <option value={iface}>{iface}</option>
            )}
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

        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap"
          onChange={openFile}
          style={{ display: 'none' }}
        />
        <button
          className="btn btn-ghost"
          onClick={() => fileInputRef.current?.click()}
          disabled={busy}
          title={t('toolbar.openFileHint')}
        >
          {t('toolbar.openFile')}
        </button>

        {status?.offline && (
          <span className="offline-badge" title={t('toolbar.offlineHint', { name: status.iface })}>
            {t('toolbar.offlineBadge', { name: status.iface })}
          </span>
        )}

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

      {/* Dedicated fields for the dimensions people actually search a packet
          list by, instead of requiring the filter grammar to locate one —
          each just builds and ANDs in one clause (see applyQuick). */}
      <div className="quick-filter-row">
        <span className="field-label">{t('toolbar.quickFilter')}</span>
        {QUICK_FIELDS.map((field) => (
          <label key={field.key} className="quick-filter-field">
            <span className="quick-filter-label">{t(field.labelKey)}</span>
            <input
              value={quick[field.key]}
              onChange={(e) => setQuick((q) => ({ ...q, [field.key]: e.target.value }))}
              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), applyQuick(field))}
              placeholder={t(field.placeholderKey)}
              spellCheck="false"
              autoComplete="off"
            />
            <button
              type="button"
              className="btn btn-ghost tiny"
              onClick={() => applyQuick(field)}
              disabled={!quick[field.key].trim()}
              title={t('toolbar.quickAdd')}
              aria-label={t('toolbar.quickAdd')}
            >
              +
            </button>
          </label>
        ))}
      </div>

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
