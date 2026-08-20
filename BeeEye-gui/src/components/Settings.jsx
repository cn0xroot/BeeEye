import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { MODES, FONTS, SIZES } from '../appearance'

// Appearance settings for the analyzer: theme, font, UI scale — mirrors the
// overview UI's panel so the two feel like one product.
export default function Settings({ mode, onMode, font, onFont, size, onSize }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  return (
    <div className="settings" ref={ref}>
      <button className="settings-btn" onClick={() => setOpen((v) => !v)} aria-label={t('settings.title')} title={t('settings.title')}>
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H10a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V10a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
        </svg>
      </button>
      {open && (
        <div className="settings-menu" role="menu">
          <div className="settings-group">
            <div className="settings-label">{t('theme.label')}</div>
            <div className="theme-grid">
              {MODES.map((m) => (
                <button key={m} className={`theme-swatch ${mode === m ? 'active' : ''}`} data-appearance-preview={m} onClick={() => onMode(m)} title={t(`theme.${m}`)}>
                  <span className="sw-a" /><span className="sw-b" /><span className="sw-c" />
                  <span className="sw-name">{t(`theme.${m}`)}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="settings-group">
            <div className="settings-label">{t('settings.font')}</div>
            <div className="seg">
              {Object.keys(FONTS).map((f) => (
                <button key={f} className={font === f ? 'active' : ''} onClick={() => onFont(f)} style={{ fontFamily: FONTS[f] }}>{t(`settings.fonts.${f}`)}</button>
              ))}
            </div>
          </div>
          <div className="settings-group">
            <div className="settings-label">{t('settings.size')}</div>
            <div className="seg">
              {Object.keys(SIZES).map((z) => (
                <button key={z} className={size === z ? 'active' : ''} onClick={() => onSize(z)}>{t(`settings.sizes.${z}`)}</button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
