import { useTranslation } from 'react-i18next'
import Settings from './Settings'

const VIEWS = ['overview', 'devices', 'connections', 'byIp', 'byProtocol', 'dns', 'mitm', 'alerts']

// The analyzer (BeeEye-gui) is a second, independent process (F42) — its own
// port, own frontend, no shared state with this one beyond whatever a file
// opened there also gets POSTed into this app's own store (see
// Analysis.jsx's former upload flow, now replaced by opening files directly
// in the analyzer). There is no API this frontend can ask "what port is the
// analyzer actually on", so this assumes the documented default (agent on
// 8080, analyzer one port up on 8081 — see INSTALL.md / scripts/dev.sh) and
// keeps the current page's own protocol and hostname, so it still works over
// LAN, a custom hostname, or HTTPS behind a reverse proxy for the agent
// itself, and just fails obviously as a normal broken link if the analyzer
// isn't actually reachable there.
function analyzerURL() {
  return `${window.location.protocol}//${window.location.hostname}:8081`
}

// The two glyphs are inline SVG rather than an emoji or an icon font: ☀/🌙
// render as someone else's colour picture on most platforms, and here the
// glyph has to take the theme's own colour to show which side is active.
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
      <path
        d="M20.3 14.6A8.6 8.6 0 0 1 9.4 3.7a8.6 8.6 0 1 0 10.9 10.9z"
        fill="currentColor"
      />
    </svg>
  )
}

export default function Header({ view, onView, theme, resolvedTheme, onTheme, font, onFont, size, onSize, alertCount, source }) {
  const { t, i18n } = useTranslation()

  return (
    <header className="app-header">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">🐝</span>
        <div>
          <div className="brand-name">{t('app.title')}</div>
          <div className="brand-sub">
            {t('app.subtitle')}
            {source && (
              <span className={`source-badge ${source.live ? 'live' : 'sim'}`}>
                {source.live
                  ? t('source.live', { iface: source.iface || '' })
                  : t('source.simulated')}
              </span>
            )}
          </div>
        </div>
      </div>

      <nav className="nav" aria-label={t('app.title')}>
        {VIEWS.map((v) => (
          <button
            key={v}
            className={view === v ? 'active' : ''}
            onClick={() => onView(v)}
            aria-current={view === v ? 'page' : undefined}
          >
            {t(`nav.${v}`)}
            {v === 'alerts' && alertCount > 0 && <span className="badge">{alertCount}</span>}
          </button>
        ))}
      </nav>

      <div className="header-controls">
        <a
          className="btn ghost tiny open-analyzer"
          href={analyzerURL()}
          target="_blank"
          rel="noreferrer"
        >
          {t('nav.openAnalyzer')}
        </a>

        <div className="theme-switch" role="group" aria-label={t('settings.theme')}>
          {[
            ['light', SunIcon],
            ['dark', MoonIcon],
          ].map(([mode, Icon]) => (
            <button
              key={mode}
              className={resolvedTheme === mode ? 'active' : ''}
              onClick={() => onTheme(mode)}
              title={t(`settings.themes.${mode}`)}
              aria-label={t(`settings.themes.${mode}`)}
              aria-pressed={resolvedTheme === mode}
            >
              <Icon />
            </button>
          ))}
        </div>

        <Settings theme={theme} onTheme={onTheme} font={font} onFont={onFont} size={size} onSize={onSize} />

        <div className="lang-switch" role="group" aria-label={t('settings.language')}>
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
    </header>
  )
}
