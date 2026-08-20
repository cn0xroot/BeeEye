import { useCallback, useEffect, useState } from 'react'

export const THEMES = ['system', 'light', 'dark', 'midnight-neon', 'matrix', 'tech-blue', 'warm-amber', 'forest-green', 'high-contrast']

// Curated font stacks. Each is a distinct character, not a random pick: a
// crisp UI sans, a technical monospace, a rounded humanist, and a reading
// serif. All resolve to fonts commonly present on Linux/macOS/Windows and
// degrade cleanly, so nothing depends on a web-font download.
export const FONTS = {
  system: 'system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  mono: 'ui-monospace, "JetBrains Mono", "Cascadia Code", "SF Mono", "Roboto Mono", Menlo, Consolas, "Noto Sans Mono CJK SC", monospace',
  rounded: '"SF Pro Rounded", "Segoe UI Variable", "Nunito", "Quicksand", system-ui, "PingFang SC", sans-serif',
  serif: '"Iowan Old Style", "Source Han Serif SC", "Songti SC", Georgia, "Times New Roman", serif',
}

// UI scale steps, applied with CSS zoom so px-sized elements scale too.
export const SIZES = { s: 0.9, m: 1, l: 1.15, xl: 1.3 }

const FONT_KEY = 'BeeEye.font'
const SIZE_KEY = 'BeeEye.size'

function applyFont(font) {
  document.documentElement.style.setProperty('--ui-font', FONTS[font] || FONTS.system)
}
function applySize(size) {
  document.documentElement.style.setProperty('--ui-zoom', String(SIZES[size] || 1))
}

// useFont / useSize persist their choice and apply it to the document root; the
// CSS reads --ui-font and --ui-zoom.
export function useFont() {
  const [font, setFontState] = useState(() => {
    try { const v = localStorage.getItem(FONT_KEY); return FONTS[v] ? v : 'system' } catch { return 'system' }
  })
  useEffect(() => { applyFont(font) }, [font])
  const setFont = useCallback((v) => {
    setFontState(v)
    try { localStorage.setItem(FONT_KEY, v) } catch { /* private mode */ }
  }, [])
  return [font, setFont]
}

export function useSize() {
  const [size, setSizeState] = useState(() => {
    try { const v = localStorage.getItem(SIZE_KEY); return SIZES[v] ? v : 'm' } catch { return 'm' }
  })
  useEffect(() => { applySize(size) }, [size])
  const setSize = useCallback((v) => {
    setSizeState(v)
    try { localStorage.setItem(SIZE_KEY, v) } catch { /* private mode */ }
  }, [])
  return [size, setSize]
}

const STORAGE_KEY = 'BeeEye.theme'

function systemTheme() {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function resolve(theme) {
  return theme === 'system' ? systemTheme() : theme
}

function apply(resolved) {
  document.documentElement.setAttribute('data-theme', resolved)
}

// useTheme persists the choice and keeps "follow system" actually following:
// a stored preference that stops tracking the OS after the first load is a
// common and irritating bug.
export function useTheme() {
  const [theme, setThemeState] = useState(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      return THEMES.includes(stored) ? stored : 'system'
    } catch {
      return 'system'
    }
  })

  // The resolved theme is state of its own, not something derived at render:
  // the sun/moon switch highlights whichever is actually showing, and under
  // "follow system" that changes without the stored preference changing.
  const [resolved, setResolved] = useState(() => 'light')

  useEffect(() => {
    const next = resolve(theme)
    apply(next)
    setResolved(next)
    if (theme !== 'system') return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => {
      const r = resolve('system')
      apply(r)
      setResolved(r)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [theme])

  const setTheme = useCallback((next) => {
    setThemeState(next)
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      /* private mode: the choice applies for this session only */
    }
  }, [])

  return [theme, setTheme, resolved]
}

// readSeriesColors pulls the chart palette out of the active theme's tokens.
// Charts must never hardcode colours (§3.8.2): reading them here is what makes
// a theme switch repaint the charts along with the rest of the page.
export function readSeriesColors(count = 8) {
  const cs = getComputedStyle(document.documentElement)
  const out = []
  for (let i = 1; i <= count; i++) {
    out.push(cs.getPropertyValue(`--series-${i}`).trim() || '#888')
  }
  return out
}

export function readToken(name, fallback = '') {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}
