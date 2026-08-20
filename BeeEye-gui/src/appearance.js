import { useCallback, useEffect, useState } from 'react'

// The analyzer's light/dark switch. Three states, because "follow the system"
// is a real preference and not the same as picking dark once.
export const MODES = ['system', 'dark', 'light', 'midnight-neon', 'matrix']
const KEY = 'BeeEye.gui.appearance'

function resolve(mode) {
  if (mode !== 'system') return mode
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export function useAppearance() {
  const [mode, setModeState] = useState(() => {
    try {
      const v = localStorage.getItem(KEY)
      return MODES.includes(v) ? v : 'dark'
    } catch {
      return 'dark'
    }
  })

  // The resolved mode is state, not a render-time derivation: the sun/moon
  // switch highlights whichever appearance is actually showing, and under
  // "follow system" that changes without the stored preference changing.
  const [resolved, setResolved] = useState(() => 'dark')

  useEffect(() => {
    const next = resolve(mode)
    document.documentElement.setAttribute('data-appearance', next)
    setResolved(next)
    if (mode !== 'system') return
    const mq = window.matchMedia('(prefers-color-scheme: light)')
    const onChange = () => {
      const r = resolve('system')
      document.documentElement.setAttribute('data-appearance', r)
      setResolved(r)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [mode])

  const setMode = useCallback((next) => {
    setModeState(next)
    try {
      localStorage.setItem(KEY, next)
    } catch {
      /* private mode: applies for this session only */
    }
  }, [])

  return [mode, setMode, resolved]
}

// Shared with the overview UI: curated font stacks and zoom-based UI scale.
export const FONTS = {
  system: 'system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
  mono: 'ui-monospace, "JetBrains Mono", "Cascadia Code", "SF Mono", "Roboto Mono", Menlo, Consolas, "Noto Sans Mono CJK SC", monospace',
  rounded: '"SF Pro Rounded", "Segoe UI Variable", "Nunito", "Quicksand", system-ui, "PingFang SC", sans-serif',
  serif: '"Iowan Old Style", "Source Han Serif SC", "Songti SC", Georgia, "Times New Roman", serif',
}
export const SIZES = { s: 0.9, m: 1, l: 1.15, xl: 1.3 }

const FONT_KEY = 'BeeEye.gui.font'
const SIZE_KEY = 'BeeEye.gui.size'

export function useFont() {
  const [font, setFontState] = useState(() => {
    try { const v = localStorage.getItem(FONT_KEY); return FONTS[v] ? v : 'mono' } catch { return 'mono' }
  })
  useEffect(() => {
    document.documentElement.style.setProperty('--ui-font', FONTS[font] || FONTS.system)
  }, [font])
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
  useEffect(() => {
    document.documentElement.style.setProperty('--ui-zoom', String(SIZES[size] || 1))
  }, [size])
  const setSize = useCallback((v) => {
    setSizeState(v)
    try { localStorage.setItem(SIZE_KEY, v) } catch { /* private mode */ }
  }, [])
  return [size, setSize]
}
