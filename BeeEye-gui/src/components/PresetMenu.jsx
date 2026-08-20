import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { PRESET_GROUPS, combine } from '../filterPresets'

// PresetMenu offers ready-made display filters. Picking one ANDs it onto
// whatever is already in the box rather than replacing it, and the result stays
// editable text — the templates are a starting point, not a separate mode.
export default function PresetMenu({ current, onPick }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    const onKey = (e) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div className="preset" ref={ref}>
      <button
        type="button"
        className="btn btn-ghost"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {t('presets.title')} <span className="glyph">▾</span>
      </button>

      {open && (
        <div className="preset-menu" role="menu">
          <div className="preset-hint">{t('presets.hint')}</div>
          {PRESET_GROUPS.map((g) => (
            <div key={g.id} className="preset-group">
              <div className="preset-group-title">{t(`presets.groups.${g.id}`)}</div>
              {g.items.map((it) => (
                <button
                  key={it.id}
                  type="button"
                  role="menuitem"
                  className="preset-item"
                  onClick={() => {
                    onPick(combine(current, it.expr))
                    setOpen(false)
                  }}
                >
                  <span className="preset-label">{t(`presets.items.${it.id}`)}</span>
                  <code className="preset-expr">{it.expr}</code>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
