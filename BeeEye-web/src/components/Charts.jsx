import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { readSeriesColors, readToken } from '../theme'
import { formatBytes } from '../api'

// Charts are hand-drawn SVG rather than a charting library, for two reasons:
// the colours have to come from the active theme's CSS tokens (§3.8.2), and
// every label has to go through i18n (§3.8.1). Both are easier to guarantee
// with direct control than by fighting a library's own theming.
//
// Shared conventions:
//  - one measure per axis, never a second y-scale
//  - series colours are assigned by identity in a fixed order, never cycled
//  - a legend is always present for ≥2 series, so colour is never the only cue
//  - grid and axis lines recede; the data is the loudest thing on the canvas

// useThemeColors re-reads the palette whenever the theme changes, which is what
// makes a theme switch actually repaint the charts.
function useThemeColors() {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const obs = new MutationObserver(() => setTick((v) => v + 1))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])
  return useMemo(
    () => ({
      series: readSeriesColors(8),
      grid: readToken('--grid', '#ddd'),
      axis: readToken('--axis', '#999'),
      text: readToken('--text-faint', '#888'),
      surface: readToken('--surface', '#fff'),
    }),
    [tick],
  )
}

function niceMax(v) {
  if (v <= 0) return 1
  const mag = 10 ** Math.floor(Math.log10(v))
  return Math.ceil(v / mag) * mag
}

/**
 * TrendChart draws stacked-free multi-line traffic over time.
 * points: [{ ts, values: { seriesKey: {bytes, conns} } }]
 */
export function TrendChart({ points, series, labelFor, height = 220 }) {
  const { t, i18n } = useTranslation()
  const c = useThemeColors()
  const [hover, setHover] = useState(null)
  const ref = useRef(null)

  if (!points?.length || !series?.length) {
    return <div className="chart-empty">{t('chart.noData')}</div>
  }

  // Cap at the first 5 series by total volume; beyond that a line chart stops
  // being readable and the rest fold into "Other" rather than becoming
  // indistinguishable extra hues.
  const totals = series.map((s) => ({
    key: s,
    total: points.reduce((a, p) => a + (p.values[s]?.bytes || 0), 0),
  }))
  totals.sort((a, b) => b.total - a.total)
  const shown = totals.slice(0, 5).map((x) => x.key)
  const foldRest = totals.length > 5

  const rows = points.map((p) => {
    const v = {}
    shown.forEach((s) => { v[s] = p.values[s]?.bytes || 0 })
    if (foldRest) {
      v.__other = totals.slice(5).reduce((a, x) => a + (p.values[x.key]?.bytes || 0), 0)
    }
    return { ts: p.ts, v }
  })
  const keys = foldRest ? [...shown, '__other'] : shown

  const W = 900
  const H = height
  const pad = { l: 62, r: 14, t: 12, b: 26 }
  const iw = W - pad.l - pad.r
  const ih = H - pad.t - pad.b

  const maxY = niceMax(Math.max(...rows.flatMap((r) => keys.map((k) => r.v[k] || 0)), 1))
  const x = (i) => pad.l + (rows.length === 1 ? iw / 2 : (i / (rows.length - 1)) * iw)
  const y = (val) => pad.t + ih - (val / maxY) * ih

  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * maxY)

  const onMove = (e) => {
    const rect = ref.current.getBoundingClientRect()
    const px = ((e.clientX - rect.left) / rect.width) * W
    const i = Math.round(((px - pad.l) / iw) * (rows.length - 1))
    setHover(i >= 0 && i < rows.length ? i : null)
  }

  return (
    <div className="chart">
      <svg
        ref={ref}
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        {ticks.map((tv, i) => (
          <g key={i}>
            <line x1={pad.l} x2={W - pad.r} y1={y(tv)} y2={y(tv)} stroke={c.grid} strokeWidth="1" />
            <text x={pad.l - 8} y={y(tv) + 4} textAnchor="end" fontSize="10" fill={c.text}>
              {formatBytes(tv)}
            </text>
          </g>
        ))}
        <line x1={pad.l} x2={W - pad.r} y1={y(0)} y2={y(0)} stroke={c.axis} strokeWidth="1" />

        {keys.map((k, si) => {
          const d = rows.map((r, i) => `${i === 0 ? 'M' : 'L'}${x(i)},${y(r.v[k] || 0)}`).join(' ')
          return (
            <path
              key={k}
              d={d}
              fill="none"
              stroke={c.series[si % c.series.length]}
              strokeWidth="2"
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          )
        })}

        {hover != null && (
          <>
            <line x1={x(hover)} x2={x(hover)} y1={pad.t} y2={pad.t + ih} stroke={c.axis} strokeDasharray="3 3" />
            {keys.map((k, si) => (
              <circle
                key={k}
                cx={x(hover)}
                cy={y(rows[hover].v[k] || 0)}
                r="4"
                fill={c.series[si % c.series.length]}
                stroke={c.surface}
                strokeWidth="2"
              />
            ))}
          </>
        )}

        {[0, Math.floor(rows.length / 2), rows.length - 1].map((i) => (
          <text key={i} x={x(i)} y={H - 8} textAnchor="middle" fontSize="10" fill={c.text}>
            {new Date(rows[i].ts * 1000).toLocaleTimeString(i18n.resolvedLanguage, {
              hour: '2-digit', minute: '2-digit',
            })}
          </text>
        ))}
      </svg>

      <ul className="legend">
        {keys.map((k, si) => (
          <li key={k}>
            <span className="swatch" style={{ background: c.series[si % c.series.length] }} />
            {k === '__other' ? t('chart.other') : labelFor?.(k) || k}
            {hover != null && <b> {formatBytes(rows[hover].v[k] || 0)}</b>}
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * BarRows is a horizontal magnitude chart. One measure, one colour: the
 * category names are already on the axis, so per-bar hues would encode nothing.
 */
export function BarRows({ rows, labelFor, valueFormat = formatBytes, max: maxOverride }) {
  const { t } = useTranslation()
  const c = useThemeColors()
  if (!rows?.length) return <div className="chart-empty">{t('chart.noData')}</div>

  const max = maxOverride || Math.max(...rows.map((r) => r.value), 1)
  return (
    <ul className="bars">
      {rows.map((r) => (
        <li key={r.key}>
          <span className="bar-label" title={labelFor?.(r.key) || r.key}>
            {labelFor?.(r.key) || r.key}
          </span>
          <span className="bar-track">
            <span
              className="bar-fill"
              style={{ width: `${Math.max(2, (r.value / max) * 100)}%`, background: c.series[0] }}
            />
          </span>
          <span className="bar-value">{valueFormat(r.value)}</span>
        </li>
      ))}
    </ul>
  )
}

/** Donut renders a share breakdown with a legend; never a bare pie with no labels. */
export function Donut({ rows, labelFor, size = 168 }) {
  const { t } = useTranslation()
  const c = useThemeColors()
  if (!rows?.length) return <div className="chart-empty">{t('chart.noData')}</div>

  const total = rows.reduce((a, r) => a + r.value, 0) || 1
  const R = size / 2
  const stroke = 26
  const r = R - stroke / 2
  const circ = 2 * Math.PI * r

  let acc = 0
  return (
    <div className="donut">
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img">
        {rows.map((row, i) => {
          const frac = row.value / total
          const dash = frac * circ
          const el = (
            <circle
              key={row.key}
              cx={R}
              cy={R}
              r={r}
              fill="none"
              stroke={c.series[i % c.series.length]}
              strokeWidth={stroke}
              strokeDasharray={`${Math.max(dash - 2, 0)} ${circ - Math.max(dash - 2, 0)}`}
              strokeDashoffset={-acc * circ}
              transform={`rotate(-90 ${R} ${R})`}
            />
          )
          acc += frac
          return el
        })}
      </svg>
      <ul className="legend column">
        {rows.map((row, i) => (
          <li key={row.key}>
            <span className="swatch" style={{ background: c.series[i % c.series.length] }} />
            {labelFor?.(row.key) || row.key}
            <b>{((row.value / total) * 100).toFixed(1)}%</b>
          </li>
        ))}
      </ul>
    </div>
  )
}
