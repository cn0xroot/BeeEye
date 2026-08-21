import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatBytes } from '../api'

// TrafficTrendChart is a plain client-side SVG chart — deliberately not the
// GPU-rendered glow/bloom picture this panel used to be. That picture was
// beautiful and completely illegible: it had no axis, no gridlines, no
// numbers, so "is that peak 40 KB or 400 KB" had no answer short of
// eyeballing a colour gradient. Styled after sniffnet's own overview chart
// (a plain filled area, axis labels, a legend, nothing else) because that is
// what was actually asked for — a chart, not an art piece.
//
// tx (this gateway sending) fills upward from a centre baseline, rx
// (receiving) mirrors it downward, so upload/download read as two shapes
// instead of one combined line where a big download could hide a real
// upload spike underneath it.
const VB_W = 1000
const VB_H = 500
const HALF = VB_H / 2
const MARGIN_TOP = 14 // headroom so a max-height sample doesn't touch the card edge
const AXIS_W = 54 // left gutter reserved for the Y-axis byte labels

export default function TrafficTrendChart() {
  const { t } = useTranslation()
  const [series, setSeries] = useState(null) // { tx: number[], rx: number[], tick_ms }
  const tRef = useRef(null)

  useEffect(() => {
    let alive = true
    const poll = () => {
      fetch('/api/render/traffic/series')
        .then((r) => r.json())
        .then((d) => { if (alive) setSeries(d) })
        .catch(() => {})
    }
    poll()
    const id = setInterval(poll, 1000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  if (!series || !series.tx?.length) {
    return (
      <div className="traffic-trend-chart">
        <div className="chart-empty">{t('chart.noData')}</div>
      </div>
    )
  }

  const { tx, rx, tick_ms: tickMs } = series
  const n = tx.length
  const plotW = VB_W - AXIS_W
  const xAt = (i) => AXIS_W + (i / (n - 1)) * plotW

  // A "nice" ceiling (1/2/5 × 10^k) above the louder of the two directions —
  // sharing one scale between tx/rx keeps their heights honestly comparable,
  // the way sniffnet's single shared axis does, rather than each side
  // silently auto-scaling to its own max and looking equally "full" no
  // matter how lopsided the real traffic is.
  const rawMax = Math.max(1, ...tx, ...rx)
  const maxVal = niceCeiling(rawMax)

  const yTx = (v) => HALF - (Math.min(v, maxVal) / maxVal) * (HALF - MARGIN_TOP)
  const yRx = (v) => HALF + (Math.min(v, maxVal) / maxVal) * (HALF - MARGIN_TOP)

  const areaPath = (values, yAt) => {
    const pts = values.map((v, i) => `${xAt(i)},${yAt(v)}`)
    return `M${AXIS_W},${HALF} L${pts.join(' L')} L${xAt(n - 1)},${HALF} Z`
  }
  const linePath = (values, yAt) =>
    `M${values.map((v, i) => `${xAt(i)},${yAt(v)}`).join(' L')}`

  const gridSteps = [0.25, 0.5, 0.75, 1]
  const spanMs = tickMs * (n - 1)

  return (
    <div className="traffic-trend-chart">
      <div className="traffic-trend-legend">
        <span className="ttl-item">
          <span className="ttl-swatch ttl-tx" />
          {t('summary.outgoing')}: <b>{formatBytes(tx[tx.length - 1] || 0)}/s</b>
        </span>
        <span className="ttl-item">
          <span className="ttl-swatch ttl-rx" />
          {t('summary.incoming')}: <b>{formatBytes(rx[rx.length - 1] || 0)}/s</b>
        </span>
      </div>
      <svg
        ref={tRef}
        className="traffic-trend-svg"
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        preserveAspectRatio="none"
      >
        {/* Y gridlines + labels, mirrored above/below the baseline. */}
        {gridSteps.map((f) => (
          <g key={`g-${f}`} className="ttc-grid">
            <line x1={AXIS_W} x2={VB_W} y1={yTx(f * maxVal)} y2={yTx(f * maxVal)} />
            <line x1={AXIS_W} x2={VB_W} y1={yRx(f * maxVal)} y2={yRx(f * maxVal)} />
            <text x={AXIS_W - 8} y={yTx(f * maxVal)} textAnchor="end" dominantBaseline="middle">
              {formatBytes(f * maxVal)}
            </text>
          </g>
        ))}
        <line className="ttc-baseline" x1={AXIS_W} x2={VB_W} y1={HALF} y2={HALF} />

        <path className="ttc-area ttc-area-tx" d={areaPath(tx, yTx)} />
        <path className="ttc-area ttc-area-rx" d={areaPath(rx, yRx)} />
        <path className="ttc-line ttc-line-tx" d={linePath(tx, yTx)} />
        <path className="ttc-line ttc-line-rx" d={linePath(rx, yRx)} />
      </svg>
      <div className="traffic-trend-xaxis" style={{ marginLeft: `${(AXIS_W / VB_W) * 100}%` }}>
        <span>-{formatDuration(spanMs)}</span>
        <span>-{formatDuration(spanMs / 2)}</span>
        <span>{t('chart.now')}</span>
      </div>
    </div>
  )
}

// niceCeiling rounds up to the nearest 1/2/5 × 10^k so axis labels read as
// "20 KB" / "50 KB", never "37,412 B" — the same convention any normal
// charting library's auto-scale uses.
function niceCeiling(v) {
  if (v <= 0) return 1
  const exp = Math.floor(Math.log10(v))
  const base = Math.pow(10, exp)
  for (const m of [1, 2, 5, 10]) {
    if (v <= m * base) return m * base
  }
  return 10 * base
}

function formatDuration(ms) {
  const s = Math.round(ms / 1000)
  if (s < 90) return `${s}s`
  return `${Math.round(s / 60)}m`
}
