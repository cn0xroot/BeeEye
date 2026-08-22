import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { formatRate } from '../api'

// TrafficTrendChart is a plain client-side SVG chart layered over the same
// GPU-rendered glow/bloom picture this panel used to be exclusively. The
// picture alone was beautiful and completely illegible: no axis, no
// gridlines, no numbers, so "is that peak 40 KB or 400 KB" had no answer
// short of eyeballing a colour gradient — see git history for the rewrite
// that replaced it outright. This keeps that fix (axis/gridlines/numbers are
// still the SVG, still legible, still what actually answers "how much") and
// puts the GPU frame back only as ambient heat behind it, low-opacity and
// additively blended so it reads as atmosphere, not as the data source. The
// backend (`GET /api/render/traffic/info`) is labeled next to the legend for
// the same reason TrafficField does it in the analyzer: claiming GPU
// rendering that is not actually happening — no CUDA device, CPU fallback in
// use — would be exactly the kind of lie F43 exists to prevent.
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
  const [info, setInfo] = useState(null) // { backend, device, ... } from /api/render/traffic/info
  const [glowTick, setGlowTick] = useState(0)
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

  useEffect(() => {
    let alive = true
    fetch('/api/render/traffic/info')
      .then((r) => r.json())
      .then((d) => { if (alive) setInfo(d) })
      .catch(() => {})
    return () => { alive = false }
  }, [])

  // The glow frame rides the history's own 1s tick (traffic_render.go rotates
  // its bucket once a second) — refetching faster than that would just draw
  // the same frame the server already drew, not a live update.
  useEffect(() => {
    const id = setInterval(() => setGlowTick((n) => n + 1), 1000)
    return () => clearInterval(id)
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

  const toPoints = (values, yAt) => values.map((v, i) => [xAt(i), yAt(v)])
  const linePath = (values, yAt) => {
    const pts = toPoints(values, yAt)
    return `M${pts[0][0]},${pts[0][1]} ${smoothCurveCommands(pts)}`
  }
  const areaPath = (values, yAt) => {
    const pts = toPoints(values, yAt)
    return `M${AXIS_W},${HALF} L${pts[0][0]},${pts[0][1]} ${smoothCurveCommands(pts)} L${xAt(n - 1)},${HALF} Z`
  }

  const gridSteps = [0.25, 0.5, 0.75, 1]
  const spanMs = tickMs * (n - 1)

  return (
    <div className="traffic-trend-chart">
      <div className="traffic-trend-legend">
        <span className="ttl-item">
          <span className="ttl-swatch ttl-tx" />
          {t('summary.outgoing')}: <b>{formatRate(tx[tx.length - 1] || 0)}</b>
        </span>
        <span className="ttl-item">
          <span className="ttl-swatch ttl-rx" />
          {t('summary.incoming')}: <b>{formatRate(rx[rx.length - 1] || 0)}</b>
        </span>
        {info && (
          <span className={`ttl-backend ${info.backend === 'cuda' ? 'gpu' : ''}`}>
            {info.backend === 'cuda' ? t('chart.rendererCuda') : t('chart.rendererCpu')}
            {info.device ? ` · ${info.device}` : ''}
          </span>
        )}
      </div>
      <div className="traffic-trend-plot">
        {/* Ambient GPU/CPU-rendered heat behind the legible SVG above it —
            decoration, not data: aria-hidden and never the only source of any
            number a viewer needs, per this file's header comment. */}
        <img
          className="traffic-trend-glow"
          alt=""
          aria-hidden="true"
          src={`/api/render/traffic.png?t=${glowTick}`}
        />
        <svg
          ref={tRef}
          className="traffic-trend-svg"
          viewBox={`0 0 ${VB_W} ${VB_H}`}
          preserveAspectRatio="none"
        >
        <defs>
          {/* Fills fade from strongest at the curve's own edge to faint at the
              baseline — the usual area-chart convention — rather than the
              flat, uniform-opacity fill this had before. Anchored to actual
              plot-area y-coordinates (not the path's own bounding box) so tx
              and rx, which occupy opposite halves of the chart, each fade the
              right direction without needing two different gradient shapes. */}
          <linearGradient id="ttcGradTx" x1="0" y1={MARGIN_TOP} x2="0" y2={HALF} gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#ffc83d" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#ffc83d" stopOpacity="0.04" />
          </linearGradient>
          <linearGradient id="ttcGradRx" x1="0" y1={HALF} x2="0" y2={VB_H - MARGIN_TOP} gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#2e9dff" stopOpacity="0.04" />
            <stop offset="100%" stopColor="#2e9dff" stopOpacity="0.5" />
          </linearGradient>
        </defs>
        {/* Y gridlines + labels, mirrored above/below the baseline. This is a
            bytes/sec axis (same numbers formatRate shows in the legend), not
            a byte-total one, so its labels use the same KB/s-and-up scale —
            "182 B/s" read as noise here for the same reason formatRate never
            shows raw bytes/sec in the legend. */}
        {gridSteps.map((f) => (
          <g key={`g-${f}`} className="ttc-grid">
            <line x1={AXIS_W} x2={VB_W} y1={yTx(f * maxVal)} y2={yTx(f * maxVal)} />
            <line x1={AXIS_W} x2={VB_W} y1={yRx(f * maxVal)} y2={yRx(f * maxVal)} />
            <text x={AXIS_W - 8} y={yTx(f * maxVal)} textAnchor="end" dominantBaseline="middle">
              {formatRate(f * maxVal)}
            </text>
          </g>
        ))}
        <line className="ttc-baseline" x1={AXIS_W} x2={VB_W} y1={HALF} y2={HALF} />

        <path className="ttc-area ttc-area-tx" d={areaPath(tx, yTx)} />
        <path className="ttc-area ttc-area-rx" d={areaPath(rx, yRx)} />
        <path className="ttc-line ttc-line-tx" d={linePath(tx, yTx)} />
        <path className="ttc-line ttc-line-rx" d={linePath(rx, yRx)} />
        </svg>
      </div>
      <div className="traffic-trend-xaxis" style={{ marginLeft: `${(AXIS_W / VB_W) * 100}%` }}>
        <span>-{formatDuration(spanMs)}</span>
        <span>-{formatDuration(spanMs / 2)}</span>
        <span>{t('chart.now')}</span>
      </div>
    </div>
  )
}

// smoothCurveCommands turns a polyline of [x,y] points into cubic-Bezier "C"
// path commands via a Catmull-Rom spline (the standard 1/6-tangent
// conversion) — the raw per-second samples are inherently blocky, and
// joining them with straight `L` segments made every one of those joints
// visible as a facet. This is what makes the line (and the area fill sharing
// the same points, so its edge doesn't disagree with the stroke on top of
// it) read as one continuous curve instead of a trace of sample points.
function smoothCurveCommands(points) {
  if (points.length < 2) return ''
  const cmds = []
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i - 1] || points[i]
    const p1 = points[i]
    const p2 = points[i + 1]
    const p3 = points[i + 2] || p2
    const c1x = p1[0] + (p2[0] - p0[0]) / 6
    const c1y = p1[1] + (p2[1] - p0[1]) / 6
    const c2x = p2[0] - (p3[0] - p1[0]) / 6
    const c2y = p2[1] - (p3[1] - p1[1]) / 6
    cmds.push(`C${c1x},${c1y} ${c2x},${c2y} ${p2[0]},${p2[1]}`)
  }
  return cmds.join(' ')
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
