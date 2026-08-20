import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { readToken } from '../theme'

// WorldMap is F32: a 2D world map of where this network is talking to, rendered
// on the GPU with WebGL2. Destinations are additively-blended radial glows, so
// overlapping traffic builds up as heat; new connections fire an animated arc
// from a fixed anchor. There is no real "where is this gateway", so the anchor
// is labelled as a schematic origin, never presented as a true location.
//
// Data: GET /api/views/geopairs (recent external connections with lat/lon).
// The projection is equirectangular: lon [-180,180] → x, lat [90,-90] → y.

function project(lat, lon) {
  // → clip space [-1,1], y up. Equirectangular.
  return [lon / 180, lat / 90]
}

const VERT_POINT = `#version 300 es
layout(location=0) in vec2 a_ll;    // lat, lon
layout(location=1) in float a_mag;  // 0..1 magnitude (bytes)
layout(location=2) in vec3 a_col;
uniform float u_size;
out vec3 v_col;
out float v_mag;
void main() {
  vec2 p = vec2(a_ll.y / 180.0, a_ll.x / 90.0);
  gl_Position = vec4(p, 0.0, 1.0);
  gl_PointSize = u_size * (0.6 + a_mag * 1.8);
  v_col = a_col;
  v_mag = a_mag;
}`

const FRAG_POINT = `#version 300 es
precision highp float;
in vec3 v_col;
in float v_mag;
out vec4 outColor;
void main() {
  // Soft radial glow: bright core, falling to zero at the sprite edge.
  vec2 d = gl_PointCoord - vec2(0.5);
  float r = length(d) * 2.0;
  float core = smoothstep(1.0, 0.0, r);
  float glow = pow(core, 2.2);
  float a = glow * (0.35 + v_mag * 0.65);
  outColor = vec4(v_col * (0.6 + glow * 0.8), a);
}`

const VERT_LINE = `#version 300 es
layout(location=0) in vec2 a_ll;
layout(location=1) in float a_t;    // 0..1 position along the arc
uniform float u_head;               // animated highlight position
out float v_t;
out float v_head;
void main() {
  vec2 p = vec2(a_ll.y / 180.0, a_ll.x / 90.0);
  gl_Position = vec4(p, 0.0, 1.0);
  v_t = a_t;
  v_head = u_head;
}`

const FRAG_LINE = `#version 300 es
precision highp float;
in float v_t;
in float v_head;
uniform vec3 u_col;
out vec4 outColor;
void main() {
  // A base filament plus a travelling pulse near u_head.
  float base = 0.22;
  float d = abs(v_t - v_head);
  float pulse = smoothstep(0.12, 0.0, d);
  float a = base + pulse * 0.9;
  outColor = vec4(u_col, a * (0.5 + v_t * 0.5));
}`

const VERT_GRID = `#version 300 es
layout(location=0) in vec2 a_ll;
void main() {
  vec2 p = vec2(a_ll.y / 180.0, a_ll.x / 90.0);
  gl_Position = vec4(p, 0.0, 1.0);
}`
const FRAG_GRID = `#version 300 es
precision highp float;
uniform vec3 u_col;
uniform float u_alpha;
out vec4 outColor;
void main() { outColor = vec4(u_col, u_alpha); }`

function compile(gl, type, src) {
  const s = gl.createShader(type)
  gl.shaderSource(s, src)
  gl.compileShader(s)
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    throw new Error(gl.getShaderInfoLog(s) || 'shader compile failed')
  }
  return s
}
function program(gl, vs, fs) {
  const p = gl.createProgram()
  gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, vs))
  gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, fs))
  gl.linkProgram(p)
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
    throw new Error(gl.getProgramInfoLog(p) || 'link failed')
  }
  return p
}

function hexToRgb(hex) {
  const h = (hex || '').trim().replace('#', '')
  if (h.length < 6) return [0.4, 0.7, 1]
  return [parseInt(h.slice(0, 2), 16) / 255, parseInt(h.slice(2, 4), 16) / 255, parseInt(h.slice(4, 6), 16) / 255]
}

// buildGraticule returns lat/lon line-segment pairs for a lon/lat grid.
function buildGraticule() {
  const v = []
  for (let lat = -60; lat <= 60; lat += 30) {
    for (let lon = -180; lon < 180; lon += 6) {
      v.push(lat, lon, lat, lon + 6)
    }
  }
  for (let lon = -150; lon <= 150; lon += 30) {
    for (let lat = -90; lat < 90; lat += 6) {
      v.push(lat, lon, lat + 6, lon)
    }
  }
  return new Float32Array(v)
}

// arc2d builds a curved poly-line from a→b in lat/lon, bowed toward the pole
// for a great-circle feel, with a t in [0,1] per vertex.
function arc2d(aLat, aLon, bLat, bLon, steps = 40) {
  const out = []
  const midLat = (aLat + bLat) / 2 + Math.min(40, Math.abs(aLon - bLon) * 0.25)
  for (let i = 0; i <= steps; i++) {
    const t = i / steps
    // Quadratic bezier through (a, mid, b).
    const lat = (1 - t) * (1 - t) * aLat + 2 * (1 - t) * t * midLat + t * t * bLat
    const lon = (1 - t) * (1 - t) * aLon + 2 * (1 - t) * t * ((aLon + bLon) / 2) + t * t * bLon
    out.push(lat, lon, t)
  }
  return out
}

// startCanvas2D renders the map without WebGL2: graticule, radial-gradient
// destination glows (additive via lighter composite), and curved arcs. Returns
// a cleanup function, matching the GL path.
function startCanvas2D(canvas, stateRef) {
  const ctx = canvas.getContext('2d')
  if (!ctx) return () => {}
  let raf = 0
  const t0 = performance.now()
  const W = () => canvas.width, H = () => canvas.height
  const px = (lat, lon) => [((lon + 180) / 360) * W(), ((90 - lat) / 180) * H()]

  const draw = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const w = canvas.clientWidth * dpr, h = canvas.clientHeight * dpr
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h }
    const now = (performance.now() - t0) / 1000
    const st = stateRef.current
    const css = getComputedStyle(document.documentElement)
    const bg = css.getPropertyValue('--bg').trim() || '#0a0e18'
    const axis = css.getPropertyValue('--axis').trim() || '#2a3550'
    const accent = css.getPropertyValue('--accent').trim() || '#22d3ee'

    ctx.fillStyle = bg
    ctx.fillRect(0, 0, W(), H())

    // Graticule.
    ctx.strokeStyle = axis; ctx.globalAlpha = 0.25; ctx.lineWidth = 1
    ctx.beginPath()
    for (let lat = -60; lat <= 60; lat += 30) { const [, y] = px(lat, 0); ctx.moveTo(0, y); ctx.lineTo(W(), y) }
    for (let lon = -150; lon <= 150; lon += 30) { const [x] = px(0, lon); ctx.moveTo(x, 0); ctx.lineTo(x, H()) }
    ctx.stroke(); ctx.globalAlpha = 1

    // Arcs.
    ctx.globalCompositeOperation = 'lighter'
    st.arcs = st.arcs.filter((a) => now - a.born < 2.2)
    for (const a of st.arcs) {
      const head = ((now - a.born) / 2.2)
      ctx.strokeStyle = accent; ctx.lineWidth = 1.4
      ctx.beginPath()
      const n = a.data.length / 3
      for (let k = 0; k < n; k++) {
        const lat = a.data[k * 3], lon = a.data[k * 3 + 1]
        const [x, y] = px(lat, lon)
        k === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
      }
      ctx.globalAlpha = 0.35; ctx.stroke()
      // Travelling pulse.
      const hi = Math.min(n - 1, Math.floor(head * (n - 1)))
      const [hx, hy] = px(a.data[hi * 3], a.data[hi * 3 + 1])
      const g = ctx.createRadialGradient(hx, hy, 0, hx, hy, 8 * dpr)
      g.addColorStop(0, accent); g.addColorStop(1, 'transparent')
      ctx.fillStyle = g; ctx.globalAlpha = 0.9
      ctx.beginPath(); ctx.arc(hx, hy, 8 * dpr, 0, Math.PI * 2); ctx.fill()
    }
    ctx.globalAlpha = 1

    // Destination glows.
    for (const p of st.points.values()) {
      const [x, y] = px(p.lat, p.lon)
      const r = (6 + p.mag * 16) * dpr
      const col = `rgb(${(p.col[0] * 255) | 0},${(p.col[1] * 255) | 0},${(p.col[2] * 255) | 0})`
      const g = ctx.createRadialGradient(x, y, 0, x, y, r)
      g.addColorStop(0, col); g.addColorStop(0.4, col); g.addColorStop(1, 'transparent')
      ctx.globalAlpha = 0.35 + p.mag * 0.5
      ctx.fillStyle = g
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill()
    }
    ctx.globalAlpha = 1; ctx.globalCompositeOperation = 'source-over'
    raf = requestAnimationFrame(draw)
  }
  raf = requestAnimationFrame(draw)
  return () => cancelAnimationFrame(raf)
}

// The gateway anchor: a schematic origin, not a real location.
const ANCHOR = { lat: 34, lon: 108 }

export default function WorldMap() {
  const { t } = useTranslation()
  const canvasRef = useRef(null)
  const glRef = useRef(null)
  const stateRef = useRef({ points: new Map(), arcs: [] })
  const [count, setCount] = useState(0)
  const [err, setErr] = useState(false)

  // --- GL setup ---
  useEffect(() => {
    const canvas = canvasRef.current
    const gl = canvas.getContext('webgl2', { alpha: true, premultipliedAlpha: false, antialias: true })
    if (!gl) {
      // No WebGL2 (locked-down browser, or a headless/remote session): fall
      // back to a Canvas 2D renderer that draws the same map with radial-
      // gradient glows. The GPU path is preferred for the richer additive
      // heat; this guarantees a map either way.
      return startCanvas2D(canvas, stateRef)
    }
    glRef.current = gl

    const progs = {
      point: program(gl, VERT_POINT, FRAG_POINT),
      line: program(gl, VERT_LINE, FRAG_LINE),
      grid: program(gl, VERT_GRID, FRAG_GRID),
    }
    const bufs = { point: gl.createBuffer(), pmag: gl.createBuffer(), pcol: gl.createBuffer(), line: gl.createBuffer(), grid: gl.createBuffer() }
    const grid = buildGraticule()
    gl.bindBuffer(gl.ARRAY_BUFFER, bufs.grid)
    gl.bufferData(gl.ARRAY_BUFFER, grid, gl.STATIC_DRAW)

    let raf = 0
    const t0 = performance.now()

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const w = canvas.clientWidth * dpr, h = canvas.clientHeight * dpr
      if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h }
      gl.viewport(0, 0, canvas.width, canvas.height)
    }

    const render = () => {
      resize()
      const now = (performance.now() - t0) / 1000
      const st = stateRef.current

      const bg = hexToRgb(readToken('--bg', '#0a0e18'))
      gl.clearColor(bg[0], bg[1], bg[2], 1)
      gl.clear(gl.COLOR_BUFFER_BIT)
      gl.enable(gl.BLEND)

      // Grid — normal alpha blend, faint.
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA)
      gl.useProgram(progs.grid)
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.grid)
      gl.enableVertexAttribArray(0)
      gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)
      gl.uniform3fv(gl.getUniformLocation(progs.grid, 'u_col'), hexToRgb(readToken('--axis', '#2a3550')))
      gl.uniform1f(gl.getUniformLocation(progs.grid, 'u_alpha'), 0.22)
      gl.drawArrays(gl.LINES, 0, grid.length / 2)

      // Arcs — additive.
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE)
      gl.useProgram(progs.line)
      const arcCol = hexToRgb(readToken('--accent', '#22d3ee'))
      gl.uniform3fv(gl.getUniformLocation(progs.line, 'u_col'), arcCol)
      st.arcs = st.arcs.filter((a) => now - a.born < 2.2)
      for (const a of st.arcs) {
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.line)
        gl.bufferData(gl.ARRAY_BUFFER, a.data, gl.DYNAMIC_DRAW)
        gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 12, 0)
        gl.enableVertexAttribArray(1); gl.vertexAttribPointer(1, 1, gl.FLOAT, false, 12, 8)
        gl.uniform1f(gl.getUniformLocation(progs.line, 'u_head'), ((now - a.born) / 2.2) % 1)
        gl.drawArrays(gl.LINE_STRIP, 0, a.data.length / 3)
      }

      // Points — additive glow (the GPU-rendered heat).
      const pts = [...st.points.values()]
      if (pts.length) {
        const ll = new Float32Array(pts.length * 2)
        const mag = new Float32Array(pts.length)
        const col = new Float32Array(pts.length * 3)
        pts.forEach((p, i) => {
          ll[i * 2] = p.lat; ll[i * 2 + 1] = p.lon; mag[i] = p.mag
          col[i * 3] = p.col[0]; col[i * 3 + 1] = p.col[1]; col[i * 3 + 2] = p.col[2]
        })
        gl.useProgram(progs.point)
        gl.uniform1f(gl.getUniformLocation(progs.point, 'u_size'), 10 * (Math.min(window.devicePixelRatio || 1, 2)))
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.point); gl.bufferData(gl.ARRAY_BUFFER, ll, gl.DYNAMIC_DRAW)
        gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.pmag); gl.bufferData(gl.ARRAY_BUFFER, mag, gl.DYNAMIC_DRAW)
        gl.enableVertexAttribArray(1); gl.vertexAttribPointer(1, 1, gl.FLOAT, false, 0, 0)
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.pcol); gl.bufferData(gl.ARRAY_BUFFER, col, gl.DYNAMIC_DRAW)
        gl.enableVertexAttribArray(2); gl.vertexAttribPointer(2, 3, gl.FLOAT, false, 0, 0)
        gl.drawArrays(gl.POINTS, 0, pts.length)
      }

      raf = requestAnimationFrame(render)
    }
    raf = requestAnimationFrame(render)
    return () => { cancelAnimationFrame(raf) }
  }, [])

  // --- data poll ---
  useEffect(() => {
    let alive = true
    const series = [1, 2, 3, 4, 5, 6, 7, 8].map((i) => hexToRgb(readToken(`--series-${i}`, '#4da3ff')))
    const colorFor = (proto) => {
      let h = 0
      for (const c of proto || 'x') h = (h * 31 + c.charCodeAt(0)) & 0xffff
      return series[h % series.length]
    }
    const poll = async () => {
      try {
        const rows = await fetch('/api/views/geopairs?limit=150').then((r) => r.json())
        if (!alive || !Array.isArray(rows)) return
        const st = stateRef.current
        const now = performance.now() / 1000
        let maxB = 1
        for (const r of rows) maxB = Math.max(maxB, r.bytes || 0)
        for (const r of rows) {
          if (r.lat === 0 && r.lon === 0) continue
          const key = `${r.lat.toFixed(2)},${r.lon.toFixed(2)}`
          const mag = Math.min(1, Math.log1p(r.bytes || 0) / Math.log1p(maxB))
          const existing = st.points.get(key)
          st.points.set(key, { lat: r.lat, lon: r.lon, mag: Math.max(mag, existing?.mag || 0), col: colorFor(r.proto) })
          // Fire an arc for connections we have not drawn before.
          if (!existing) {
            st.arcs.push({ born: now, data: new Float32Array(arc2d(ANCHOR.lat, ANCHOR.lon, r.lat, r.lon)) })
            if (st.arcs.length > 60) st.arcs.shift()
          }
        }
        // Cap the point set so an all-day session does not grow unbounded.
        if (st.points.size > 400) {
          const keys = [...st.points.keys()].slice(0, st.points.size - 400)
          keys.forEach((k) => st.points.delete(k))
        }
        setCount(st.points.size)
      } catch {
        /* transient; the next tick retries */
      }
    }
    poll()
    const id = setInterval(poll, 4000)
    return () => { alive = false; clearInterval(id) }
  }, [])

  if (err) {
    return (
      <section className="card worldmap-card">
        <div className="card-title">{t('map.title')}</div>
        <div className="worldmap-fallback">{t('map.noWebgl')}</div>
      </section>
    )
  }

  return (
    <section className="card worldmap-card">
      <div className="card-title">
        {t('map.title')}
        <span className="worldmap-count">{t('map.destinations', { count })}</span>
      </div>
      <div className="worldmap-wrap">
        <canvas ref={canvasRef} className="worldmap-canvas" />
        <div className="worldmap-note">{t('map.anchorNote')}</div>
      </div>
    </section>
  )
}
