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

// buildLandSegments turns a GeoJSON FeatureCollection's polygon rings into
// GL_LINES-ready [lat,lon, lat,lon, …] segment pairs — the exact shape
// buildGraticule already produces, so coastlines draw through the identical
// grid shader with no new machinery. Coordinates come from world.geo.json
// (public/), a low-resolution country-boundary set fetched once and never
// re-requested: it does not change while the tab is open.
function buildLandSegments(geojson) {
  const out = []
  const addRing = (ring) => {
    for (let i = 0; i < ring.length; i++) {
      const [lon0, lat0] = ring[i]
      const [lon1, lat1] = ring[(i + 1) % ring.length]
      out.push(lat0, lon0, lat1, lon1)
    }
  }
  for (const f of geojson.features || []) {
    const g = f.geometry
    if (!g) continue
    if (g.type === 'Polygon') {
      for (const ring of g.coordinates) addRing(ring)
    } else if (g.type === 'MultiPolygon') {
      for (const poly of g.coordinates) for (const ring of poly) addRing(ring)
    }
  }
  return new Float32Array(out)
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
  const W = () => canvas.width, H = () => canvas.height
  const px = (lat, lon) => [((lon + 180) / 360) * W(), ((90 - lat) / 180) * H()]

  // draw is one animation frame; drawFrame is where the actual per-frame
  // guards live (0-sized canvas, degenerate arcs, non-finite point coords —
  // see their own comments). draw wraps it in try/catch as a second line of
  // defense: this loop reschedules itself only from its OWN tail, so any
  // uncaught throw — the specific ones already guarded against, or a case
  // nobody has hit yet — would otherwise silently end the animation forever,
  // leaving whatever was last drawn on screen (a "black screen" bug report
  // traced to exactly that: one bad frame, then nothing, ever again).
  const draw = () => {
    try {
      drawFrame()
    } catch (e) {
      console.error('WorldMap: canvas2d frame failed, skipping it', e)
    }
    raf = requestAnimationFrame(draw)
  }

  const drawFrame = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    const w = canvas.clientWidth * dpr, h = canvas.clientHeight * dpr
    // Before the card has been laid out (first paint, or briefly after an
    // aspect-ratio-driven resize) clientWidth/clientHeight can read 0 — a
    // 0-sized canvas.width/height turns every later coordinate into a
    // divide-by-zero, and createRadialGradient throws on a non-finite value
    // rather than silently drawing nothing. Skipping the frame (not resizing
    // to 0, not drawing) rather than resizing to a 0×0 buffer is what keeps
    // the picture correct once layout does settle.
    if (w <= 0 || h <= 0) {
      return
    }
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h }
    // Same raw epoch (performance.now()/1000, not mount-relative) as a.born
    // below — an arc's age must be measured from that one shared clock,
    // never one offset by however long this render loop had been mounted
    // before the arc was born, or "now - a.born" comes out permanently
    // negative (a fresh mount always starts after any earlier a.born was
    // stamped) and every pulse freezes at its arc's start point forever (an
    // arc's age also never crosses the 2.2s cutoff, so it never expires —
    // "光点不跳动了").
    const now = performance.now() / 1000
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

    // Land outline — drawn over the graticule (more opaque) so the
    // coastlines read as the map's actual subject, not just another grid
    // line. st.land arrives asynchronously (see the land-data effect below);
    // until it does, the grid alone still reads as a map, just a plainer one.
    if (st.land) {
      ctx.strokeStyle = axis; ctx.globalAlpha = 0.6; ctx.lineWidth = 1
      ctx.beginPath()
      for (let i = 0; i < st.land.length; i += 4) {
        const [x0, y0] = px(st.land[i], st.land[i + 1])
        const [x1, y1] = px(st.land[i + 2], st.land[i + 3])
        ctx.moveTo(x0, y0); ctx.lineTo(x1, y1)
      }
      ctx.stroke(); ctx.globalAlpha = 1
    }

    // Arcs.
    ctx.globalCompositeOperation = 'lighter'
    st.arcs = st.arcs.filter((a) => now - a.born < 2.2)
    for (const a of st.arcs) {
      const n = a.data.length / 3
      if (n <= 0) continue // a degenerate (empty) arc has no head point to pulse
      const head = ((now - a.born) / 2.2)
      ctx.strokeStyle = accent; ctx.lineWidth = 1.4
      ctx.beginPath()
      for (let k = 0; k < n; k++) {
        const lat = a.data[k * 3], lon = a.data[k * 3 + 1]
        const [x, y] = px(lat, lon)
        k === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y)
      }
      ctx.globalAlpha = 0.35; ctx.stroke()
      // Travelling pulse.
      const hi = Math.max(0, Math.min(n - 1, Math.floor(head * (n - 1))))
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
      if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(r) || r <= 0) continue
      const col = `rgb(${(p.col[0] * 255) | 0},${(p.col[1] * 255) | 0},${(p.col[2] * 255) | 0})`
      const g = ctx.createRadialGradient(x, y, 0, x, y, r)
      g.addColorStop(0, col); g.addColorStop(0.4, col); g.addColorStop(1, 'transparent')
      ctx.globalAlpha = 0.35 + p.mag * 0.5
      ctx.fillStyle = g
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill()
    }
    ctx.globalAlpha = 1; ctx.globalCompositeOperation = 'source-over'
  }
  raf = requestAnimationFrame(draw)
  return () => cancelAnimationFrame(raf)
}

// The gateway anchor: a schematic origin, not a real location.
const ANCHOR = { lat: 34, lon: 108 }

export default function WorldMap({ iface } = {}) {
  const { t } = useTranslation()
  const canvasRef = useRef(null)
  const glRef = useRef(null)
  const stateRef = useRef({ points: new Map(), arcs: [], land: null })
  const [count, setCount] = useState(0)
  const [err, setErr] = useState(false)
  const [tip, setTip] = useState(null) // { x, y, point } in canvas-local pixels, or null
  // Whether tip came from a click rather than a hover: a click "pins" the
  // panel open (survives the pointer leaving the canvas, e.g. moving to
  // read the IP) until the user clicks again — plain hover keeps the old
  // follow-the-mouse behavior for desktop users who just want a quick peek.
  const [pinned, setPinned] = useState(false)

  // Same clip-space math as VERT_POINT/the Canvas2D fallback, inverted back
  // to pixels for hit-testing — kept in one place so a hover always lands on
  // the dot the eye actually sees, not a slightly-off approximation.
  const toScreen = (lat, lon, w, h) => {
    const [cx, cy] = project(lat, lon)
    return [(cx + 1) / 2 * w, (1 - cy) / 2 * h]
  }

  // Shared by hover and click: finds the destination point nearest the
  // event, in canvas-local pixels, or null if nothing is close enough.
  const hitTest = (e) => {
    const canvas = canvasRef.current
    if (!canvas) return null
    const rect = canvas.getBoundingClientRect()
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const w = canvas.clientWidth, h = canvas.clientHeight
    let best = null, bestD = 16 // px — a generous hit radius, points render small
    for (const p of stateRef.current.points.values()) {
      const [sx, sy] = toScreen(p.lat, p.lon, w, h)
      const d = Math.hypot(sx - mx, sy - my)
      if (d < bestD) { bestD = d; best = p }
    }
    return best ? { x: mx, y: my, point: best } : null
  }

  const handlePointerMove = (e) => {
    if (pinned) return // a click pinned the panel; hovering elsewhere must not steal it
    setTip(hitTest(e))
  }

  const handleClick = (e) => {
    const hit = hitTest(e)
    setTip(hit)
    setPinned(!!hit) // clicking empty space unpins and clears, same as a miss
  }

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
    const bufs = { point: gl.createBuffer(), pmag: gl.createBuffer(), pcol: gl.createBuffer(), line: gl.createBuffer(), grid: gl.createBuffer(), land: gl.createBuffer() }
    const grid = buildGraticule()
    gl.bindBuffer(gl.ARRAY_BUFFER, bufs.grid)
    gl.bufferData(gl.ARRAY_BUFFER, grid, gl.STATIC_DRAW)
    // Coastlines arrive asynchronously (the land-data effect below) and
    // never change afterwards, so upload once — landData !== st.land is
    // only ever true the one time a fresh Float32Array shows up.
    let landData = null, landCount = 0

    let raf = 0

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const w = canvas.clientWidth * dpr, h = canvas.clientHeight * dpr
      if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h }
      gl.viewport(0, 0, canvas.width, canvas.height)
    }

    // render is one frame; renderFrame does the actual GL work. Same
    // try/catch-then-reschedule shape as the Canvas2D fallback's draw/
    // drawFrame split (see its comment) — a WebGL call throwing is rarer
    // than createRadialGradient's non-finite check, but the failure mode is
    // identical (this loop only ever reschedules from its own tail, so one
    // uncaught throw would silently end the animation forever) and costs
    // nothing to guard against here too.
    const render = () => {
      try {
        renderFrame()
      } catch (e) {
        console.error('WorldMap: webgl frame failed, skipping it', e)
      }
      raf = requestAnimationFrame(render)
    }

    const renderFrame = () => {
      resize()
      if (canvas.width <= 0 || canvas.height <= 0) return // not laid out yet
      // Same raw epoch as a.born (see startCanvas2D's drawFrame comment) —
      // mount-relative time here would make every arc's age permanently
      // negative once this effect has been mounted a while before an arc is
      // born, freezing the travelling pulse at each arc's start point.
      const now = performance.now() / 1000
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

      // Land outline — same grid shader (it is just coloured line segments),
      // drawn more opaque than the graticule so the coastlines read as the
      // map's actual subject.
      if (st.land && st.land !== landData) {
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.land)
        gl.bufferData(gl.ARRAY_BUFFER, st.land, gl.STATIC_DRAW)
        landData = st.land
        landCount = st.land.length / 2
      }
      if (landCount) {
        gl.useProgram(progs.grid)
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.land)
        gl.enableVertexAttribArray(0)
        gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0)
        gl.uniform3fv(gl.getUniformLocation(progs.grid, 'u_col'), hexToRgb(readToken('--axis', '#2a3550')))
        gl.uniform1f(gl.getUniformLocation(progs.grid, 'u_alpha'), 0.6)
        gl.drawArrays(gl.LINES, 0, landCount)
      }

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
    }
    raf = requestAnimationFrame(render)
    return () => {
      cancelAnimationFrame(raf)
      // Release the GPU-side objects explicitly rather than leaving them for
      // the garbage collector — some WebView engines (WebKitGTK in
      // particular, which BeeEye-desktop's Tauri window uses on Linux) are
      // known to be unreliable about reclaiming a WebGL context that just
      // goes out of scope, and switching away from this view (e.g. to
      // Alerts) tears this context down on every single visit. Losing the
      // context explicitly is the one step of this that actually matters —
      // it tells the browser this GPU resource is done, on our terms, rather
      // than whenever finalization gets around to it.
      Object.values(progs).forEach((p) => p && gl.deleteProgram(p))
      Object.values(bufs).forEach((b) => b && gl.deleteBuffer(b))
      gl.getExtension('WEBGL_lose_context')?.loseContext()
    }
  }, [])

  // --- land outline (fetched once; coastlines do not move) ---
  useEffect(() => {
    let alive = true
    fetch('/world.geo.json')
      .then((r) => r.json())
      .then((geojson) => {
        if (!alive) return
        stateRef.current.land = buildLandSegments(geojson)
      })
      .catch(() => {
        // The map still works without coastlines — just the graticule and
        // glows, which is what this looked like before this existed.
      })
    return () => { alive = false }
  }, [])

  // --- data poll ---
  useEffect(() => {
    let alive = true
    // Switching scope (live vs. one imported file, see the picker in
    // Overview) starts from a clean map — otherwise an import's handful of
    // points would just blend into whatever the live view had already
    // plotted, which defeats the point of scoping to it at all.
    const st0 = stateRef.current
    st0.points.clear()
    st0.arcs.length = 0
    setCount(0)
    const url = `/api/views/geopairs?limit=150${iface ? `&iface=${encodeURIComponent(iface)}` : ''}`
    const series = [1, 2, 3, 4, 5, 6, 7, 8].map((i) => hexToRgb(readToken(`--series-${i}`, '#4da3ff')))
    const colorFor = (proto) => {
      let h = 0
      for (const c of proto || 'x') h = (h * 31 + c.charCodeAt(0)) & 0xffff
      return series[h % series.length]
    }
    const poll = async () => {
      try {
        const rows = await fetch(url).then((r) => r.json())
        if (!alive || !Array.isArray(rows)) return
        const st = stateRef.current
        const now = performance.now() / 1000
        let maxB = 1
        for (const r of rows) maxB = Math.max(maxB, r.bytes || 0)
        // One arc per destination per poll, not per row: geopairs can list
        // several connections to the same IP in one 4s window, and a map
        // whose fastest-updating field is capped at "150 rows" should not
        // fire dozens of arcs to the same point because of that.
        const pulsedThisPoll = new Set()
        for (const r of rows) {
          if (r.lat === 0 && r.lon === 0) continue
          const key = `${r.lat.toFixed(2)},${r.lon.toFixed(2)}`
          const mag = Math.min(1, Math.log1p(r.bytes || 0) / Math.log1p(maxB))
          const existing = st.points.get(key)
          st.points.set(key, {
            lat: r.lat, lon: r.lon, mag: Math.max(mag, existing?.mag || 0), col: colorFor(r.proto),
            // Carried through for the hover tooltip (see handleMouseMove) —
            // geo detail only, never re-derived here, so it stays exactly
            // as honest as the backend's own geoip.Lookup was (region/city
            // blank rather than guessed when only a Country-tier db is
            // loaded; src fields blank for the ordinary "LAN device talks
            // out" case where the source has no meaningful geo of its own).
            dstIp: r.dst_ip, country: r.country, region: r.region, city: r.city, domain: r.domain,
            srcIp: r.src_ip, srcCountry: r.src_country, srcRegion: r.src_region, srcCity: r.src_city,
            // Network operator (F22's ASN tier) — blank/0 rather than guessed
            // when only a Country-tier or no ASN database is loaded, same
            // honesty policy as the rest of this object.
            isp: r.isp, asn: r.asn,
          })
          // Fire a pulse for every poll that still sees traffic to this
          // destination, not only the first time it is ever seen — a live
          // map should keep animating for as long as data keeps arriving,
          // not go static the moment every destination has been visited once.
          if (!pulsedThisPoll.has(key)) {
            pulsedThisPoll.add(key)
            // Which way the pulse travels follows which way more of the
            // traffic actually went — anchor→destination for an
            // upload-heavy flow, destination→anchor for a download-heavy
            // one — rather than always animating outward regardless of
            // whether this device sent or received the data. Falls back to
            // outward when direction is unknown (older rows / a flow with
            // no local endpoint, tx_bytes and rx_bytes both 0).
            const arcPath = (r.rx_bytes || 0) > (r.tx_bytes || 0)
              ? arc2d(r.lat, r.lon, ANCHOR.lat, ANCHOR.lon)
              : arc2d(ANCHOR.lat, ANCHOR.lon, r.lat, r.lon)
            st.arcs.push({ born: now, data: new Float32Array(arcPath) })
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
  }, [iface])

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
        {iface && <span className="worldmap-scope" title={iface}>📥 {iface}</span>}
        <span className="worldmap-count">{t('map.destinations', { count })}</span>
      </div>
      <div className="worldmap-wrap">
        <canvas
          ref={canvasRef}
          className="worldmap-canvas"
          onMouseMove={handlePointerMove}
          onMouseLeave={() => { if (!pinned) setTip(null) }}
          onClick={handleClick}
        />
        <div className="worldmap-note">{t('map.anchorNote')} · {t('map.tooltipHint')}</div>
        {/* "0 destinations" is frequently the honest, correct answer — a
            scoped-to-import capture whose traffic never left the local
            loopback (GSMTAP/SIM-reader captures, for instance) or a live
            capture polled before any external traffic has happened yet —
            not a broken map. Saying so beats leaving an unexplained blank
            canvas that reads as "this doesn't work" (same principle as
            GeoAccuracyBadge and F43's live/unavailable labeling elsewhere). */}
        {count === 0 && <div className="worldmap-empty">{t('map.empty')}</div>}
        {tip && (
          <div
            className={`worldmap-tooltip${pinned ? ' pinned' : ''}`}
            style={{ left: Math.min(tip.x + 14, (canvasRef.current?.clientWidth || 0) - 210), top: tip.y + 14 }}
          >
            {tip.point.srcCountry && (
              <div className="wt-row">
                <span className="wt-label">{t('map.tooltipSrc')}</span>
                <span>{formatGeo(tip.point.srcCountry, tip.point.srcRegion, tip.point.srcCity)}</span>
              </div>
            )}
            <div className="wt-row">
              <span className="wt-label">{t('map.tooltipDst')}</span>
              <span>{formatGeo(tip.point.country, tip.point.region, tip.point.city)}</span>
            </div>
            {tip.point.domain && <div className="wt-domain">{tip.point.domain}</div>}
            <div className="wt-ip dim">{tip.point.dstIp}</div>
            {tip.point.isp && (
              <div className="wt-row">
                <span className="wt-label">{t('map.tooltipIsp')}</span>
                <span>{tip.point.isp}{tip.point.asn ? ` (AS${tip.point.asn})` : ''}</span>
              </div>
            )}
            <div className="wt-row">
              <span className="wt-label">{t('map.tooltipCoords')}</span>
              <span>{formatCoords(tip.point.lat, tip.point.lon)}</span>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}

// formatGeo joins whichever of country/region/city geoip actually resolved
// — a Country-tier database (the common case) leaves region/city blank, and
// this shows exactly what is known rather than padding with placeholders.
function formatGeo(country, region, city) {
  return [country, region, city].filter(Boolean).join(' · ') || '—'
}

// formatCoords renders the destination's own lat/lon (never the anchor's —
// see ANCHOR's comment) as signed degrees, e.g. "37.75°N, 122.42°W".
function formatCoords(lat, lon) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return '—'
  const ns = lat >= 0 ? 'N' : 'S'
  const ew = lon >= 0 ? 'E' : 'W'
  return `${Math.abs(lat).toFixed(2)}°${ns}, ${Math.abs(lon).toFixed(2)}°${ew}`
}
