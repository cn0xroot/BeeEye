import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, streamPackets } from './api'
import Toolbar from './components/Toolbar'
import TrafficField from './components/TrafficField'
import PacketList from './components/PacketList'
import FieldTree from './components/FieldTree'
import HexDump from './components/HexDump'
import Plaintext from './components/Plaintext'
import EndpointBar from './components/EndpointBar'
import StatusBar from './components/StatusBar'
import ErrorBoundary from './components/ErrorBoundary'
import { useAppearance, useFont, useSize } from './appearance'

// How many rows the list keeps. The server retains far more; this is purely
// what the DOM holds, and it is the number that decides whether scrolling
// stays smooth on a modest machine.
const MAX_ROWS = 3000

// While auto-scroll is off the window is allowed to grow to this instead.
// Dropping rows off the head moves every row still on screen upward, which is
// what made a paused list drift under the reader on every flush; not dropping
// them is the only way the history stays still. The ceiling is what keeps that
// from being an unbounded buffer if someone leaves the list paused all day.
const MAX_ROWS_PAUSED = 12000

// How often buffered packets are applied to the table (ms). Not per frame:
// re-rendering thousands of rows at 60 Hz is what made the UI lag.
const FLUSH_MS = 300

// How many packet details to keep cached in the browser. The raw bytes and the
// field tree live only in the server's capture ring, which keeps advancing, so
// a packet you looked at a minute ago can be evicted there. Caching the details
// we have already fetched means clicking back to such a packet still works —
// and, crucially, that packets you inspect while the list is paused stay
// inspectable even as the server ring moves past them.
const DETAIL_CACHE_MAX = 1500

export default function App() {
  const { t } = useTranslation()
  const [appearance, setAppearance, resolvedAppearance] = useAppearance()
  const [font, setFont] = useFont()
  const [size, setSize] = useSize()
  const [status, setStatus] = useState(null)
  const [interfaces, setInterfaces] = useState([])
  const [packets, setPackets] = useState([])
  const [selected, setSelected] = useState(null)
  // Packets captured while auto-scroll is off, held aside so the view stays
  // still for inspection; surfaced as a count on the toggle.
  const [held, setHeld] = useState(0)
  const [decryptStatus, setDecryptStatus] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailError, setDetailError] = useState(null)
  const [hoverField, setHoverField] = useState(null)
  const [selectedField, setSelectedField] = useState(null)
  // Persisted: a preference that resets on every reload is not a preference.
  const [autoScroll, setAutoScrollState] = useState(() => {
    try {
      return localStorage.getItem('BeeEye.autoscroll') !== '0'
    } catch {
      return true
    }
  })
  // Turning auto-scroll back on applies everything buffered while paused, in
  // one update, and returns to the live tail. Defined before setAutoScroll
  // because that callback lists it as a dependency.
  const resumeTail = useCallback(() => {
    const buf = pending.current
    pending.current = []
    setHeld(0)
    if (buf.length) {
      setPackets((prev) => {
        const next = prev.length ? prev.concat(buf) : buf
        return next.length > MAX_ROWS ? next.slice(next.length - MAX_ROWS) : next
      })
    }
  }, [])

  const setAutoScroll = useCallback((v) => {
    setAutoScrollState(v)
    if (v) resumeTail()
    try {
      localStorage.setItem('BeeEye.autoscroll', v ? '1' : '0')
    } catch {
      /* private mode: applies for this session only */
    }
  }, [resumeTail])

  const pending = useRef([])
  // no → fetched detail. A Map so insertion order gives a cheap LRU trim.
  const detailCache = useRef(new Map())
  // The flush loop is installed once and must not be torn down and rebuilt
  // every time the toggle flips, so it reads the current mode through a ref.
  const autoScrollRef = useRef(autoScroll)
  useEffect(() => { autoScrollRef.current = autoScroll }, [autoScroll])

  useEffect(() => {
    api.interfaces().then(setInterfaces).catch(() => setInterfaces([]))
    api.status().then(setStatus).catch(() => {})
    api.packets(MAX_ROWS).then(setPackets).catch(() => {})
  }, [])

  // Poll status for the counters. The SSE stream also pushes status, but only
  // on its keepalive, and the status bar should not sit stale for 15s.
  useEffect(() => {
    const id = setInterval(() => {
      api.status().then(setStatus).catch(() => {})
    }, 1000)
    api.decryptStatus().then(setDecryptStatus).catch(() => setDecryptStatus(null))
    return () => clearInterval(id)
  }, [])

  // Incoming packets are buffered and applied to React state at a fixed, human
  // cadence rather than once per animation frame. Re-rendering a 3000-row table
  // 60 times a second pins the main thread — that was the source of the "the UI
  // is unusably laggy" and "rows flicker past too fast to click" reports.
  // FLUSH_MS = 300 cuts that to ~3 Hz, which reads as live but leaves the
  // browser time to actually paint and to handle a click.
  useEffect(() => {
    let timer = 0
    const flush = () => {
      const buf = pending.current
      if (buf.length) {
        if (autoScrollRef.current) {
          // Live tail: apply the buffer and keep the newest MAX_ROWS.
          pending.current = []
          setHeld(0)
          setPackets((prev) => {
            const next = prev.length ? prev.concat(buf) : buf
            return next.length > MAX_ROWS ? next.slice(next.length - MAX_ROWS) : next
          })
        } else {
          // Paused for inspection: freeze the visible list and hold new packets
          // aside so nothing moves under the reader. The held buffer is capped
          // so a long pause cannot grow it without bound; the oldest hidden
          // packets are dropped first, exactly as the live ring would drop them.
          if (buf.length > MAX_ROWS_PAUSED) {
            pending.current = buf.slice(buf.length - MAX_ROWS_PAUSED)
          }
          setHeld(pending.current.length)
        }
      }
      timer = setTimeout(flush, FLUSH_MS)
    }
    timer = setTimeout(flush, FLUSH_MS)

    const close = streamPackets({
      onPackets: (batch) => pending.current.push(...batch),
      onStatus: setStatus,
    })
    return () => {
      clearTimeout(timer)
      close()
    }
  }, [])


  useEffect(() => {
    if (selected == null) {
      setDetail(null)
      setDetailError(null)
      return
    }
    setSelectedField(null)
    setHoverField(null)

    // Serve a previously fetched detail from the cache. This is what makes a
    // packet you have already opened stay openable after the server has
    // evicted its bytes, and makes re-selection instant.
    const cached = detailCache.current.get(selected)
    if (cached) {
      // Refresh LRU recency.
      detailCache.current.delete(selected)
      detailCache.current.set(selected, cached)
      setDetail(cached)
      setDetailError(null)
      return
    }

    let alive = true
    setDetailError(null)
    api
      .packet(selected)
      .then((d) => {
        detailCache.current.set(selected, d)
        // Trim oldest entries past the cap.
        while (detailCache.current.size > DETAIL_CACHE_MAX) {
          detailCache.current.delete(detailCache.current.keys().next().value)
        }
        if (alive) setDetail(d)
      })
      .catch((e) => alive && setDetailError(e.message))
    return () => {
      alive = false
    }
  }, [selected])

  // Replacing the packet set after a capture or filter change, in one place so
  // every caller resets the same state.
  const reload = useCallback((newStatus) => {
    setStatus(newStatus)
    setSelected(null)
    setDetail(null)
    pending.current = []
    setHeld(0)
    // A new capture restarts packet numbering, so cached details for the old
    // numbers would be wrong. A filter change keeps numbering, but clearing is
    // cheap and the cache refills as you click.
    detailCache.current.clear()
    api.packets(MAX_ROWS).then(setPackets).catch(() => {})
  }, [])

  const onStarted = useCallback((s) => { setPackets([]); reload(s) }, [reload])

  const applyFieldFilter = useCallback(async (expr) => {
    try {
      reload(await api.setFilter(expr))
    } catch {
      /* the toolbar surfaces filter errors; a click-to-filter that fails is
         not worth a second error channel */
    }
  }, [reload])

  const highlight = hoverField || selectedField
  const hexBytes = useMemo(() => detail?.hex || null, [detail])

  return (
    <div className="app">
      <Toolbar
        status={status}
        interfaces={interfaces}
        onStarted={onStarted}
        onStopped={setStatus}
        onFilterApplied={reload}
        resolvedAppearance={resolvedAppearance}
        onAppearance={setAppearance}
        appearance={appearance}
        font={font}
        onFont={setFont}
        size={size}
        onSize={setSize}
      />

      <TrafficField running={!!status?.running} />

      <main className="panes">
        <PacketList
          packets={packets}
          selected={selected}
          onSelect={setSelected}
          autoScroll={autoScroll}
          onAutoScroll={setAutoScroll}
          held={held}
          filter={status?.filter || ''}
          onClearFilter={() => api.setFilter('').then(reload).catch(() => {})}
        />

        <div className="detail-region">
          {detail && <EndpointBar detail={detail} />}
          <div className="lower">
          {detailError ? (
            <section className="pane">
              <div className="empty">
                <div className="empty-title">{t('errors.detailGone')}</div>
              </div>
            </section>
          ) : (
            <ErrorBoundary label="Packet detail">
              <FieldTree
                detail={detail}
                onHover={setHoverField}
                selectedField={selectedField}
                onSelectField={setSelectedField}
                onFilterField={applyFieldFilter}
              />
            </ErrorBoundary>
          )}
          <ErrorBoundary label="Bytes">
            <HexDump bytes={hexBytes} highlight={highlight} layers={detail?.layers} />
          </ErrorBoundary>
          <ErrorBoundary label="Plaintext">
            <Plaintext
              pid={detail?.summary?.process?.pid || 0}
              comm={detail?.summary?.process?.comm || ''}
              decryptRunning={decryptStatus?.running}
            />
          </ErrorBoundary>
          </div>
        </div>
      </main>

      <StatusBar status={status} displayed={packets.length} />
    </div>
  )
}
