import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from './api'
import { useTheme, useFont, useSize } from './theme'
import Header from './components/Header'
import FilterPanel from './components/FilterPanel'
import Overview from './components/Overview'
import Mitm from './components/Mitm'
import { DevicesView, ConnectionsView, IPView, ProtocolView, DNSView, AlertsView } from './components/Views'
import ErrorBoundary from './components/ErrorBoundary'

// Views that consume the shared filter (F30). The overview and the alert list
// deliberately do not: a filtered overview would answer a different question
// than "how is the house doing right now".
const FILTERED = new Set(['connections', 'byIp', 'byProtocol'])

const SEEN_IMPORTS_KEY = 'beeeye.seenImports'

// localStorage-backed, so "already offered" survives a page reload — see
// seenImportsRef's own comment for why this can't just be an in-memory ref.
// Wrapped in try/catch: private browsing or a storage-blocking policy must
// not break importing, just fall back to "nothing persists, re-offer every
// page load" (matches this feature's pre-existing behavior before it did).
function loadSeenImports() {
  try {
    const raw = localStorage.getItem(SEEN_IMPORTS_KEY)
    if (raw) return new Set(JSON.parse(raw))
  } catch { /* ignore */ }
  return new Set()
}

function saveSeenImports(seen) {
  try { localStorage.setItem(SEEN_IMPORTS_KEY, JSON.stringify([...seen])) } catch { /* ignore */ }
}

// A row only counts as a real "just imported" signal if imported_at is a
// real timestamp — the server only sets it on POST /api/pcap/import within
// its own current process lifetime (see api.go's importedAt map), so a row
// imported before the agent's last restart reports the Go zero time
// instead, which parses to a large negative epoch offset here.
function hasRealImportedAt(b) {
  return b.imported_at ? new Date(b.imported_at).getTime() > 0 : false
}

export default function App() {
  const { t } = useTranslation()
  const [theme, setTheme, resolvedTheme] = useTheme()
  const [font, setFont] = useFont()
  const [size, setSize] = useSize()
  const [view, setView] = useState('overview')
  const [filter, setFilter] = useState({})
  const [error, setError] = useState(null)

  const [summary, setSummary] = useState(null)
  const [devices, setDevices] = useState([])
  const [events, setEvents] = useState([])
  const [config, setConfig] = useState(null)
  const [connections, setConnections] = useState([])
  const [ipRows, setIpRows] = useState([])
  const [protoRows, setProtoRows] = useState([])
  const [dnsRows, setDnsRows] = useState([])
  const [countries, setCountries] = useState([])
  const [source, setSource] = useState(null)
  // Imported capture files (see api.js pcapImports / BeeEye-agent's
  // /api/pcap/imports) — surfaced so the world map can be scoped to one
  // instead of an import's data sitting invisible, crowded out of the
  // recency-ordered live view by whatever traffic keeps arriving. null
  // scope means "live/default", same as before this existed.
  const [imports, setImports] = useState([])
  const [importScope, setImportScope] = useState(null)
  // Which iface we already auto-scoped to, so a "just imported" jump only
  // happens once per import — the user clearing it (back to live) must
  // stick, not get fought by the next poll re-noticing the same import.
  const autoScopedRef = useRef(null)
  // ifaces already offered as an auto-scope target, persisted across page
  // loads/reloads (see loadSeenImports below) — not just "this render", and
  // not bounded by how long ago the import happened. Importing happens from
  // the analyzer, a separate page/port (F42): the user may open the overview
  // tab seconds or many minutes after that POST landed, or may not have had
  // it open at all yet, so there is no wall-clock window that reliably
  // covers "did the user already get offered a jump to this import".
  const seenImportsRef = useRef(null)

  const loadCore = useCallback(async () => {
    try {
      const [s, d, e, c] = await Promise.all([
        api.summary(importScope), api.devices(), api.events(200), api.config(),
      ])
      setSummary(s)
      setDevices(d || [])
      setEvents(e || [])
      setConfig(c)
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }, [importScope])

  // Poll rather than load once: the overview is the "how is the house doing
  // right now" view, and a page that only fetches on mount reads as a
  // history snapshot rather than the live picture the analyzer's own view
  // gives — the summary/device/event counts kept ticking there but froze
  // here the moment the tab was opened.
  useEffect(() => {
    loadCore()
    const t = setInterval(loadCore, 3000)
    return () => clearInterval(t)
  }, [loadCore])

  // Data source (live vs unavailable — there is no simulated state, F43) is
  // decided at startup and does not change, so fetch it once.
  useEffect(() => { api.source().then(setSource).catch(() => setSource(null)) }, [])

  // Overview extras. Kept separate from the core load so a slow aggregate does
  // not hold up the device list. Same reasoning as loadCore above: polled,
  // not fetched once, so the traffic timeline and top-talkers stay current
  // for as long as the overview tab is open.
  useEffect(() => {
    if (view !== 'overview') return
    const loadExtras = () => {
      api.topN('country', 8, importScope).then((r) => setCountries(r.rows || [])).catch(() => setCountries([]))
      api.protocolView(importScope).then(setProtoRows).catch(() => setProtoRows([]))
      api.pcapImports().then((rows) => {
        setImports(rows || [])
        if (seenImportsRef.current === null) seenImportsRef.current = loadSeenImports()
        const seen = seenImportsRef.current
        const candidates = (rows || []).filter((b) => !seen.has(b.iface) && hasRealImportedAt(b))
        if (candidates.length > 0) {
          const target = candidates.reduce((a, b) =>
            new Date(b.imported_at) > new Date(a.imported_at) ? b : a)
          if (autoScopedRef.current !== target.iface) {
            autoScopedRef.current = target.iface
            setImportScope(target.iface)
          }
        }
        // Every iface seen this poll is "offered" from here on, whether or
        // not it won the pick above — otherwise a second, newer import
        // arriving next poll would flip-flop the scope back to a candidate
        // that already lost once.
        const ifaces = rows || []
        ifaces.forEach((b) => seen.add(b.iface))
        saveSeenImports(seen)
      }).catch(() => {})
    }
    loadExtras()
    const t = setInterval(loadExtras, 3000)
    return () => clearInterval(t)
  }, [view, importScope])

  useEffect(() => {
    if (view === 'connections') api.connections(filter, 1000, importScope).then(setConnections).catch(() => setConnections([]))
    if (view === 'byIp') api.ipView(importScope).then(setIpRows).catch(() => setIpRows([]))
    if (view === 'byProtocol') api.protocolView(importScope).then(setProtoRows).catch(() => setProtoRows([]))
    if (view === 'dns') api.dns('', 1000, importScope).then(setDnsRows).catch(() => setDnsRows([]))
  }, [view, filter, importScope])

  const protocols = useMemo(
    () => Array.from(new Set(protoRows.map((p) => p.protocol))).sort(),
    [protoRows],
  )

  const highAlerts = events.filter((e) => e.severity === 'high' && !e.acked).length

  return (
    <div className="app">
      <Header
        view={view}
        onView={setView}
        theme={theme}
        resolvedTheme={resolvedTheme}
        onTheme={setTheme}
        font={font}
        onFont={setFont}
        size={size}
        onSize={setSize}
        alertCount={highAlerts}
        source={source}
      />

      {error && (
        <div className="banner error" role="alert">
          {t('common.error')}: {error}
          <button className="btn tiny" onClick={loadCore}>{t('common.retry')}</button>
        </div>
      )}

      {FILTERED.has(view) && (
        <FilterPanel filter={filter} onChange={setFilter} devices={devices} protocols={protocols} />
      )}

      <main className="content">
        {/* Keyed by view: a crash in one tab must not leave a different tab
            stuck showing that crash's fallback after the user navigates
            away from it — a fresh key mounts a fresh boundary. */}
        <ErrorBoundary key={view} label={t('common.viewCrashed', { defaultValue: 'This view failed to render' })}>
          {view === 'overview' && (
            <Overview
              summary={summary}
              events={events}
              topCountries={countries}
              protocols={protoRows}
              devices={devices}
              imports={imports}
              importScope={importScope}
              onScopeChange={setImportScope}
            />
          )}
          {view === 'devices' && <DevicesView devices={devices} onChanged={loadCore} />}
          {view === 'connections' && <ConnectionsView connections={connections} />}
          {view === 'byIp' && <IPView rows={ipRows} devices={devices} />}
          {view === 'byProtocol' && <ProtocolView rows={protoRows} />}
          {view === 'mitm' && <Mitm />}
          {view === 'dns' && <DNSView records={dnsRows} devices={devices} />}
          {view === 'alerts' && (
            <AlertsView
              events={events}
              devices={devices}
              weights={config?.signal_weights}
              onChanged={loadCore}
            />
          )}
        </ErrorBoundary>
      </main>
    </div>
  )
}
