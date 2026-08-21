import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from './api'
import { useTheme, useFont, useSize } from './theme'
import Header from './components/Header'
import Analysis from './components/Analysis'
import FilterPanel from './components/FilterPanel'
import Overview from './components/Overview'
import Mitm from './components/Mitm'
import { DevicesView, ConnectionsView, IPView, ProtocolView, DNSView, AlertsView } from './components/Views'
import ErrorBoundary from './components/ErrorBoundary'

// Views that consume the shared filter (F30). The overview and the alert list
// deliberately do not: a filtered overview would answer a different question
// than "how is the house doing right now".
const FILTERED = new Set(['connections', 'byIp', 'byProtocol'])

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

  // Data source (live vs simulated) is decided at startup and does not change,
  // so fetch it once (F43).
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
        // Fresh = accepted in the last 90s (imported_at is wall-clock import
        // time, not the file's own packet timestamps — a historical capture
        // can be months old and still count as "just imported").
        const fresh = (rows || []).find((b) => {
          if (!b.imported_at) return false
          return Date.now() - new Date(b.imported_at).getTime() < 90_000
        })
        if (fresh && autoScopedRef.current !== fresh.iface) {
          autoScopedRef.current = fresh.iface
          setImportScope(fresh.iface)
        }
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
          {view === 'analysis' && <Analysis />}
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
