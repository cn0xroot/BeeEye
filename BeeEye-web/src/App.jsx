import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from './api'
import { useTheme, useFont, useSize } from './theme'
import Header from './components/Header'
import Analysis from './components/Analysis'
import FilterPanel from './components/FilterPanel'
import Overview from './components/Overview'
import Mitm from './components/Mitm'
import { DevicesView, ConnectionsView, IPView, ProtocolView, DNSView, AlertsView } from './components/Views'

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
  const [series, setSeries] = useState(null)
  const [countries, setCountries] = useState([])
  const [source, setSource] = useState(null)

  const loadCore = useCallback(async () => {
    try {
      const [s, d, e, c] = await Promise.all([
        api.summary(), api.devices(), api.events(200), api.config(),
      ])
      setSummary(s)
      setDevices(d || [])
      setEvents(e || [])
      setConfig(c)
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => { loadCore() }, [loadCore])

  // Data source (live vs simulated) is decided at startup and does not change,
  // so fetch it once (F43).
  useEffect(() => { api.source().then(setSource).catch(() => setSource(null)) }, [])

  // Overview extras. Kept separate from the core load so a slow aggregate does
  // not hold up the device list.
  useEffect(() => {
    if (view !== 'overview') return
    api.timeseries({}, 900, 'category').then(setSeries).catch(() => setSeries(null))
    api.topN('country', 8).then((r) => setCountries(r.rows || [])).catch(() => setCountries([]))
    api.protocolView().then(setProtoRows).catch(() => setProtoRows([]))
  }, [view])

  useEffect(() => {
    if (view === 'connections') api.connections(filter, 1000).then(setConnections).catch(() => setConnections([]))
    if (view === 'byIp') api.ipView().then(setIpRows).catch(() => setIpRows([]))
    if (view === 'byProtocol') api.protocolView().then(setProtoRows).catch(() => setProtoRows([]))
    if (view === 'dns') api.dns('', 1000).then(setDnsRows).catch(() => setDnsRows([]))
  }, [view, filter])

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
        {view === 'overview' && (
          <Overview
            summary={summary}
            series={series}
            events={events}
            topCountries={countries}
            protocols={protoRows}
            devices={devices}
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
      </main>
    </div>
  )
}
