import { useTranslation } from 'react-i18next'
import { formatBytes } from '../api'
import { BarRows, Donut } from './Charts'
import { SeverityTag } from './Tables'
import TrafficTrendChart from './TrafficTrendChart'
import WorldMap from './WorldMap'
import InterfaceInfo from './InterfaceInfo'

// StatTile is a hero number, not a chart: a single value with a label reads
// faster than any plot of one number could.
function StatTile({ label, value, sub, tone }) {
  return (
    <div className={`tile ${tone ? `tone-${tone}` : ''}`}>
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  )
}

export default function Overview({
  summary, events, topCountries, protocols, devices,
  imports, importScope, onScopeChange,
}) {
  const { t } = useTranslation()
  const { t: td } = useTranslation('device')
  const { t: ta } = useTranslation('alert')

  if (!summary) return <div className="empty"><div className="empty-title">{t('table.loading')}</div></div>

  const highCount = summary.severity_count?.high || 0
  const catRows = Object.entries(summary.category_count || {})
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)

  const protoRows = (protocols || [])
    .slice(0, 6)
    .map((p) => ({ key: p.protocol, value: p.bytes }))

  const deviceName = (mac) => devices?.find((d) => d.mac === mac)?.hostname || mac

  return (
    <div className="view">
      <div className="tiles">
        <StatTile
          label={t('summary.devices')}
          value={summary.device_count}
          sub={summary.new_devices > 0 ? `${summary.new_devices} ${t('summary.newDevices')}` : null}
          tone={summary.new_devices > 0 ? 'warning' : null}
        />
        <StatTile
          label={t('summary.connections')}
          value={summary.connection_count}
          sub={`${summary.internal_flows} ${t('summary.internalFlows')}`}
        />
        <StatTile label={t('summary.traffic')} value={formatBytes(summary.total_bytes)} />
        <StatTile
          label={t('summary.alerts')}
          value={summary.event_count}
          sub={highCount > 0 ? `${highCount} ${t('summary.highSeverity')}` : null}
          tone={highCount > 0 ? 'danger' : null}
        />
      </div>

      <InterfaceInfo />

      <div className="card-row">
        <section className="card">
          <h2>{t('summary.byCategory')}</h2>
          <BarRows
            rows={catRows}
            labelFor={(k) => td(`category.${k}`, { defaultValue: k })}
            valueFormat={(v) => String(v)}
          />
        </section>

        <section className="card">
          <h2>{t('summary.protocolShare')}</h2>
          <Donut rows={protoRows} />
        </section>

        <section className="card">
          <h2>{t('summary.geoDistribution')}</h2>
          <BarRows rows={(topCountries || []).map((r) => ({ key: r.key, value: r.bytes }))} />
        </section>
      </div>

      <section className="card wide">
        <h2>{t('summary.trend')}</h2>
        <TrafficTrendChart />
      </section>

      {imports && imports.length > 0 && (
        <div className="import-scope-bar">
          <span className="dim">{t('map.importedFiles')}:</span>
          <select
            value={importScope || ''}
            onChange={(e) => onScopeChange(e.target.value || null)}
          >
            <option value="">{t('map.scopeLive')}</option>
            {imports.map((b) => (
              <option key={b.iface} value={b.iface}>
                {b.iface} · {b.count}
              </option>
            ))}
          </select>
          {importScope && (
            <button className="btn ghost tiny" onClick={() => onScopeChange(null)}>
              {t('map.scopeClear')}
            </button>
          )}
        </div>
      )}

      <WorldMap iface={importScope} />

      <section className="card wide">
        <h2>{t('nav.alerts')}</h2>
        <ul className="timeline">
          {(events || []).slice(0, 8).map((e) => (
            <li key={e.id}>
              <SeverityTag severity={e.severity} />
              <span className="tl-type">
                {ta(`eventType.${e.event_type}`, { defaultValue: e.event_type })}
              </span>
              <span className="tl-device">{deviceName(e.mac)}</span>
              <span className="tl-score">{e.risk_score}</span>
            </li>
          ))}
          {(!events || events.length === 0) && (
            <li className="dim">{t('table.empty')}</li>
          )}
        </ul>
      </section>
    </div>
  )
}
