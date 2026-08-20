import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api, formatBytes } from '../api'
import { Table, SeverityTag, CategoryTag, GeoCell, Bytes, When } from './Tables'
import { BarRows } from './Charts'

/* ------------------------------------------------------------------ devices */

export function DevicesView({ devices, onChanged }) {
  const { t } = useTranslation()
  const { t: td } = useTranslation('device')

  const columns = [
    { key: 'name', label: td('columns.hostname') },
    { key: 'mac', label: td('columns.mac') },
    { key: 'ip', label: td('columns.ip') },
    { key: 'vendor', label: td('columns.vendor') },
    { key: 'category', label: td('columns.category') },
    { key: 'access', label: td('columns.accessType') },
    { key: 'iface', label: td('columns.iface') },
    { key: 'lastSeen', label: td('columns.lastSeen') },
    { key: 'status', label: td('columns.status') },
  ]

  return (
    <div className="view">
      <section className="card wide">
        <h2>{t('nav.devices')}</h2>
        <Table
          columns={columns}
          rows={devices}
          keyOf={(d) => d.mac}
          renderRow={(d, key) => (
            <tr key={key} className={d.is_new ? 'row-new' : ''}>
              <td>
                <b>{d.hostname || '—'}</b>
                {d.model_guess && <div className="dim small">{d.model_guess}</div>}
              </td>
              <td className="num">{d.mac}</td>
              <td className="num">{d.ip}</td>
              <td>{d.vendor || <span className="dim">{t('common.unknown')}</span>}</td>
              <td><CategoryTag category={d.category} /></td>
              <td>{d.access_type ? td(`access.${d.access_type}`) : '—'}</td>
              <td className="num">{d.iface}</td>
              <td><When value={d.last_seen} /></td>
              <td>
                {d.is_new ? (
                  <button
                    className="btn tiny warning"
                    title={td('isNewHelp')}
                    onClick={() => api.ackDevice(d.mac).then(onChanged)}
                  >
                    {td('isNew')} — {t('common.acknowledge')}
                  </button>
                ) : (
                  <span className="dim">{t('common.acknowledged')}</span>
                )}
              </td>
            </tr>
          )}
        />
      </section>
    </div>
  )
}

/* -------------------------------------------------------------- connections */

export function ConnectionsView({ connections }) {
  const { t } = useTranslation()
  const columns = [
    { key: 'ts', label: t('nav.connections') },
    { key: 'mac', label: t('filters.device') },
    { key: 'src', label: 'src' },
    { key: 'dst', label: 'dst' },
    { key: 'domain', label: t('filters.ipOrDomain') },
    { key: 'proto', label: t('filters.protocol') },
    { key: 'geo', label: t('summary.geoDistribution') },
    { key: 'bytes', label: t('units.bytes') },
  ]

  return (
    <div className="view">
      <section className="card wide">
        <h2>
          {t('nav.connections')} <span className="count">{t('table.rows', { count: connections.length })}</span>
        </h2>
        <Table
          columns={columns}
          rows={connections}
          keyOf={(c) => c.id}
          renderRow={(c, key) => (
            <tr key={key} className={c.internal ? 'row-internal' : ''}>
              <td><When value={c.ts} /></td>
              <td className="num">{c.mac}</td>
              <td className="num">{c.src_ip}:{c.src_port}</td>
              <td className="num">{c.dst_ip}:{c.dst_port}</td>
              <td>
                {c.domain || <span className="dim">{t('common.noDnsRecord')}</span>}
              </td>
              <td>
                <span className="proto">{c.app_protocol}</span>
                <span className="dim small"> / {c.proto}</span>
              </td>
              <td><GeoCell geo={c.geo} /></td>
              <td><Bytes value={c.bytes} /></td>
            </tr>
          )}
        />
      </section>
    </div>
  )
}

/* ------------------------------------------------------------------ by IP */

export function IPView({ rows, devices }) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(null)
  const name = (mac) => devices?.find((d) => d.mac === mac)?.hostname || mac

  const columns = [
    { key: 'ip', label: 'IP' },
    { key: 'domain', label: t('filters.ipOrDomain') },
    { key: 'geo', label: t('summary.geoDistribution') },
    { key: 'devices', label: t('filters.device') },
    { key: 'protocols', label: t('filters.protocol') },
    { key: 'bytes', label: t('units.bytes') },
    { key: 'conns', label: t('units.connections') },
  ]

  return (
    <div className="view">
      <section className="card wide">
        <h2>{t('nav.byIp')}</h2>
        <Table
          columns={columns}
          rows={rows}
          keyOf={(r) => r.ip}
          renderRow={(r, key) => (
            <>
              <tr key={key} onClick={() => setExpanded(expanded === r.ip ? null : r.ip)} className="clickable">
                <td className="num"><b>{r.ip}</b></td>
                <td>{r.domain || <span className="dim">{t('common.noDnsRecord')}</span>}</td>
                <td><GeoCell geo={r.geo} /></td>
                <td>{r.devices?.length || 0}</td>
                <td>{r.protocols?.join(', ')}</td>
                <td><Bytes value={r.bytes} /></td>
                <td className="num">{r.conn_count}</td>
              </tr>
              {expanded === r.ip && (
                <tr key={`${key}-x`} className="expando">
                  <td colSpan={columns.length}>
                    <div className="expando-grid">
                      <div>
                        <h4>{t('filters.device')}</h4>
                        <ul className="plain">
                          {r.devices?.map((m) => <li key={m}>{name(m)} <span className="dim num">{m}</span></li>)}
                        </ul>
                      </div>
                      <div>
                        <h4>{t('filters.portRange')}</h4>
                        <ul className="plain">
                          {Object.entries(r.ports || {}).map(([p, svc]) => (
                            <li key={p}><span className="num">{p}</span> {svc || ''}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </>
          )}
        />
      </section>
    </div>
  )
}

/* ------------------------------------------------------------ by protocol */

export function ProtocolView({ rows }) {
  const { t } = useTranslation()
  const columns = [
    { key: 'proto', label: t('filters.protocol') },
    { key: 'bytes', label: t('units.bytes') },
    { key: 'conns', label: t('units.connections') },
    { key: 'devices', label: t('filters.device') },
    { key: 'ports', label: t('filters.portRange') },
    { key: 'targets', label: t('summary.topTalkers') },
  ]

  return (
    <div className="view">
      <section className="card wide">
        <h2>{t('nav.byProtocol')}</h2>
        <BarRows rows={(rows || []).map((r) => ({ key: r.protocol, value: r.bytes }))} />
      </section>
      <section className="card wide">
        <Table
          columns={columns}
          rows={rows}
          keyOf={(r) => r.protocol}
          renderRow={(r, key) => (
            <tr key={key}>
              <td><span className="proto">{r.protocol}</span></td>
              <td><Bytes value={r.bytes} /></td>
              <td className="num">{r.conn_count}</td>
              <td className="num">{r.devices?.length || 0}</td>
              <td className="num">{Object.keys(r.ports || {}).join(', ')}</td>
              <td className="dim">{r.top_targets?.join(', ')}</td>
            </tr>
          )}
        />
      </section>
    </div>
  )
}

/* ---------------------------------------------------------------- DNS view */

export function DNSView({ records, devices }) {
  const { t } = useTranslation()
  const name = (mac) => devices?.find((d) => d.mac === mac)?.hostname || mac

  const columns = [
    { key: 'ts', label: t('nav.dns') },
    { key: 'device', label: t('filters.device') },
    { key: 'domain', label: t('filters.ipOrDomain') },
    { key: 'ips', label: 'IP' },
    { key: 'rcode', label: 'RCODE' },
  ]

  return (
    <div className="view">
      <section className="card wide">
        <h2>{t('nav.dns')}</h2>
        <Table
          columns={columns}
          rows={records}
          keyOf={(r) => r.id}
          renderRow={(r, key) => (
            <tr key={key} className={r.rcode === 'NXDOMAIN' ? 'row-warn' : ''}>
              <td><When value={r.ts} /></td>
              <td>{name(r.mac)}</td>
              <td>
                {r.encrypted ? (
                  // DoH/DoT: say plainly that the content is not visible rather
                  // than showing a blank cell that looks like missing data.
                  <span className="dim">🔒 {t('common.encryptedDns')}</span>
                ) : (
                  r.domain
                )}
              </td>
              <td className="num">{r.resolved_ips?.join(', ') || '—'}</td>
              <td className="num">{r.rcode}</td>
            </tr>
          )}
        />
      </section>
    </div>
  )
}

/* ------------------------------------------------------------------ alerts */

export function AlertsView({ events, devices, weights, onChanged }) {
  const { t } = useTranslation()
  const { t: ta } = useTranslation('alert')
  const name = (mac) => devices?.find((d) => d.mac === mac)?.hostname || mac
  const [open, setOpen] = useState(null)

  const columns = [
    { key: 'ts', label: ta('columns.time') },
    { key: 'device', label: ta('columns.device') },
    { key: 'type', label: ta('columns.type') },
    { key: 'sev', label: ta('columns.severity') },
    { key: 'score', label: ta('columns.score') },
    { key: 'signals', label: ta('columns.signals') },
    { key: 'ack', label: '' },
  ]

  return (
    <div className="view">
      {weights && (
        <section className="card wide">
          <h2>{ta('weightsTitle')}</h2>
          <p className="dim">{ta('riskExplain')}</p>
          <BarRows
            rows={Object.entries(weights).map(([key, value]) => ({ key, value })).sort((a, b) => b.value - a.value)}
            labelFor={(k) => ta(`signal.${k}`, { defaultValue: k })}
            valueFormat={(v) => String(v)}
          />
        </section>
      )}

      <section className="card wide">
        <h2>{t('nav.alerts')}</h2>
        <Table
          columns={columns}
          rows={events}
          keyOf={(e) => e.id}
          empty={ta('empty')}
          renderRow={(e, key) => (
            <>
              <tr key={key} className={`sev-row-${e.severity} clickable`} onClick={() => setOpen(open === e.id ? null : e.id)}>
                <td><When value={e.ts} /></td>
                <td>{name(e.mac)}</td>
                <td>{ta(`eventType.${e.event_type}`, { defaultValue: e.event_type })}</td>
                <td><SeverityTag severity={e.severity} /></td>
                <td className="num"><b>{e.risk_score}</b></td>
                <td className="dim small">
                  {e.signals?.map((s) => ta(`signal.${s}`, { defaultValue: s })).join(' · ')}
                </td>
                <td>
                  {!e.acked && (
                    <button
                      className="btn tiny"
                      onClick={(ev) => { ev.stopPropagation(); api.ackEvent(e.id).then(onChanged) }}
                    >
                      {t('common.acknowledge')}
                    </button>
                  )}
                </td>
              </tr>
              {open === e.id && (
                <tr key={`${key}-d`} className="expando">
                  <td colSpan={columns.length}>
                    <pre className="detail-json">{JSON.stringify(e.detail, null, 2)}</pre>
                  </td>
                </tr>
              )}
            </>
          )}
        />
      </section>
    </div>
  )
}
