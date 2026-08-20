import { useTranslation } from 'react-i18next'

// EndpointBar shows the selected packet's destination identity: its domain
// (from the IP↔name map, F21) and its offline geolocation — country, province,
// city and network operator (F22). It sits above the field tree so the "who is
// this and where" answer is visible without hunting through the tree.
export default function EndpointBar({ detail }) {
  const { t } = useTranslation()
  if (!detail?.summary) return null
  const s = detail.summary
  const g = detail.geo || {}
  const isp = g.isp || (g.asn ? `AS${g.asn}` : '')
  const place = [g.region, g.city].filter(Boolean).join(' · ')

  return (
    <div className="endpoint-bar">
      <div className="ep-col">
        <span className="ep-label">{t('columns.destination')}</span>
        <span className="ep-ip">{s.dst}</span>
        {s.dst_name && <span className="ep-domain">{s.dst_name}</span>}
      </div>
      {!g.local && g.country && g.country !== '??' && (
        <div className="ep-col">
          <span className="ep-label">{t('endpoint.geo')}</span>
          <span className="ep-geo">
            <b>{g.country}</b>
            {place ? ` · ${place}` : ''}
          </span>
          {isp && <span className="ep-isp">{isp}</span>}
        </div>
      )}
      {g.local && (
        <div className="ep-col">
          <span className="ep-label">{t('endpoint.geo')}</span>
          <span className="ep-geo dim">{t('endpoint.local')}</span>
        </div>
      )}
    </div>
  )
}
