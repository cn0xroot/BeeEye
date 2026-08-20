import { useTranslation } from 'react-i18next'
import { formatBytes, formatTime } from '../api'

// Shared table chrome, so every view's empty state, header treatment and
// row density match instead of each one inventing its own.
export function Table({ columns, rows, renderRow, keyOf, empty }) {
  const { t } = useTranslation()
  if (!rows?.length) {
    return (
      <div className="empty">
        <div className="empty-title">{empty || t('table.empty')}</div>
        <div className="empty-help">{t('table.emptyHelp')}</div>
      </div>
    )
  }
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>{columns.map((c) => <th key={c.key} className={c.className}>{c.label}</th>)}</tr>
        </thead>
        <tbody>{rows.map((r) => renderRow(r, keyOf(r)))}</tbody>
      </table>
    </div>
  )
}

// SeverityTag pairs colour with a text label and an icon. A severity that is
// only a colour is unusable for a colour-blind reader and unreadable in print.
export function SeverityTag({ severity }) {
  const { t } = useTranslation('alert')
  const glyph = { high: '⛔', medium: '▲', low: '•', info: 'ⓘ' }[severity] || '•'
  return (
    <span className={`sev sev-${severity}`}>
      <span aria-hidden="true">{glyph}</span> {t(`severity.${severity}`)}
    </span>
  )
}

export function CategoryTag({ category }) {
  const { t } = useTranslation('device')
  return <span className={`cat cat-${category}`}>{t(`category.${category}`)}</span>
}

export function GeoCell({ geo }) {
  const { t } = useTranslation()
  if (!geo) return <span className="dim">—</span>
  if (geo.local) return <span className="dim">{t('common.local')}</span>
  if (!geo.country || geo.country === '??') return <span className="dim">{t('common.unknown')}</span>
  // Country · Province · City, with the operator/ASN shown beneath when known.
  const place = [geo.region, geo.city].filter(Boolean).join(' · ')
  const isp = geo.isp || (geo.asn ? `AS${geo.asn}` : '')
  return (
    <span className="geo-cell" title={[geo.country, geo.region, geo.city, isp].filter(Boolean).join(' · ')}>
      <b>{geo.country}</b>
      {place ? ` · ${place}` : ''}
      {isp && <span className="geo-isp">{isp}</span>}
    </span>
  )
}

export function Bytes({ value }) {
  return <span className="num">{formatBytes(value)}</span>
}

export function When({ value }) {
  const { i18n } = useTranslation()
  return <span className="dim num">{formatTime(value, i18n.resolvedLanguage)}</span>
}
