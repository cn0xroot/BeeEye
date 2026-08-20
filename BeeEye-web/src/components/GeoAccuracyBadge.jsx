import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'

// GeoAccuracyBadge tells the operator whether locations on screen are precise
// (a real MaxMind City+ASN database is loaded) or a coarse country-level
// stand-in (F22) — so "why does this say Unknown City" has an answer right on
// the page instead of requiring a look at the server log.
export default function GeoAccuracyBadge() {
  const { t } = useTranslation()
  const [st, setSt] = useState(null)
  useEffect(() => { api.geoipStatus().then(setSt).catch(() => setSt(null)) }, [])
  if (!st) return null

  const level = st.accuracy // "city" | "country" | "builtin"
  if (level === 'city') {
    return <span className="geo-acc geo-acc-city" title={t('geoAcc.cityHint')}>{t('geoAcc.city')}</span>
  }
  return (
    <span className={`geo-acc geo-acc-${level}`} title={t('geoAcc.coarseHint')}>
      {t(level === 'country' ? 'geoAcc.country' : 'geoAcc.builtin')}
    </span>
  )
}
