import { useTranslation } from 'react-i18next'
import { api } from '../api'

const RANGES = [
  ['1h', 3600],
  ['6h', 21600],
  ['24h', 86400],
  ['7d', 604800],
  ['all', 0],
]

// FilterPanel is the single filter surface for the whole app (F30). Every view
// reads the same filter object, so switching between by-device, by-IP and
// by-protocol keeps the question you were asking.
export default function FilterPanel({ filter, onChange, devices, protocols }) {
  const { t } = useTranslation('common')

  const set = (patch) => onChange({ ...filter, ...patch })

  const setRange = (seconds) => {
    if (!seconds) return set({ since: '', until: '' })
    set({ since: Math.floor(Date.now() / 1000) - seconds, until: '' })
  }

  const activeRange = (() => {
    if (!filter.since) return 'all'
    const age = Math.floor(Date.now() / 1000) - Number(filter.since)
    const hit = RANGES.find(([, s]) => s && Math.abs(age - s) < 120)
    return hit ? hit[0] : ''
  })()

  return (
    <section className="filters" aria-label={t('filters.title')}>
      <div className="filter-row">
        <label className="control">
          <span className="control-label">{t('filters.device')}</span>
          <select
            multiple
            size="1"
            value={filter.macs || []}
            onChange={(e) =>
              set({ macs: Array.from(e.target.selectedOptions).map((o) => o.value) })
            }
          >
            {devices.map((d) => (
              <option key={d.mac} value={d.mac}>
                {d.hostname || d.mac}
              </option>
            ))}
          </select>
        </label>

        <label className="control">
          <span className="control-label">{t('filters.ipOrDomain')}</span>
          <input
            value={filter.ip || ''}
            onChange={(e) => set({ ip: e.target.value })}
            placeholder="10.0.0.0/8, hikvision…"
            spellCheck="false"
          />
        </label>

        <label className="control">
          <span className="control-label">{t('filters.protocol')}</span>
          <select
            value={(filter.protos && filter.protos[0]) || ''}
            onChange={(e) => set({ protos: e.target.value ? [e.target.value] : [] })}
          >
            <option value="">{t('filters.all')}</option>
            {protocols.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>

        <label className="control narrow">
          <span className="control-label">{t('filters.portRange')}</span>
          <span className="port-range">
            <input
              type="number"
              min="0"
              max="65535"
              value={filter.portMin || ''}
              onChange={(e) => set({ portMin: e.target.value })}
              placeholder="0"
            />
            <span>–</span>
            <input
              type="number"
              min="0"
              max="65535"
              value={filter.portMax || ''}
              onChange={(e) => set({ portMax: e.target.value })}
              placeholder="65535"
            />
          </span>
        </label>
      </div>

      <div className="filter-row">
        <div className="control">
          <span className="control-label">{t('filters.timeRange')}</span>
          <div className="chip-group">
            {RANGES.map(([key, seconds]) => (
              <button
                key={key}
                className={activeRange === key ? 'chip active' : 'chip'}
                onClick={() => setRange(seconds)}
              >
                {t(`filters.ranges.${key}`)}
              </button>
            ))}
          </div>
        </div>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={!!filter.internalOnly}
            onChange={(e) => set({ internalOnly: e.target.checked })}
          />
          <span>{t('filters.internalOnly')}</span>
        </label>

        <div className="spacer" />

        <span className="control-label">{t('filters.export')}</span>
        <a className="btn ghost" href={api.exportURL(filter, 'csv')} download>
          {t('filters.exportCsv')}
        </a>
        <a className="btn ghost" href={api.exportURL(filter, 'json')} download>
          {t('filters.exportJson')}
        </a>
        <button className="btn ghost" onClick={() => onChange({})}>
          {t('filters.reset')}
        </button>
      </div>
    </section>
  )
}
