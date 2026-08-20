import { useTranslation } from 'react-i18next'
import { formatBytes } from '../api'

// StatusBar carries the honesty requirement (F43): whichever capture source is
// actually in effect is named here, and a simulated source is called out
// loudly rather than being allowed to pass for live traffic.
export default function StatusBar({ status, displayed }) {
  const { t } = useTranslation()
  if (!status) return null

  const simulated = status.running && !status.real_capture

  return (
    <footer className={`statusbar ${simulated ? 'simulated' : ''}`}>
      <span className={`dot ${status.running ? 'live' : 'idle'}`} aria-hidden="true" />
      <span className="st-primary">
        {status.running ? t('status.capturing') : t('status.idle')}
        {status.iface ? ` · ${status.iface}` : ''}
      </span>

      {simulated && (
        <span className="st-warn" title={t('status.simulatedHelp', { reason: status.fallback_reason || '—' })}>
          ⚠ {t('status.simulated')}
        </span>
      )}

      <span className="st-sep" />
      <span>{t('status.source')}: <b>{status.source || '—'}</b></span>
      <span>{t('status.captured')}: <b>{status.captured ?? 0}</b></span>
      <span>{t('status.displayed')}: <b>{displayed}</b></span>
      <span>{t('status.bytes')}: <b>{formatBytes(status.bytes || 0)}</b></span>
      {status.kernel_drops > 0 && (
        <span className="st-drop">{t('status.dropped')}: <b>{status.kernel_drops}</b></span>
      )}
      {status.evicted > 0 && (
        <span className="st-dim">{t('status.evicted')}: <b>{status.evicted}</b></span>
      )}
      <span className="st-dim">
        {t('status.buffered')}: <b>{status.buffered ?? 0}</b>/{status.ring_size ?? 0}
      </span>
    </footer>
  )
}
