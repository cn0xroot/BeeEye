import { useTranslation } from 'react-i18next'
import { formatBytes } from '../api'

// StatusBar carries the honesty requirement (F43): whichever capture source is
// actually in effect is named here. There is no simulated source to fall back
// to — real_capture only ever reads false in the idle state, before Start has
// ever succeeded — but the warning is kept as a guard rather than assumed
// away, so a future regression here would be visible rather than silent.
export default function StatusBar({ status }) {
  const { t } = useTranslation()
  if (!status) return null

  const nonLive = status.running && !status.real_capture

  return (
    <footer className={`statusbar ${nonLive ? 'non-live' : ''}`}>
      <span className={`dot ${status.running ? 'live' : 'idle'}`} aria-hidden="true" />
      <span className="st-primary">
        {status.running ? t('status.capturing') : t('status.idle')}
        {status.iface ? ` · ${status.iface}` : ''}
      </span>

      {nonLive && (
        <span className="st-warn" title={t('status.nonLiveHelp', { reason: status.fallback_reason || '—' })}>
          ⚠ {t('status.nonLive')}
        </span>
      )}

      <span className="st-sep" />
      <span>{t('status.source')}: <b>{status.source || '—'}</b></span>
      <span>{t('status.captured')}: <b>{status.captured ?? 0}</b></span>
      {/* Server-side count of ring-buffer packets matching the current
          filter — not the client's local packets.length, which is capped at
          MAX_ROWS/MAX_ROWS_PAUSED and so understates (or, while paused with
          a big backlog, overstates) what the server actually has. */}
      <span>{t('status.displayed')}: <b>{status.displayed ?? 0}</b></span>
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
