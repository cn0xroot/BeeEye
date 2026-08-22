import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api'

// TrafficField shows the colour field rendered by the server — on the GPU via
// CUDA when the analyzer was built with that backend, otherwise the identical
// image computed on the CPU.
//
// Frames are fetched as images rather than drawn here on purpose: the whole
// point of the exercise is that the per-pixel colour work happens in the
// renderer, not in JavaScript. The backend in use is labeled, so nobody has to
// guess which one produced what they are looking at.
//
// Height scales with the channel count rather than a flat constant: each row
// is a glow band whose ridge-shading (see software.go's Render) needs a
// handful of pixels top-to-bottom to actually read as a curved band instead
// of a flat stripe. A fixed 168px height was fine back when there were 8
// channels (21px/row); at 12 (RenderChannels grew for SIP/SCTP/GTP/SIM) that
// same 168px squeezes every row down to 14px, which is where the complaint
// that prompted this came from. PX_PER_CHANNEL is picked to keep roughly the
// same per-row legibility the original 8-channel/168px pairing had.
const PX_PER_CHANNEL = 24
const MIN_FRAME_HEIGHT = 168
const MAX_FRAME_HEIGHT = 420
// Assumed channel count before /api/render/info's own answer arrives, so the
// very first frame request (fired before that response lands) still asks
// for a reasonable height instead of falling back to the old cramped one.
const DEFAULT_CHANNEL_COUNT = 12

export default function TrafficField({ running, offline }) {
  const { t } = useTranslation()
  const imgRef = useRef(null)
  const [info, setInfo] = useState(null)
  const [hoverChannel, setHoverChannel] = useState(null)
  const [hasFrame, setHasFrame] = useState(false)
  const [totals, setTotals] = useState(null) // { totals: {channel: bytes}, total_bytes }
  // Tracks the previous render's `running` so a true→false edge (a capture
  // stopping, or — the common case for an offline import — a whole file
  // being replayed and finishing before this component's next chance to
  // notice) can be told apart from "was already stopped".
  const wasRunning = useRef(running)

  useEffect(() => {
    api.renderInfo().then(setInfo).catch(() => setInfo(null))
  }, [])

  const channelCount = info?.channels?.length || DEFAULT_CHANNEL_COUNT
  const frameHeight = Math.min(MAX_FRAME_HEIGHT, Math.max(MIN_FRAME_HEIGHT, channelCount * PX_PER_CHANNEL))

  // Refresh at ~8fps while capturing. A new URL each time defeats the cache;
  // the server also sends no-store, since every frame differs.
  //
  // An offline import replays as fast as the file can be read/dissected —
  // not paced to real time — so `session.consume()` writes every one of its
  // packets into the field's history and then flips `running` back to false
  // again, often within a single status-poll interval of the import
  // starting. From here that can look like `running` going false without
  // ever having been observed true, so gating the fetch on `running` alone
  // left the field showing whatever frame predated the import — the
  // offline file's own protocols never appeared to have been "rendered" at
  // all, even though the server-side history had them the whole time. Firing
  // one more fetch on every false edge (not just while true) is what picks
  // that up.
  useEffect(() => {
    let alive = true
    const tick = () => {
      if (!alive || !imgRef.current) return
      imgRef.current.src = api.frameURL(frameHeight)
    }
    if (running) {
      tick()
      const id = setInterval(tick, 125)
      wasRunning.current = true
      return () => {
        alive = false
        clearInterval(id)
      }
    }
    if (wasRunning.current) tick()
    wasRunning.current = false
    return () => {
      alive = false
    }
    // frameHeight is derived from info, which only ever transitions once
    // (null → the analyzer's fixed channel list) — re-running this effect
    // when it settles is what keeps the very first frame (requested before
    // that response lands, at the DEFAULT_CHANNEL_COUNT fallback height)
    // from being stuck at a stale height for the rest of the session.
  }, [running, frameHeight])

  // Protocol composition (F-offline-protocol-share): an imported file is a
  // fixed, finished thing — "what's actually in it" is a more useful reading
  // than a live scrolling field of a capture that will never produce another
  // packet. Session.ChannelTotals() is a non-decaying running total (unlike
  // the field's own 82s-wide rolling history), so this stays the file's real
  // composition for as long as the session stays open, not just briefly
  // after import. Polled rather than fetched once because `offline` can
  // still be true while a large file is mid-replay, and this should settle
  // into its final numbers the same way the field's own frame does.
  useEffect(() => {
    if (!offline) {
      setTotals(null)
      return
    }
    let alive = true
    const poll = () => {
      api.renderTotals().then((d) => { if (alive) setTotals(d) }).catch(() => {})
    }
    poll()
    const id = setInterval(poll, 1000)
    return () => { alive = false; clearInterval(id) }
  }, [offline])

  const channels = info?.channels || []
  const totalBytes = totals?.total_bytes || 0
  const pctFor = (c) => (totalBytes > 0 ? ((totals.totals?.[c] || 0) / totalBytes) * 100 : 0)

  return (
    <section className="pane pane-field">
      <div className="pane-head">
        <h2>{t('panes.field')}</h2>
        <span className={`render-badge ${info?.backend === 'cuda' ? 'gpu' : 'cpu'}`}>
          {t('status.renderer')}:{' '}
          {info?.backend === 'cuda' ? t('status.rendererCuda') : t('status.rendererCpu')}
          {info?.device ? ` · ${info.device}` : ''}
        </span>
      </div>

      <div className="field-body">
        <ul className={`field-channels ${totals ? 'with-share' : ''}`} aria-hidden="false">
          {channels.map((c) => {
            const pct = totals ? pctFor(c) : null
            return (
              <li
                key={c}
                className={hoverChannel === c ? 'hot' : ''}
                onMouseEnter={() => setHoverChannel(c)}
                onMouseLeave={() => setHoverChannel(null)}
              >
                {/* Order stays fixed (RenderChannels) rather than sorted by
                    share — this list lines up row-for-row with the field
                    image itself, and reordering it would break that. */}
                {pct !== null && (
                  <span className="field-chan-bar" style={{ width: `${pct}%`, background: `var(--proto-${c})` }} />
                )}
                <span className="field-chan-name">{c}</span>
                {pct !== null && <span className="field-chan-pct">{pct.toFixed(1)}%</span>}
              </li>
            )
          })}
        </ul>
        <div className="field-canvas">
          <img
            ref={imgRef}
            alt={t('panes.field')}
            style={{ height: frameHeight }}
            src={api.frameURL(frameHeight)}
            onLoad={() => setHasFrame(true)}
          />
          {/* Only claim "idle" before anything has ever been rendered — once a
              frame has loaded (including the final frame of a finished
              offline replay), covering it back up just because `running` is
              now false would hide real data behind a label that means
              "nothing to show", which is no longer true. */}
          {!running && !hasFrame && <div className="field-idle">{t('status.idle')}</div>}
        </div>
      </div>
    </section>
  )
}
