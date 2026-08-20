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
const FRAME_HEIGHT = 168

export default function TrafficField({ running }) {
  const { t } = useTranslation()
  const imgRef = useRef(null)
  const [info, setInfo] = useState(null)
  const [hoverChannel, setHoverChannel] = useState(null)

  useEffect(() => {
    api.renderInfo().then(setInfo).catch(() => setInfo(null))
  }, [])

  // Refresh at ~8fps while capturing. A new URL each time defeats the cache;
  // the server also sends no-store, since every frame differs.
  useEffect(() => {
    if (!running) return
    let alive = true
    const tick = () => {
      if (!alive || !imgRef.current) return
      imgRef.current.src = api.frameURL(FRAME_HEIGHT)
    }
    tick()
    const id = setInterval(tick, 125)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [running])

  const channels = info?.channels || []

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
        <ul className="field-channels" aria-hidden="false">
          {channels.map((c) => (
            <li
              key={c}
              className={hoverChannel === c ? 'hot' : ''}
              onMouseEnter={() => setHoverChannel(c)}
              onMouseLeave={() => setHoverChannel(null)}
            >
              {c}
            </li>
          ))}
        </ul>
        <div className="field-canvas">
          <img
            ref={imgRef}
            alt={t('panes.field')}
            height={FRAME_HEIGHT}
            src={api.frameURL(FRAME_HEIGHT)}
          />
          {!running && <div className="field-idle">{t('status.idle')}</div>}
        </div>
      </div>
    </section>
  )
}
