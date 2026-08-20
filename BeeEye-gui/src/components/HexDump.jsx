import { useTranslation } from 'react-i18next'
import { layerRole } from '../api'

// HexDump is the third pane. The highlight range comes from whichever field is
// hovered or selected in the tree, which is what turns "TLS ClientHello, SNI"
// from a claim into something you can see in the bytes.
export default function HexDump({ bytes, highlight, layers }) {
  const { t } = useTranslation()

  if (!bytes || bytes.length === 0) {
    return (
      <section className="pane pane-hex">
        <div className="pane-head"><h2>{t('panes.bytes')}</h2></div>
        <div className="empty"><div className="empty-help">—</div></div>
      </section>
    )
  }

  const from = highlight ? highlight.offset : -1
  const to = highlight ? highlight.offset + highlight.length : -1

  // roleAt answers "which protocol layer owns this byte", so the dump shows the
  // packet's structure at a glance instead of an undifferentiated wall of hex.
  const ranges = (layers || []).map((l) => ({
    role: layerRole(l.proto),
    from: l.offset,
    to: l.offset + l.length,
  }))
  const roleAt = (i) => {
    // Later layers are nested inside earlier ones, so the last match wins.
    let role = ''
    for (const r of ranges) if (i >= r.from && i < r.to) role = r.role
    return role
  }

  const rows = []
  for (let off = 0; off < bytes.length; off += 16) {
    // Array.from is load-bearing: bytes is a Uint8Array, and its .map returns
    // another Uint8Array, which coerces JSX elements to NaN rather than
    // rendering them.
    rows.push({ off, slice: Array.from(bytes.slice(off, off + 16)) })
  }

  return (
    <section className="pane pane-hex">
      <div className="pane-head">
        <h2>{t('panes.bytes')}</h2>
        <ul className="layer-legend">
          {(layers || []).map((l, i) => (
            <li key={i} className={`role-${layerRole(l.proto)}`}>
              <span className="swatch" aria-hidden="true" />
              {l.proto || '?'}
            </li>
          ))}
        </ul>
        <span className="pane-meta">
          {bytes.length} B{highlight ? ` · +${highlight.offset}..${to - 1}` : ''}
        </span>
      </div>

      <div className="hex-wrap">
        <table className="hex">
          <tbody>
            {rows.map(({ off, slice }) => (
              <tr key={off}>
                <td className="hex-off">{off.toString(16).padStart(4, '0')}</td>
                <td className="hex-bytes">
                  {slice.map((b, i) => {
                    const abs = off + i
                    const on = abs >= from && abs < to
                    return (
                      <span key={i} className={`by-${roleAt(abs)} ${on ? 'hl' : ''}`}>
                        {b.toString(16).padStart(2, '0')}
                        {i === 7 ? '  ' : ' '}
                      </span>
                    )
                  })}
                </td>
                <td className="hex-ascii">
                  {slice.map((b, i) => {
                    const abs = off + i
                    const on = abs >= from && abs < to
                    // Only printable ASCII; everything else is a dot, the same
                    // convention every hex viewer uses.
                    const ch = b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'
                    return (
                      <span key={i} className={`by-${roleAt(abs)} ${on ? 'hl' : ''}`}>
                        {ch}
                      </span>
                    )
                  })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
