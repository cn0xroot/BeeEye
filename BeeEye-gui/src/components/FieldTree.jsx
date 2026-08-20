import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { layerRole } from '../api'

// FieldTree is the middle pane: the protocol dissection as an expandable tree.
//
// Hovering or selecting a row reports its byte range upward so the hex pane can
// highlight exactly those bytes — that link is the whole reason the dissector
// carries offset/length on every field.
function TreeNode({ node, depth, role, onHover, selectedField, onSelectField }) {
  // Expanded by default: selecting a packet should show what is in it, not a
  // row of closed twisties to click through. Collapsing is still one click
  // away for anyone who wants a shorter tree.
  const [open, setOpen] = useState(true)
  const hasKids = node.children?.length > 0
  const isSelected = selectedField === node

  return (
    <li>
      <div
        className={`tree-row role-${role} ${depth === 0 ? 'layer-head' : ''} ${isSelected ? 'selected' : ''}`}
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
        onMouseEnter={() => onHover(node)}
        onMouseLeave={() => onHover(null)}
        onClick={() => {
          onSelectField(node)
          if (hasKids) setOpen(!open)
        }}
      >
        <span className={`twisty ${hasKids ? (open ? 'open' : 'closed') : 'leaf'}`} aria-hidden="true">
          {hasKids ? (open ? '▾' : '▸') : '·'}
        </span>
        <span className="tree-label">{node.label}</span>
        {node.value && node.label.indexOf(node.value) === -1 && (
          <span className="tree-value">{node.value}</span>
        )}
        {node.field && <code className="tree-field">{node.field}</code>}
      </div>
      {hasKids && open && (
        <ul>
          {node.children.map((c, i) => (
            <TreeNode
              key={`${c.label}-${i}`}
              node={c}
              depth={depth + 1}
              role={role}
              onHover={onHover}
              selectedField={selectedField}
              onSelectField={onSelectField}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export default function FieldTree({ detail, onHover, selectedField, onSelectField, onFilterField }) {
  const { t } = useTranslation()

  if (!detail) {
    return (
      <section className="pane pane-tree">
        <div className="pane-head"><h2>{t('panes.detail')}</h2></div>
        <div className="empty">
          <div className="empty-title">{t('empty.noSelection')}</div>
          <div className="empty-help">{t('empty.noSelectionHelp')}</div>
        </div>
      </section>
    )
  }

  return (
    <section className="pane pane-tree">
      <div className="pane-head">
        <h2>{t('panes.detail')}</h2>
        <span className="pane-meta">#{detail.summary.no}</span>
      </div>

      {detail.process && (
        <div className="proc-strip">
          <span><b>{t('process.local')}</b> {detail.process.comm} · pid {detail.process.pid}</span>
          {detail.process.user && <span><b>user</b> {detail.process.user}</span>}
          {detail.process.exe && <span><b>exe</b> {detail.process.exe}</span>}
        </div>
      )}

      {(detail.sni || detail.ja3 || detail.alpn?.length) && (
        <div className="tls-strip">
          {detail.sni && <span><b>SNI</b> {detail.sni}</span>}
          {detail.alpn?.length > 0 && <span><b>ALPN</b> {detail.alpn.join(', ')}</span>}
          {detail.ja3 && <span><b>JA3</b> <code>{detail.ja3}</code></span>}
        </div>
      )}

      <div className="tree-wrap">
        {/* Keyed on the packet number so switching packets rebuilds the tree
            with fresh expansion state — otherwise React reuses the previous
            packet's open/closed nodes for structurally similar rows. */}
        <ul className="tree" key={detail.summary.no}>
          {detail.layers?.map((l, i) => (
            <TreeNode
              key={i}
              node={l}
              depth={0}
              role={layerRole(l.proto)}
              onHover={onHover}
              selectedField={selectedField}
              onSelectField={onSelectField}
            />
          ))}
        </ul>
      </div>

      {selectedField?.field && (
        <div className="tree-actions">
          <button
            className="btn btn-ghost tiny"
            onClick={() => onFilterField(`${selectedField.field} == "${selectedField.value}"`)}
          >
            {t('actions.filterOnField')}
          </button>
          <button
            className="btn btn-ghost tiny"
            onClick={() => navigator.clipboard?.writeText(selectedField.value || '')}
          >
            {t('actions.copyField')}
          </button>
        </div>
      )}
    </section>
  )
}
