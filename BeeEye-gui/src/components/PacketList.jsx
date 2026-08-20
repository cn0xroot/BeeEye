import { memo, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { protocolSlot } from '../api'

// Wall-clock time, to the millisecond, in the viewer's own locale and zone.
// Wireshark defaults to seconds-since-first-packet; that is useful for reading
// a trace in isolation but useless for lining an event up against a log or a
// door-lock record, which is what this system is for.
function clock(tsMs, locale) {
  const d = new Date(tsMs)
  const hms = d.toLocaleTimeString(locale, { hour12: false })
  return `${hms}.${String(d.getMilliseconds()).padStart(3, '0')}`
}

// Column sorting, Wireshark's model: click a heading to sort by it, click the
// same heading again to reverse, click a third time to drop back to capture
// order. Capture order is a real state and not just "sorted by No. ascending" —
// it is the only one where a live capture keeps making sense as it grows.
//
// Addresses sort numerically rather than lexically. As text, 192.168.1.9 sorts
// after 192.168.1.10 and a sorted address column is then useless for spotting a
// range, which is most of why anyone sorts by address.
// The rank prefix keeps the address families in distinct blocks. Without it
// the grouping is an accident of which characters the padded forms happen to
// start with, which holds for 192.168.x.y and breaks for ::1.
function addrKey(a) {
  if (!a) return '9'
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a)
  if (v4) return '1' + v4.slice(1).map((o) => o.padStart(3, '0')).join('.')
  // A MAC is six hex pairs; an IPv6 address is anything else with colons in it.
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(a)) return '3' + a.toLowerCase()
  if (a.includes(':')) return '2' + a.split(':').map((h) => h.padStart(4, '0')).join(':')
  return '4' + a.toLowerCase()
}

// A packet with no local process sorts after every packet that has one, in both
// directions: "not this host" is the absence of a value, and parking it at the
// end keeps the processes themselves contiguous.
const SORTERS = {
  no: (p) => p.no,
  time: (p) => p.ts_ms,
  src: (p) => addrKey(p.src),
  dst: (p) => addrKey(p.dst),
  proto: (p) => (p.proto || '').toLowerCase(),
  process: (p) => (p.process ? p.process.comm.toLowerCase() : '\uffff'),
  length: (p) => p.length,
  info: (p) => (p.info || '').toLowerCase(),
}

// PacketRow is memoized so a flush that appends a handful of rows does not
// re-render the thousands already on screen. The parent preserves each
// packet's object identity across flushes, so memo's shallow prop compare sees
// an unchanged `packet` and skips the row entirely; only genuinely new rows,
// and the two rows whose `isSelected` flips, actually render.
const PacketRow = memo(function PacketRow({ packet: p, isSelected, onSelect, locale, t }) {
  const slot = protocolSlot(p.proto)
  return (
    <tr
      className={`proto-${slot} ${isSelected ? 'selected' : ''}`}
      onClick={() => onSelect(p.no)}
    >
      <td className="c-no">{p.no}</td>
      <td className="c-time" title={`+${p.time.toFixed(6)} s`}>
        {clock(p.ts_ms, locale)}
      </td>
      <td className="c-addr" title={p.src}>
        <span className="addr">{p.src}</span>
        {p.src_name && (
          <span className="addr-name" title={t('names.nameFrom', { source: p.src_name_source })}>
            {p.src_name}
          </span>
        )}
      </td>
      <td className="c-addr" title={p.dst}>
        <span className="addr">{p.dst}</span>
        {p.country && p.country !== 'LOCAL' && <span className="cc">{p.country}</span>}
        {p.dst_name && (
          <span className="addr-name" title={t('names.nameFrom', { source: p.dst_name_source })}>
            {p.dst_name}
          </span>
        )}
      </td>
      <td className="c-proto">
        <span className="proto-dot" aria-hidden="true" />
        {p.proto}
      </td>
      <td className="c-proc">
        {p.process ? (
          <span title={`${p.process.exe || ''} ${p.process.user || ''}`.trim()}>
            <span className="proc-name">{p.process.comm}</span>{' '}
            <span className="proc-pid">{p.process.pid}</span>
          </span>
        ) : (
          <span className="proc-none" title={t('process.notLocalHelp')}>
            {t('process.notLocal')}
          </span>
        )}
      </td>
      <td className="c-len">{p.length}</td>
      <td className="c-info" title={p.info}>{p.info}</td>
    </tr>
  )
})

// PacketList is the top pane. It renders plain rows rather than a virtualized
// list: the server caps what it sends, and a scroll container of a few thousand
// rows is well within what the browser handles smoothly — virtualization here
// would add complexity and break find-in-page for no real gain.
export default function PacketList({ packets, selected, onSelect, autoScroll, onAutoScroll, held = 0, filter, onClearFilter }) {
  const { t, i18n } = useTranslation()
  const bodyRef = useRef(null)

  // null = capture order. Sorting is a view over the same packets, never a
  // change to them: the No. column still shows capture order under every sort.
  const [sort, setSort] = useState(null)

  const rows = useMemo(() => {
    if (!sort) return packets
    const key = SORTERS[sort.key]
    const dir = sort.dir === 'desc' ? -1 : 1
    // Sort a copy — packets is state owned by App, and sorting in place would
    // mutate it. Ties fall back to capture order so the sort is stable and a
    // burst of same-millisecond packets keeps the order they arrived in.
    return [...packets].sort((a, b) => {
      const ka = key(a)
      const kb = key(b)
      if (ka < kb) return -dir
      if (ka > kb) return dir
      return a.no - b.no
    })
  }, [packets, sort])

  // Clicking a heading cycles asc → desc → capture order. Following the tail
  // is meaningless once the list is not in capture order, so the first sort
  // also releases auto-scroll rather than fighting it.
  const onSortClick = (key) => {
    setSort((prev) => {
      if (!prev || prev.key !== key) {
        if (autoScroll) onAutoScroll(false)
        return { key, dir: 'asc' }
      }
      if (prev.dir === 'asc') return { key, dir: 'desc' }
      return null
    })
  }

  const COLUMNS = [
    ['no', 'c-no'],
    ['time', 'c-time'],
    ['src', 'c-addr'],
    ['dst', 'c-addr'],
    ['proto', 'c-proto'],
    ['process', 'c-proc'],
    ['length', 'c-len'],
    ['info', 'c-info'],
  ]
  const HEADING = {
    no: 'columns.no',
    time: 'columns.time',
    src: 'columns.source',
    dst: 'columns.destination',
    proto: 'columns.protocol',
    process: 'columns.process',
    length: 'columns.length',
    info: 'columns.info',
  }

  // Scrolls we perform ourselves must not be mistaken for the user scrolling.
  const programmatic = useRef(false)

  // The tail follows only this pane. scrollIntoView() was used here before and
  // was wrong twice over: it scrolls every scrollable ancestor, so following
  // the tail dragged the whole page with it, and it moves the viewport even
  // when the pane is already where it should be.
  //
  // Keyed on the newest packet number rather than packets.length, because the
  // length stops changing once the ring is full — which silently stopped
  // auto-scroll working after the first MAX_ROWS packets.
  const newest = packets.length ? packets[packets.length - 1].no : 0

  useLayoutEffect(() => {
    const el = bodyRef.current
    if (!autoScroll || !el) return
    programmatic.current = true
    el.scrollTop = el.scrollHeight
    // Cleared on the next frame, after the scroll event has been dispatched.
    requestAnimationFrame(() => { programmatic.current = false })
  }, [newest, autoScroll])

  // Scrolling up is an intent to read history, so it turns auto-scroll off —
  // nothing is more annoying than being yanked back to the tail mid-read.
  //
  // The reverse is deliberately NOT true: reaching the bottom does not turn it
  // back on. Doing that made the checkbox impossible to switch off, because the
  // list is usually already at the bottom when you click it, and the very next
  // scroll event turned it straight back on.
  const onScroll = () => {
    const el = bodyRef.current
    if (!el || programmatic.current) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24
    if (!atBottom && autoScroll) onAutoScroll(false)
  }

  return (
    <section className="pane pane-packets">
      <div className="pane-head">
        <h2>{t('panes.packets')}</h2>
        {/* A pressed-state toggle rather than a checkbox: this is a mode the
            list is in, and it needs to read as on or off at a glance from
            across a desk. */}
        <button
          type="button"
          className="toggle"
          aria-pressed={autoScroll}
          onClick={() => onAutoScroll(!autoScroll)}
          title={held > 0 ? t('toolbar.autoscrollHeld', { count: held }) : undefined}
        >
          <span className="led" aria-hidden="true" />
          {autoScroll ? t('toolbar.autoscrollOn') : t('toolbar.autoscrollOff')}
          {!autoScroll && held > 0 && (
            <span className="held-badge">+{held > 9999 ? '9999+' : held}</span>
          )}
        </button>
      </div>

      <div className="table-wrap" ref={bodyRef} onScroll={onScroll}>
        <table className="packet-table">
          <thead>
            <tr>
              {COLUMNS.map(([key, cls]) => {
                const active = sort?.key === key
                return (
                  <th
                    key={key}
                    className={`${cls} sortable${active ? ' sorted' : ''}`}
                    aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
                  >
                    <button type="button" onClick={() => onSortClick(key)} title={t('columns.sortHint')}>
                      {t(HEADING[key])}
                      <span className="sort-mark" aria-hidden="true">
                        {active ? (sort.dir === 'asc' ? '▲' : '▼') : ''}
                      </span>
                    </button>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <PacketRow
                key={p.no}
                packet={p}
                isSelected={selected === p.no}
                onSelect={onSelect}
                locale={i18n.resolvedLanguage}
                t={t}
              />
            ))}
          </tbody>
        </table>

        {packets.length === 0 && (
          <div className="empty">
            {filter ? (
              // An empty list under an active filter is not the same problem as
              // an empty capture, and saying so saves the operator from
              // debugging a capture that is working fine.
              <>
                <div className="empty-title">{t('empty.filteredOut')}</div>
                <div className="empty-help">
                  <code>{filter}</code>
                </div>
                <button className="btn btn-ghost tiny" onClick={onClearFilter}>
                  {t('toolbar.clear')}
                </button>
              </>
            ) : (
              <>
                <div className="empty-title">{t('empty.noPackets')}</div>
                <div className="empty-help">{t('empty.noPacketsHelp')}</div>
              </>
            )}
          </div>
        )}
      </div>
    </section>
  )
}
