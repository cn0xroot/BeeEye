// Display-filter templates.
//
// Every expression here is valid input to internal/dfilter — they are starting
// points a person can then edit, not a separate query language. Labels go
// through i18n; the expressions never do, because they are syntax the user
// types and translating a field name would make the filter unenterable
// (program.md §3.12.5).
//
// RFC 1918 plus CGNAT, spelled out once and reused: getting one of these ranges
// wrong silently changes what "internal" means across several presets.
const PRIVATE = '(ip.addr == 10.0.0.0/8 || ip.addr == 172.16.0.0/12 || ip.addr == 192.168.0.0/16 || ip.addr == 100.64.0.0/10)'

export const PRESET_GROUPS = [
  {
    id: 'protocol',
    items: [
      { id: 'tls', expr: 'tls' },
      { id: 'dns', expr: 'dns || mdns' },
      { id: 'http', expr: 'http' },
      { id: 'mqtt', expr: 'mqtt' },
      { id: 'arp', expr: 'arp' },
      { id: 'icmp', expr: 'icmp' },
      { id: 'dhcp', expr: 'dhcp' },
      { id: 'discovery', expr: 'ssdp || mdns || dhcp' },
    ],
  },
  {
    id: 'address',
    items: [
      { id: 'internal', expr: PRIVATE },
      { id: 'external', expr: `!${PRIVATE}` },
      { id: 'eastWest', expr: `${PRIVATE} && !arp` },
      { id: 'oneHost', expr: 'ip.addr == 192.168.1.100' },
      { id: 'subnet', expr: 'ip.addr == 192.168.1.0/24' },
      { id: 'ipv6', expr: 'ipv6' },
    ],
  },
  {
    id: 'investigate',
    items: [
      // The handshake is where the identity is: SNI, ALPN and the JA3 inputs.
      { id: 'clientHello', expr: 'tls.handshake.type == 1' },
      { id: 'sniContains', expr: 'tls.handshake.extensions_server_name contains "example"' },
      { id: 'ja3', expr: 'tls.ja3 == "PASTE_JA3_HASH_HERE"' },
      // NXDOMAIN storms are the classic domain-generation-algorithm signature.
      { id: 'nxdomain', expr: 'dns.flags.rcode == 3' },
      { id: 'dnsQuery', expr: 'dns.qry.name contains "tuya"' },
      // A device using encrypted DNS is itself worth knowing, even though the
      // queries inside are not readable.
      { id: 'encryptedDns', expr: 'tcp.port == 853 || udp.port == 853' },
      // Connection attempts with no reply: what a port scan looks like.
      { id: 'synOnly', expr: 'tcp.flags.syn == 1 && tcp.flags.ack == 0' },
      { id: 'resets', expr: 'tcp.flags.reset == 1' },
      { id: 'plaintext', expr: 'http || telnet || ssdp' },
      { id: 'largeFrames', expr: 'frame.len >= 1400' },
      { id: 'nonStandardTls', expr: 'tls && !(tcp.port == 443) && !(tcp.port == 8883)' },
    ],
  },
  {
    id: 'noise',
    items: [
      { id: 'noDiscovery', expr: '!mdns && !ssdp && !arp' },
      { id: 'noLocalChatter', expr: '!arp && !icmp && !dhcp' },
      { id: 'unicastOnly', expr: `!(eth.dst == ff:ff:ff:ff:ff:ff)` },
    ],
  },
]

// combine appends a preset to an existing filter with AND, which is what a
// person almost always means when picking a second template — replacing what
// they already typed would throw away their work.
export function combine(current, expr) {
  const c = (current || '').trim()
  if (!c) return expr
  if (c.includes(expr)) return c
  const wrap = (s) => (/\s(\|\||or)\s/i.test(s) ? `(${s})` : s)
  return `${wrap(c)} && ${wrap(expr)}`
}
