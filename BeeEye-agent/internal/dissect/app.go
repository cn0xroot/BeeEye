package dissect

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Application-layer dissectors. Protocol selection follows §3.5.4: a
// successful plaintext parse wins outright, ALPN comes next, the well-known
// port table is the fallback, and anything still unresolved is reported as
// "unknown" rather than guessed at.

func dissectAppTCP(r *Result, b []byte, off int, sport, dport uint16) {
	p := b[off:]
	switch {
	case len(p) >= 6 && p[0] == 0x16 && p[1] == 0x03:
		dissectTLS(r, b, off)
	// Checked before the HTTP case, not after: "OPTIONS " is a valid first
	// word for both an HTTP request line and a SIP one, and only the SIP
	// check looks far enough (the line's own trailing " SIP/2.0") to tell
	// them apart. Every other SIP method name is unambiguous on its own.
	case looksLikeSIPRequest(p) || looksLikeSIPResponse(p):
		dissectSIP(r, b, off)
	case looksLikeHTTPRequest(p) || looksLikeHTTPResponse(p):
		dissectHTTP(r, b, off)
	case sport == 1883 || dport == 1883:
		dissectMQTT(r, b, off)
	case sport == 53 || dport == 53:
		// DNS over TCP carries a 2-byte length prefix.
		if len(p) > 2 {
			dissectDNS(r, b, off+2, "dns")
		}
	case sport == 5060 || dport == 5060 || sport == 5061 || dport == 5061:
		// Content sniffing above already catches a message that starts
		// clean; this is the fallback for a mid-stream/pipelined segment
		// that does not begin at a request or status line.
		dissectSIP(r, b, off)
	default:
		if svc := wellKnownService(sport, dport); svc != "" {
			r.Proto = svc
			r.proto(strings.ToLower(svc))
		}
	}
}

func dissectAppUDP(r *Result, b []byte, off int, sport, dport uint16) {
	p := b[off:]
	switch {
	case sport == 53 || dport == 53:
		dissectDNS(r, b, off, "dns")
	case sport == 5353 || dport == 5353:
		dissectDNS(r, b, off, "mdns")
	case sport == 1900 || dport == 1900:
		dissectSSDP(r, b, off)
	case sport == 67 || dport == 67 || sport == 68 || dport == 68:
		dissectDHCP(r, b, off)
	case sport == 123 || dport == 123:
		r.Proto = "NTP"
		r.proto("ntp")
		r.Info = "NTP"
	case sport == 5683 || dport == 5683:
		dissectCoAP(r, b, off)
	case looksLikeSIPRequest(p) || looksLikeSIPResponse(p) || sport == 5060 || dport == 5060:
		// SIP's classic transport (RFC 3261): most calls' signaling never
		// touches TCP at all.
		dissectSIP(r, b, off)
	case sport == 2152 || dport == 2152 || sport == 2123 || dport == 2123:
		// GTP-U (2152, user-plane) / GTP-C (2123, control-plane) — a mobile
		// core's own tunnel between the gateway and the radio side. Every
		// phone's actual traffic (its TLS, HTTP, SIP, DNS…) rides inside a
		// GTP-U G-PDU wrapping a second, complete IP packet; without peeling
		// that back this analyzer sees nothing but "UDP 2152" between two
		// core-network addresses no matter what the phone is really doing.
		dissectGTP(r, b, off)
	case sport == 4729 || dport == 4729:
		// GSMTAP (osmocom's capture-relay format) — SIMtrace-family probes
		// use this to deliver ISO/IEC 7816-4 SIM/USIM APDU traces.
		dissectGSMTAP(r, b, off)
	default:
		if svc := wellKnownService(sport, dport); svc != "" {
			r.Proto = svc
			r.proto(strings.ToLower(svc))
		}
	}
}

// wellKnownService is the §3.5.4 priority-3 fallback. It stays deliberately
// short: the authoritative, user-extensible table lives in
// config/port-service-map.yaml and is applied by the agent.
func wellKnownService(sport, dport uint16) string {
	for _, p := range []uint16{sport, dport} {
		switch p {
		case 22:
			return "SSH"
		case 23:
			return "Telnet"
		case 443:
			return "HTTPS"
		case 445:
			return "SMB"
		case 554:
			return "RTSP"
		case 853:
			return "DoT"
		case 3389:
			return "RDP"
		case 8883:
			return "MQTT-TLS"
		}
	}
	return ""
}

// ------------------------------------------------------------------ DNS/mDNS

func dissectDNS(r *Result, b []byte, off int, protoKey string) {
	p := b[off:]
	if len(p) < 12 {
		return
	}
	txid := binary.BigEndian.Uint16(p[0:2])
	flags := binary.BigEndian.Uint16(p[2:4])
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	an := int(binary.BigEndian.Uint16(p[6:8]))
	isResp := flags&0x8000 != 0
	rcode := flags & 0x000F

	r.proto(protoKey)
	r.Proto = strings.ToUpper(protoKey)
	r.set("dns.flags.response", boolStr(isResp))
	r.set("dns.flags.rcode", strconv.Itoa(int(rcode)))

	n := node("Domain Name System", off, len(p))
	if isResp {
		n.Label += " (response)"
	} else {
		n.Label += " (query)"
	}
	r.leaf(n, "Transaction ID", "dns.id", fmt.Sprintf("0x%04x", txid), off, 2)
	r.leaf(n, "Response Code: "+rcodeName(rcode), "dns.flags.rcode", strconv.Itoa(int(rcode)), off+2, 2)

	pos := 12
	var names []string
	for i := 0; i < qd && pos < len(p); i++ {
		name, next, ok := readDNSName(p, pos)
		if !ok || next+4 > len(p) {
			break
		}
		qtype := binary.BigEndian.Uint16(p[next : next+2])
		q := node(fmt.Sprintf("Queries: %s: type %s", name, dnsTypeName(qtype)), off+pos, next+4-pos)
		r.leaf(q, "Name", "dns.qry.name", name, off+pos, next-pos)
		r.leaf(q, "Type", "dns.qry.type", dnsTypeName(qtype), off+next, 2)
		n.Children = append(n.Children, q)
		r.set("dns.qry.name", name)
		r.set("dns.qry.type", dnsTypeName(qtype))
		names = append(names, name)
		pos = next + 4
	}

	var answers []string
	for i := 0; i < an && pos < len(p); i++ {
		name, next, ok := readDNSName(p, pos)
		if !ok || next+10 > len(p) {
			break
		}
		atype := binary.BigEndian.Uint16(p[next : next+2])
		ttl := binary.BigEndian.Uint32(p[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(p[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(p) {
			break
		}
		var val string
		switch {
		case atype == 1 && rdlen == 4:
			val = net.IP(p[rdata : rdata+4]).String()
			r.set("dns.a", val)
		case atype == 28 && rdlen == 16:
			val = net.IP(p[rdata : rdata+16]).String()
			r.set("dns.aaaa", val)
		case atype == 5:
			if cname, _, ok := readDNSName(p, rdata); ok {
				val = cname
				r.set("dns.cname", val)
			}
		default:
			val = fmt.Sprintf("%d bytes", rdlen)
		}
		a := node(fmt.Sprintf("Answers: %s: type %s, %s", name, dnsTypeName(atype), val), off+pos, rdata+rdlen-pos)
		r.leaf(a, "Name", "dns.resp.name", name, off+pos, next-pos)
		r.leaf(a, "Type", "dns.resp.type", dnsTypeName(atype), off+next, 2)
		r.leaf(a, "Time to live", "dns.resp.ttl", strconv.Itoa(int(ttl)), off+next+4, 4)
		if val != "" {
			r.leaf(a, "Address", "dns.resp.addr", val, off+rdata, rdlen)
		}
		n.Children = append(n.Children, a)
		answers = append(answers, val)
		pos = rdata + rdlen
	}
	r.layer(n, protoKey)
	r.Domains = append(r.Domains, names...)

	switch {
	case !isResp && len(names) > 0:
		r.Info = "Standard query 0x" + fmt.Sprintf("%04x %s", txid, strings.Join(names, ", "))
	case isResp && rcode == 3:
		r.Info = fmt.Sprintf("Standard query response 0x%04x No such name %s", txid, strings.Join(names, ", "))
	case isResp:
		r.Info = fmt.Sprintf("Standard query response 0x%04x %s %s",
			txid, strings.Join(names, ", "), strings.Join(answers, ", "))
	default:
		r.Info = fmt.Sprintf("DNS 0x%04x", txid)
	}
}

// readDNSName decodes a possibly-compressed name. It bounds the pointer chain
// so a malformed or hostile packet cannot spin here forever.
func readDNSName(p []byte, pos int) (string, int, bool) {
	var parts []string
	origin := pos
	jumped := false
	hops := 0
	for {
		if pos >= len(p) {
			return "", origin, false
		}
		l := int(p[pos])
		if l == 0 {
			pos++
			if !jumped {
				origin = pos
			}
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer
			if pos+1 >= len(p) {
				return "", origin, false
			}
			if hops++; hops > 16 {
				return "", origin, false
			}
			target := int(binary.BigEndian.Uint16(p[pos:pos+2]) & 0x3FFF)
			if !jumped {
				origin = pos + 2
				jumped = true
			}
			pos = target
			continue
		}
		if pos+1+l > len(p) {
			return "", origin, false
		}
		parts = append(parts, string(p[pos+1:pos+1+l]))
		pos += 1 + l
	}
	return strings.Join(parts, "."), origin, true
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	}
	return strconv.Itoa(int(t))
}

func rcodeName(c uint16) string {
	switch c {
	case 0:
		return "No error (0)"
	case 2:
		return "Server failure (2)"
	case 3:
		return "No such name (3)"
	case 5:
		return "Refused (5)"
	}
	return strconv.Itoa(int(c))
}

// ---------------------------------------------------------------------- TLS

// greaseValues are the RFC 8701 reserved values Chrome/Firefox inject. JA3
// excludes them, so two runs of the same client hash identically.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

func dissectTLS(r *Result, b []byte, off int) {
	p := b[off:]
	if len(p) < 6 {
		return
	}
	r.proto("tls")
	r.Proto = "TLS"

	recType := p[0]
	recVer := binary.BigEndian.Uint16(p[1:3])
	recLen := int(binary.BigEndian.Uint16(p[3:5]))

	n := node("Transport Layer Security", off, min(len(p), 5+recLen))
	r.leaf(n, "Content Type: "+tlsContentType(recType), "tls.record.content_type", strconv.Itoa(int(recType)), off, 1)
	r.leaf(n, "Version", "tls.record.version", tlsVersionName(recVer), off+1, 2)
	r.leaf(n, "Length", "tls.record.length", strconv.Itoa(recLen), off+3, 2)
	r.set("tls.record.content_type", strconv.Itoa(int(recType)))

	if recType != 0x16 || len(p) < 9 {
		r.Info = tlsContentType(recType)
		r.layer(n, "tls")
		return
	}

	hsType := p[5]
	hs := node("Handshake Protocol: "+tlsHandshakeType(hsType), off+5, min(len(p)-5, recLen))
	r.leaf(hs, "Handshake Type: "+tlsHandshakeType(hsType), "tls.handshake.type", strconv.Itoa(int(hsType)), off+5, 1)
	r.set("tls.handshake.type", strconv.Itoa(int(hsType)))

	if hsType != 0x01 {
		n.Children = append(n.Children, hs)
		r.layer(n, "tls")
		r.Info = "TLS " + tlsHandshakeType(hsType)
		return
	}

	// ClientHello body: version(2) random(32) sessionID cipherSuites
	// compression extensions. Every step is bounds-checked; a truncated
	// capture must degrade to "what we could read", never panic.
	q := 9
	if q+34 > len(p) {
		n.Children = append(n.Children, hs)
		r.layer(n, "tls")
		return
	}
	clientVer := binary.BigEndian.Uint16(p[q : q+2])
	r.leaf(hs, "Version", "tls.handshake.version", tlsVersionName(clientVer), off+q, 2)
	q += 2 + 32

	if q >= len(p) {
		return
	}
	sidLen := int(p[q])
	q += 1 + sidLen
	if q+2 > len(p) {
		return
	}
	csLen := int(binary.BigEndian.Uint16(p[q : q+2]))
	q += 2
	if q+csLen > len(p) {
		return
	}
	var ciphers []uint16
	var cipherStrs []string
	for i := 0; i+1 < csLen; i += 2 {
		c := binary.BigEndian.Uint16(p[q+i : q+i+2])
		if isGREASE(c) {
			continue
		}
		ciphers = append(ciphers, c)
		cipherStrs = append(cipherStrs, fmt.Sprintf("0x%04x", c))
	}
	r.leaf(hs, "Cipher Suites", "tls.handshake.ciphersuite",
		fmt.Sprintf("%d suites: %s", len(ciphers), strings.Join(cipherStrs, " ")), off+q, csLen)
	q += csLen

	if q >= len(p) {
		return
	}
	compLen := int(p[q])
	q += 1 + compLen
	if q+2 > len(p) {
		return
	}
	extTotal := int(binary.BigEndian.Uint16(p[q : q+2]))
	q += 2
	extEnd := min(q+extTotal, len(p))

	var extTypes []uint16
	var curves, pointFmts []uint16
	extNode := node("Extensions", off+q, extEnd-q)

	for q+4 <= extEnd {
		etype := binary.BigEndian.Uint16(p[q : q+2])
		elen := int(binary.BigEndian.Uint16(p[q+2 : q+4]))
		body := q + 4
		if body+elen > extEnd {
			break
		}
		if !isGREASE(etype) {
			extTypes = append(extTypes, etype)
		}
		switch etype {
		case 0x0000: // server_name — the SNI (F3)
			if elen >= 5 {
				nameLen := int(binary.BigEndian.Uint16(p[body+3 : body+5]))
				if body+5+nameLen <= len(p) {
					r.SNI = string(p[body+5 : body+5+nameLen])
					r.set("tls.handshake.extensions_server_name", r.SNI)
					r.Domains = append(r.Domains, r.SNI)
					r.leaf(extNode, "Server Name Indication", "tls.handshake.extensions_server_name",
						r.SNI, off+body+5, nameLen)
				}
			}
		case 0x0010: // ALPN — §3.5.4 priority 2
			if elen >= 2 {
				lp := body + 2
				for lp < body+elen && lp < len(p) {
					l := int(p[lp])
					if lp+1+l > len(p) {
						break
					}
					proto := string(p[lp+1 : lp+1+l])
					r.ALPN = append(r.ALPN, proto)
					r.set("tls.handshake.extensions_alpn_str", proto)
					lp += 1 + l
				}
				if len(r.ALPN) > 0 {
					r.leaf(extNode, "ALPN", "tls.handshake.extensions_alpn_str",
						strings.Join(r.ALPN, ", "), off+body, elen)
				}
			}
		case 0x000a: // supported_groups — a JA3 component
			if elen >= 2 {
				ln := int(binary.BigEndian.Uint16(p[body : body+2]))
				for i := 0; i+1 < ln && body+2+i+1 < len(p); i += 2 {
					g := binary.BigEndian.Uint16(p[body+2+i : body+4+i])
					if !isGREASE(g) {
						curves = append(curves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats — a JA3 component
			if elen >= 1 {
				ln := int(p[body])
				for i := 0; i < ln && body+1+i < len(p); i++ {
					pointFmts = append(pointFmts, uint16(p[body+1+i]))
				}
			}
		}
		q = body + elen
	}
	if len(extNode.Children) > 0 {
		hs.Children = append(hs.Children, extNode)
	}

	// JA3 is computed here, in userspace, exactly as §3.4.3 requires — the
	// kernel only ever hands up the raw bytes.
	r.JA3 = ja3(clientVer, ciphers, extTypes, curves, pointFmts)
	r.leaf(hs, "JA3 Fingerprint", "tls.ja3", r.JA3, off+5, 1)
	r.set("tls.ja3", r.JA3)

	n.Children = append(n.Children, hs)
	r.layer(n, "tls")

	// ALPN outranks the port table when naming the protocol (§3.5.4).
	switch {
	case contains(r.ALPN, "h2"):
		r.Proto = "HTTP/2 (TLS)"
	case contains(r.ALPN, "h3"):
		r.Proto = "HTTP/3 (TLS)"
	case contains(r.ALPN, "http/1.1"):
		r.Proto = "HTTPS"
	}
	if r.SNI != "" {
		r.Info = "Client Hello (SNI=" + r.SNI + ")"
	} else {
		r.Info = "Client Hello"
	}
}

// ja3 renders the canonical JA3 string and returns its MD5, per the original
// specification: version,ciphers,extensions,curves,point_formats.
func ja3(version uint16, ciphers, exts, curves, pointFmts []uint16) string {
	join := func(v []uint16) string {
		s := make([]string, len(v))
		for i, x := range v {
			s[i] = strconv.Itoa(int(x))
		}
		return strings.Join(s, "-")
	}
	raw := strings.Join([]string{
		strconv.Itoa(int(version)),
		join(ciphers), join(exts), join(curves), join(pointFmts),
	}, ",")
	return fmt.Sprintf("%x", md5.Sum([]byte(raw)))
}

func tlsContentType(t uint8) string {
	switch t {
	case 20:
		return "Change Cipher Spec (20)"
	case 21:
		return "Alert (21)"
	case 22:
		return "Handshake (22)"
	case 23:
		return "Application Data (23)"
	}
	return strconv.Itoa(int(t))
}

func tlsHandshakeType(t uint8) string {
	switch t {
	case 1:
		return "Client Hello"
	case 2:
		return "Server Hello"
	case 11:
		return "Certificate"
	case 16:
		return "Client Key Exchange"
	}
	return "Type " + strconv.Itoa(int(t))
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS 1.0 (0x0301)"
	case 0x0302:
		return "TLS 1.1 (0x0302)"
	case 0x0303:
		return "TLS 1.2 (0x0303)"
	case 0x0304:
		return "TLS 1.3 (0x0304)"
	}
	return fmt.Sprintf("0x%04x", v)
}

// ---------------------------------------------------------------- HTTP/MQTT

func looksLikeHTTPRequest(p []byte) bool {
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "} {
		if len(p) >= len(m) && string(p[:len(m)]) == m {
			return true
		}
	}
	return false
}

func looksLikeHTTPResponse(p []byte) bool {
	return len(p) >= 5 && string(p[:5]) == "HTTP/"
}

func dissectHTTP(r *Result, b []byte, off int) {
	p := b[off:]
	r.proto("http")
	r.Proto = "HTTP"

	text := string(p)
	lines := strings.Split(text, "\r\n")
	n := node("Hypertext Transfer Protocol", off, len(p))

	if len(lines) > 0 {
		r.leaf(n, "Request Line", "http.request.line", lines[0], off, len(lines[0]))
		fields := strings.Fields(lines[0])
		if looksLikeHTTPRequest(p) && len(fields) >= 2 {
			r.set("http.request.method", fields[0])
			r.set("http.request.uri", fields[1])
			r.Info = fields[0] + " " + fields[1]
		} else if looksLikeHTTPResponse(p) && len(fields) >= 2 {
			r.set("http.response.code", fields[1])
			r.Info = "HTTP " + strings.Join(fields[1:], " ")
		}
	}
	pos := 0
	for _, line := range lines[1:] {
		pos += len(line) + 2
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		r.leaf(n, k, "http."+strings.ToLower(strings.ReplaceAll(k, "-", "_")), v, off+pos, len(line))
		switch strings.ToLower(k) {
		case "host":
			r.set("http.host", v)
			r.Domains = append(r.Domains, v)
			if r.Info != "" {
				r.Info += " (" + v + ")"
			}
		case "user-agent":
			// The UA is a first-class fingerprinting signal for the asset
			// database (F1), so it gets its own filterable field.
			r.set("http.user_agent", v)
		}
	}
	r.layer(n, "http")
}

// ------------------------------------------------------------------- SIP

// sipRequestMethods are every method RFC 3261 and its extensions define.
// "OPTIONS" is deliberately included even though HTTP has a same-named verb
// — looksLikeSIPRequest disambiguates by also requiring the line's own
// trailing " SIP/2.0", which an HTTP request line never has.
var sipRequestMethods = []string{
	"INVITE ", "ACK ", "BYE ", "CANCEL ", "REGISTER ", "OPTIONS ", "PRACK ",
	"SUBSCRIBE ", "NOTIFY ", "PUBLISH ", "INFO ", "REFER ", "MESSAGE ", "UPDATE ",
}

func firstLine(p []byte) string {
	line := p
	if i := bytes.IndexByte(p, '\n'); i >= 0 {
		line = p[:i]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
	} else if len(line) > 256 {
		// No line break at all inside a reasonable prefix means this is not
		// text framed the way SIP/HTTP/SSDP are — cap what gets turned into
		// a string rather than stringifying an entire binary payload.
		line = line[:256]
	}
	return string(line)
}

func looksLikeSIPRequest(p []byte) bool {
	line := firstLine(p)
	for _, m := range sipRequestMethods {
		if strings.HasPrefix(line, m) {
			return strings.HasSuffix(line, "SIP/2.0")
		}
	}
	return false
}

func looksLikeSIPResponse(p []byte) bool {
	return len(p) >= 8 && string(p[:8]) == "SIP/2.0 "
}

// sipCompactHeaders expands the single-letter forms RFC 3261 §7.3.3 allows
// (common on the wire since every byte matters on a constrained signaling
// link) to their canonical names, so "f:" and "From:" land in the same
// filterable field instead of silently splitting a call's headers in two.
var sipCompactHeaders = map[string]string{
	"f": "From", "t": "To", "i": "Call-ID", "m": "Contact",
	"l": "Content-Length", "c": "Content-Type", "v": "Via",
	"k": "Supported", "s": "Subject", "e": "Content-Encoding",
}

func sipHeaderName(k string) string {
	if full, ok := sipCompactHeaders[strings.ToLower(k)]; ok {
		return full
	}
	return k
}

// dissectSIP parses RFC 3261's request/status line and headers — the same
// CRLF-delimited, "Name: value" text shape as HTTP (SIP was deliberately
// modeled on it), just with call-signaling semantics: an INVITE/BYE/REGISTER
// method line rather than a GET/POST one, and From/To/Call-ID/CSeq in place
// of Host/User-Agent as the fields that actually identify a call. No SDP
// body parsing (the media negotiation carried in a body after the headers)
// — that is a second, unrelated grammar, and the signaling metadata here is
// what a network view like this one needs.
func dissectSIP(r *Result, b []byte, off int) {
	p := b[off:]
	r.proto("sip")
	r.Proto = "SIP"

	lines := strings.Split(string(p), "\r\n")
	n := node("Session Initiation Protocol", off, len(p))

	// A request line already names its own method ("INVITE sip:…"); only a
	// status line ("200 OK") is missing it, which is why CSeq's method gets
	// folded into Info below for responses only — doing it unconditionally
	// left a request reading "INVITE sip:… (INVITE)".
	isResponse := false
	if len(lines) > 0 {
		r.leaf(n, "Request/Status Line", "sip.line", lines[0], off, len(lines[0]))
		fields := strings.Fields(lines[0])
		switch {
		case looksLikeSIPRequest(p) && len(fields) >= 2:
			r.set("sip.method", fields[0])
			r.set("sip.request_uri", fields[1])
			r.Info = fields[0] + " " + fields[1]
		case looksLikeSIPResponse(p) && len(fields) >= 2:
			isResponse = true
			r.set("sip.status_code", fields[1])
			r.Info = "Status: " + strings.Join(fields[1:], " ")
		}
	}

	pos := 0
	for _, line := range lines[1:] {
		pos += len(line) + 2
		if line == "" {
			break // the blank line separating headers from any SDP body
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name := sipHeaderName(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		field := "sip." + strings.ToLower(strings.ReplaceAll(name, "-", "_"))
		r.leaf(n, name, field, v, off+pos, len(line))

		switch strings.ToLower(name) {
		case "from":
			r.set("sip.from", v)
		case "to":
			r.set("sip.to", v)
		case "call-id":
			r.set("sip.call_id", v)
		case "via":
			r.set("sip.via", v)
		case "contact":
			r.set("sip.contact", v)
		case "user-agent":
			r.set("sip.user_agent", v)
		case "cseq":
			r.set("sip.cseq", v)
			if _, method, ok := strings.Cut(v, " "); ok {
				r.set("sip.cseq.method", method)
				if isResponse && r.Info != "" {
					r.Info += " (" + method + ")"
				}
			}
		}
	}
	r.layer(n, "sip")
}

// ------------------------------------------------------------------- GTP

// dissectGTP parses a GTPv1 header (3GPP TS 29.060 §6) and, for a G-PDU
// (message type 255 — the one carrying an actual tunneled packet rather
// than tunnel-management signaling), recurses into the IPv4/IPv6 packet it
// wraps exactly the way dissectRawLink does for a headerless capture: there
// is no further framing to strip, just an IP version nibble to read.
//
// That recursive call is what makes the inner packet's own protocol (TLS,
// HTTP, SIP, whatever the phone was actually doing) end up as this frame's
// reported Proto/Info/Src/Dst — "gtp" stays in the protocol list (r.proto
// only appends, never replaces) so `gtp` alone still finds every tunneled
// frame, but the fields that matter for "what is this device talking to"
// describe the phone's own conversation, not the two core-network relay
// addresses the outer IP header names.
func dissectGTP(r *Result, b []byte, off int) {
	p := b[off:]
	if len(p) < 8 {
		return
	}
	flags := p[0]
	version := (flags >> 5) & 0x07
	msgType := p[1]
	teid := binary.BigEndian.Uint32(p[4:8])

	r.proto("gtp")
	r.Proto = "GTP"
	r.set("gtp.version", strconv.Itoa(int(version)))
	r.set("gtp.message_type", strconv.Itoa(int(msgType)))
	r.set("gtp.teid", fmt.Sprintf("0x%08x", teid))

	hdrLen := 8
	// Sequence Number / N-PDU Number / Next Extension Header Type — present
	// as one 4-octet block whenever any of the E/S/PN flag bits are set,
	// even though only the bit's own sub-field is meaningful.
	if flags&0x07 != 0 {
		hdrLen += 4
		if flags&0x04 != 0 && off+hdrLen <= len(b) { // E bit: extension headers follow
			pos := hdrLen
			for off+pos < len(b) {
				extLen := int(p[pos]) * 4 // length is in 4-octet units, self-inclusive
				if extLen == 0 || pos+extLen > len(p) {
					break
				}
				nextType := p[pos+extLen-1] // last octet of the block names the next one
				pos += extLen
				if nextType == 0 {
					break
				}
			}
			hdrLen = pos
		}
	}

	n := node(fmt.Sprintf("GPRS Tunneling Protocol, TEID: 0x%08x", teid), off, min(hdrLen, len(p)))
	r.leaf(n, "Version", "gtp.version", strconv.Itoa(int(version)), off, 1)
	r.leaf(n, "Message Type: "+gtpMessageTypeName(msgType), "gtp.message_type", strconv.Itoa(int(msgType)), off+1, 1)
	r.leaf(n, "TEID", "gtp.teid", fmt.Sprintf("0x%08x", teid), off+4, 4)
	r.layer(n, "gtp")

	if msgType != 0xff {
		r.Info = "GTP " + gtpMessageTypeName(msgType)
		return
	}
	inner := off + hdrLen
	if inner >= len(b) {
		r.Info = "GTP G-PDU (empty)"
		return
	}
	switch b[inner] >> 4 {
	case 4:
		dissectIPv4(r, b, inner)
	case 6:
		dissectIPv6(r, b, inner)
	default:
		r.Info = "GTP G-PDU"
	}
}

func gtpMessageTypeName(t uint8) string {
	switch t {
	case 1:
		return "Echo Request"
	case 2:
		return "Echo Response"
	case 16:
		return "Create PDP Context Request"
	case 17:
		return "Create PDP Context Response"
	case 18:
		return "Update PDP Context Request"
	case 19:
		return "Update PDP Context Response"
	case 20:
		return "Delete PDP Context Request"
	case 21:
		return "Delete PDP Context Response"
	case 26:
		return "Error Indication"
	case 31:
		return "Supported Extension Headers Notification"
	case 255:
		return "G-PDU"
	}
	return fmt.Sprintf("type %d", t)
}

func dissectMQTT(r *Result, b []byte, off int) {
	p := b[off:]
	if len(p) < 2 {
		return
	}
	r.proto("mqtt")
	r.Proto = "MQTT"
	msgType := p[0] >> 4
	n := node("MQ Telemetry Transport Protocol, "+mqttType(msgType), off, len(p))
	r.leaf(n, "Message Type: "+mqttType(msgType), "mqtt.msgtype", strconv.Itoa(int(msgType)), off, 1)
	r.set("mqtt.msgtype", strconv.Itoa(int(msgType)))
	r.Info = "MQTT " + mqttType(msgType)

	if msgType == 1 && len(p) > 12 { // CONNECT
		// variable header: protocol name, level, flags, keepalive, client id
		q := 2
		if q+2 <= len(p) {
			nameLen := int(binary.BigEndian.Uint16(p[q : q+2]))
			q += 2 + nameLen
			if q+4 <= len(p) {
				q += 4 // level + flags + keepalive
				if q+2 <= len(p) {
					idLen := int(binary.BigEndian.Uint16(p[q : q+2]))
					if q+2+idLen <= len(p) {
						id := string(p[q+2 : q+2+idLen])
						r.leaf(n, "Client ID", "mqtt.clientid", id, off+q+2, idLen)
						r.set("mqtt.clientid", id)
						r.Info = "MQTT Connect Command (client=" + id + ")"
					}
				}
			}
		}
	}
	r.layer(n, "mqtt")
}

func mqttType(t uint8) string {
	names := []string{"Reserved", "Connect Command", "Connect Ack", "Publish Message",
		"Publish Ack", "Publish Received", "Publish Release", "Publish Complete",
		"Subscribe Request", "Subscribe Ack", "Unsubscribe Request", "Unsubscribe Ack",
		"Ping Request", "Ping Response", "Disconnect Req", "Reserved"}
	if int(t) < len(names) {
		return names[t]
	}
	return "Type " + strconv.Itoa(int(t))
}

// ---------------------------------------------------------------- SSDP/DHCP

func dissectSSDP(r *Result, b []byte, off int) {
	p := b[off:]
	r.proto("ssdp")
	r.Proto = "SSDP"
	lines := strings.Split(string(p), "\r\n")
	n := node("Simple Service Discovery Protocol", off, len(p))
	if len(lines) > 0 {
		r.leaf(n, "Request Line", "ssdp.line", lines[0], off, len(lines[0]))
		r.Info = lines[0]
	}
	for _, line := range lines[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			r.leaf(n, k, "ssdp."+strings.ToLower(k), v, off, len(line))
			if strings.EqualFold(k, "SERVER") || strings.EqualFold(k, "ST") {
				r.set("ssdp."+strings.ToLower(k), v)
			}
		}
	}
	r.layer(n, "ssdp")
}

func dissectDHCP(r *Result, b []byte, off int) {
	p := b[off:]
	if len(p) < 240 {
		return
	}
	r.proto("dhcp")
	r.Proto = "DHCP"
	clientMAC := net.HardwareAddr(p[28:34])
	n := node("Dynamic Host Configuration Protocol", off, len(p))
	r.leaf(n, "Client MAC address", "dhcp.hw.mac_addr", clientMAC.String(), off+28, 6)
	r.set("dhcp.hw.mac_addr", clientMAC.String())

	// Options start after the 4-byte magic cookie at 236.
	q := 240
	msgType := ""
	for q+2 <= len(p) {
		code := p[q]
		if code == 255 {
			break
		}
		if code == 0 {
			q++
			continue
		}
		l := int(p[q+1])
		if q+2+l > len(p) {
			break
		}
		val := p[q+2 : q+2+l]
		switch code {
		case 53: // message type
			if l == 1 {
				msgType = dhcpMsgType(val[0])
				r.leaf(n, "DHCP Message Type", "dhcp.option.dhcp", msgType, off+q, 2+l)
				r.set("dhcp.option.dhcp", msgType)
			}
		case 12: // host name
			r.leaf(n, "Host Name", "dhcp.option.hostname", string(val), off+q, 2+l)
			r.set("dhcp.option.hostname", string(val))
		case 55: // parameter request list — the DHCP fingerprint (F1, §3.5.2)
			nums := make([]string, len(val))
			for i, v := range val {
				nums[i] = strconv.Itoa(int(v))
			}
			fp := strings.Join(nums, ",")
			r.leaf(n, "Parameter Request List", "dhcp.option.request_list_item", fp, off+q, 2+l)
			r.set("dhcp.option.request_list_item", fp)
		case 60: // vendor class identifier — also a fingerprint input
			r.leaf(n, "Vendor class identifier", "dhcp.option.vendor_class_id", string(val), off+q, 2+l)
			r.set("dhcp.option.vendor_class_id", string(val))
		}
		q += 2 + l
	}
	if msgType != "" {
		r.Info = "DHCP " + msgType + " - Transaction ID 0x" +
			fmt.Sprintf("%08x", binary.BigEndian.Uint32(p[4:8]))
	}
	r.layer(n, "dhcp")
}

func dhcpMsgType(t uint8) string {
	names := map[uint8]string{1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
		5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
	if n, ok := names[t]; ok {
		return n
	}
	return strconv.Itoa(int(t))
}

// ----------------------------------------------------------------------CoAP

// dissectCoAP parses RFC 7252 §3: a 4-byte fixed header, an optional token, a
// run of delta-encoded options terminated by 0xFF, and payload. IoT devices
// (sensors, actuators) that don't speak MQTT/HTTP commonly speak this instead.
func dissectCoAP(r *Result, b []byte, off int) {
	p := b[off:]
	r.proto("coap")
	r.Proto = "CoAP"
	if len(p) < 4 {
		r.Info = "CoAP (truncated)"
		return
	}
	ver := p[0] >> 6
	typ := (p[0] >> 4) & 0x3
	tkl := p[0] & 0x0F
	code := p[1]
	msgID := binary.BigEndian.Uint16(p[2:4])

	n := node("Constrained Application Protocol", off, len(p))
	r.leaf(n, "Version", "coap.version", strconv.Itoa(int(ver)), off, 1)
	r.leaf(n, "Type", "coap.type", coapType(typ), off, 1)
	r.leaf(n, "Code: "+coapCode(code), "coap.code", coapCodeStr(code), off+1, 1)
	r.leaf(n, "Message ID", "coap.mid", strconv.Itoa(int(msgID)), off+2, 2)
	r.set("coap.code", coapCodeStr(code))
	r.set("coap.type", coapType(typ))

	q := 4
	var token string
	if int(tkl) <= 8 && q+int(tkl) <= len(p) {
		token = fmt.Sprintf("%x", p[q:q+int(tkl)])
		if tkl > 0 {
			r.leaf(n, "Token", "coap.token", token, off+q, int(tkl))
			r.set("coap.token", token)
		}
		q += int(tkl)
	}

	// Options: each starts with a byte of (delta<<4)|length nibbles; 13/14
	// mean "read one/two more extension bytes"; 15 in either nibble is
	// reserved (option end marker only appears as the standalone 0xFF).
	var uriPath []string
	var uriQuery []string
	optNum := 0
	for q < len(p) && p[q] != 0xFF {
		nibble := p[q]
		deltaNib := int(nibble >> 4)
		lenNib := int(nibble & 0x0F)
		q++
		delta, ok := coapExt(p, &q, deltaNib)
		if !ok {
			break
		}
		length, ok := coapExt(p, &q, lenNib)
		if !ok || q+length > len(p) {
			break
		}
		optNum += delta
		val := p[q : q+length]
		name := coapOptionName(optNum)
		switch optNum {
		case 11: // Uri-Path
			uriPath = append(uriPath, string(val))
			r.leaf(n, name, "coap.opt.uri_path", string(val), off+q, length)
		case 15: // Uri-Query
			uriQuery = append(uriQuery, string(val))
			r.leaf(n, name, "coap.opt.uri_query", string(val), off+q, length)
		case 12: // Content-Format
			cf := 0
			for _, bb := range val {
				cf = cf<<8 | int(bb)
			}
			r.leaf(n, name, "coap.opt.content_format", coapContentFormat(cf), off+q, length)
			r.set("coap.opt.content_format", coapContentFormat(cf))
		case 6: // Observe
			obs := 0
			for _, bb := range val {
				obs = obs<<8 | int(bb)
			}
			r.leaf(n, name, "coap.opt.observe", strconv.Itoa(obs), off+q, length)
		case 3: // Uri-Host
			r.leaf(n, name, "coap.opt.uri_host", string(val), off+q, length)
			r.Domains = append(r.Domains, string(val))
		default:
			r.leaf(n, fmt.Sprintf("Option %d", optNum), "coap.opt.unknown", fmt.Sprintf("%d bytes", length), off+q, length)
		}
		q += length
	}
	if len(uriPath) > 0 {
		path := "/" + strings.Join(uriPath, "/")
		r.set("coap.opt.uri_path_full", path)
		r.Info = coapCode(code) + " /" + strings.Join(uriPath, "/")
		if len(uriQuery) > 0 {
			r.Info += "?" + strings.Join(uriQuery, "&")
		}
	} else {
		r.Info = coapCode(code)
	}
	if typ == 2 || typ == 3 { // ACK / RST carry the exchange's message ID, not a fresh request
		r.Info += fmt.Sprintf(" MID:%d", msgID)
	}
	r.layer(n, "coap")
}

// coapExt resolves a 4-bit option delta/length nibble to its real value,
// consuming 0, 1 or 2 extension bytes from p as RFC 7252 §3.1 specifies.
func coapExt(p []byte, q *int, nibble int) (int, bool) {
	switch nibble {
	case 13:
		if *q >= len(p) {
			return 0, false
		}
		v := int(p[*q]) + 13
		*q++
		return v, true
	case 14:
		if *q+1 >= len(p) {
			return 0, false
		}
		v := int(binary.BigEndian.Uint16(p[*q:*q+2])) + 269
		*q += 2
		return v, true
	case 15:
		return 0, false // reserved for the payload marker, not a valid option nibble
	default:
		return nibble, true
	}
}

func coapType(t uint8) string {
	switch t {
	case 0:
		return "Confirmable"
	case 1:
		return "Non-confirmable"
	case 2:
		return "Acknowledgement"
	case 3:
		return "Reset"
	}
	return strconv.Itoa(int(t))
}

// coapCodeStr renders the wire code as CoAP's own "class.detail" notation,
// e.g. 0x01 -> "0.01", 0x45 -> "2.05".
func coapCodeStr(c uint8) string {
	return fmt.Sprintf("%d.%02d", c>>5, c&0x1F)
}

func coapCode(c uint8) string {
	if c>>5 == 0 { // class 0: request methods
		switch c {
		case 1:
			return "GET"
		case 2:
			return "POST"
		case 3:
			return "PUT"
		case 4:
			return "DELETE"
		case 5:
			return "FETCH"
		case 6:
			return "PATCH"
		case 7:
			return "iPATCH"
		case 0:
			return "Empty"
		}
		return coapCodeStr(c)
	}
	names := map[uint8]string{
		65: "2.01 Created", 66: "2.02 Deleted", 67: "2.03 Valid", 68: "2.04 Changed",
		69: "2.05 Content", 95: "2.31 Continue",
		128: "4.00 Bad Request", 129: "4.01 Unauthorized", 130: "4.02 Bad Option",
		131: "4.03 Forbidden", 132: "4.04 Not Found", 133: "4.05 Method Not Allowed",
		140: "4.12 Precondition Failed", 141: "4.13 Request Entity Too Large",
		143: "4.15 Unsupported Content-Format",
		160: "5.00 Internal Server Error", 161: "5.01 Not Implemented",
		162: "5.02 Bad Gateway", 163: "5.03 Service Unavailable",
		164: "5.04 Gateway Timeout", 165: "5.05 Proxying Not Supported",
	}
	if n, ok := names[c]; ok {
		return n
	}
	return coapCodeStr(c)
}

func coapOptionName(num int) string {
	names := map[int]string{
		1: "If-Match", 3: "Uri-Host", 4: "ETag", 5: "If-None-Match", 6: "Observe",
		7: "Uri-Port", 8: "Location-Path", 11: "Uri-Path", 12: "Content-Format",
		14: "Max-Age", 15: "Uri-Query", 17: "Accept", 20: "Location-Query",
		35: "Proxy-Uri", 39: "Proxy-Scheme", 60: "Size1",
	}
	if n, ok := names[num]; ok {
		return n
	}
	return fmt.Sprintf("Option %d", num)
}

func coapContentFormat(cf int) string {
	names := map[int]string{
		0: "text/plain", 40: "application/link-format", 41: "application/xml",
		42: "application/octet-stream", 47: "application/exi", 50: "application/json",
		60: "application/cbor",
	}
	if n, ok := names[cf]; ok {
		return n
	}
	return strconv.Itoa(cf)
}

// ------------------------------------------------------------------ helpers

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
