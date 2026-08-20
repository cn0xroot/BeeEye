// Package protocol identifies application-layer protocols and maps ports to
// service names (program.md §3.5.4 F23, §3.5.4 port map F24).
//
// Identification follows the priority order in §3.5.4:
//  1. plaintext parse result (passed in as a hint)
//  2. TLS ClientHello ALPN
//  3. known-port map (fallback)
//  4. heuristic (out of scope here) → "unknown"
package protocol

// portServiceMap is the default known-port → service table (§3.5.4). In the
// running system this is loaded from config/port-service-map.yaml so users can
// extend it with vendor-private ports without recompiling.
var portServiceMap = map[int]string{
	80:    "HTTP",
	443:   "HTTPS",
	22:    "SSH",
	53:    "DNS",
	1883:  "MQTT",
	8883:  "MQTT-TLS",
	5683:  "CoAP",
	5684:  "CoAP-DTLS",
	123:   "NTP",
	853:   "DoT",
	3389:  "RDP",
	445:   "SMB",
	23:    "Telnet",
	554:   "RTSP",
	8080:  "HTTP-Alt",
	1900:  "SSDP",
	5353:  "mDNS",
	67:    "DHCP",
	68:    "DHCP",
	9000:  "HTTP-Alt",
	37777: "Dahua-DVR",
}

// SetPortServiceMap replaces the built-in table (called after loading YAML).
func SetPortServiceMap(m map[int]string) {
	if len(m) > 0 {
		portServiceMap = m
	}
}

// ServiceName maps a port to a readable service, or "" if unknown (F24).
func ServiceName(port int) string {
	return portServiceMap[port]
}

// Identify resolves the application-layer protocol using the priority chain.
// plaintext: result of a plaintext parser ("" if none)
// alpn: ALPN value from a TLS ClientHello ("" if none)
// isTLS: whether a TLS handshake was seen on the flow
// dstPort: destination port for the known-port fallback
func Identify(plaintext, alpn string, isTLS bool, dstPort int) string {
	// 1. plaintext parse hit — highest confidence
	if plaintext != "" {
		return plaintext
	}
	// 2. ALPN from ClientHello
	switch alpn {
	case "h2":
		return "HTTP/2"
	case "http/1.1":
		return "HTTPS"
	case "h3":
		return "HTTP/3"
	}
	// 3. known-port fallback
	if svc := portServiceMap[dstPort]; svc != "" {
		return svc
	}
	if isTLS {
		return "TLS"
	}
	// 4. give up honestly rather than guess (§3.5.4)
	return "unknown"
}
