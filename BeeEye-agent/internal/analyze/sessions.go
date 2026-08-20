package analyze

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"BeeEye/internal/dissect"
)

// Session is one reconstructed conversation with its payload.
type Session struct {
	ID         string    `json:"id"`
	Transport  string    `json:"transport"`
	App        string    `json:"app"`
	Client     string    `json:"client"`
	ClientPort int       `json:"client_port"`
	Server     string    `json:"server"`
	ServerPort int       `json:"server_port"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	Packets    int       `json:"packets"`
	BytesC2S   int64     `json:"bytes_c2s"`
	BytesS2C   int64     `json:"bytes_s2c"`
	// Previews are capped text renderings of each direction. Binary bytes are
	// shown as dots, the same convention as a hex viewer's ASCII column.
	RequestPreview  string `json:"request_preview"`
	ResponsePreview string `json:"response_preview"`
	AuthFailures    int    `json:"auth_failures"`
}

// Credential is a plaintext secret observed on the wire.
//
// Passwords are reported in full deliberately: the point of this report is to
// show the owner exactly what a passive observer on their own network could
// have read. A masked value would understate the exposure.
type Credential struct {
	SessionID string    `json:"session_id"`
	TS        time.Time `json:"ts"`
	Protocol  string    `json:"protocol"`
	Method    string    `json:"method"`
	Client    string    `json:"client"`
	Server    string    `json:"server"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Evidence  string    `json:"evidence"`
}

// CarvedFile is a file reconstructed out of a session's payload.
type CarvedFile struct {
	ID          string `json:"id"`
	SessionID   string `json:"session_id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
	SHA256      string `json:"sha256"`
	Source      string `json:"source"`
	Suspicious  string `json:"suspicious,omitempty"`
	Data        []byte `json:"-"`
}

// Finding is a security observation.
type Finding struct {
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"` // high | medium | low | info
	Title     string    `json:"title"`
	Client    string    `json:"client"`
	Server    string    `json:"server"`
	TS        time.Time `json:"ts"`
	Evidence  string    `json:"evidence"`
	SessionID string    `json:"session_id,omitempty"`
	// Heuristic marks a pattern match rather than a proven fact, so a reader
	// weighs it accordingly instead of treating it as a verdict.
	Heuristic bool `json:"heuristic"`
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// maxStreamBytes caps how much payload is retained per direction. A full
// reassembly of a large download would dwarf the report; the head of a stream
// is where the protocol, the credentials and the file headers live.
const maxStreamBytes = 512 << 10

type stream struct {
	id                     string
	transport              string
	client, server         string
	clientPort, serverPort int
	first, last            time.Time
	packets                int
	c2s, s2c               []byte
	c2sBytes, s2cBytes     int64
	app                    string
}

type streamTable struct {
	streams map[string]*stream
	order   []string
}

func newStreamTable() *streamTable {
	return &streamTable{streams: map[string]*stream{}}
}

func (t *streamTable) add(r *dissect.Result) {
	if r.Transport == "" || len(r.Raw) == 0 {
		return
	}
	payload := appPayload(r)
	key, clientFirst := streamKey(r)

	s := t.streams[key]
	if s == nil {
		client, server := r.Src, r.Dst
		cp, sp := r.SrcPort, r.DstPort
		if !clientFirst {
			client, server = r.Dst, r.Src
			cp, sp = r.DstPort, r.SrcPort
		}
		s = &stream{
			id:        fmt.Sprintf("%s-%s.%d-%s.%d", r.Transport, client, cp, server, sp),
			transport: strings.ToUpper(r.Transport),
			client:    client, server: server,
			clientPort: cp, serverPort: sp,
			first: r.TS, app: r.Proto,
		}
		t.streams[key] = s
		t.order = append(t.order, key)
	}

	s.packets++
	s.last = r.TS
	if s.app == "TCP" || s.app == "UDP" || s.app == "unknown" {
		s.app = r.Proto
	}

	if len(payload) == 0 {
		return
	}
	if r.Src == s.client && r.SrcPort == s.clientPort {
		s.c2sBytes += int64(len(payload))
		if len(s.c2s) < maxStreamBytes {
			s.c2s = append(s.c2s, payload...)
		}
	} else {
		s.s2cBytes += int64(len(payload))
		if len(s.s2c) < maxStreamBytes {
			s.s2c = append(s.s2c, payload...)
		}
	}
}

// streamKey normalizes both directions onto one key and decides which endpoint
// is the client. The lower port is taken to be the server, which is right for
// the well-known services this report cares about; on a tie the addresses
// break it, so the choice is at least stable.
func streamKey(r *dissect.Result) (key string, srcIsClient bool) {
	a := fmt.Sprintf("%s:%d", r.Src, r.SrcPort)
	b := fmt.Sprintf("%s:%d", r.Dst, r.DstPort)
	srcIsClient = r.SrcPort > r.DstPort || (r.SrcPort == r.DstPort && a > b)
	if srcIsClient {
		return r.Transport + "|" + a + "|" + b, true
	}
	return r.Transport + "|" + b + "|" + a, false
}

// appPayload returns the bytes above the transport header.
func appPayload(r *dissect.Result) []byte {
	// The last layer's offset is where the application data starts; when the
	// dissector recognised an application protocol it created that layer, and
	// when it did not the transport layer's end serves the same purpose.
	if len(r.Layers) == 0 {
		return nil
	}
	last := r.Layers[len(r.Layers)-1]
	off := last.Offset
	switch last.Proto {
	case "tcp", "udp", "icmp", "icmpv6":
		off = last.Offset + last.Length
	}
	if off < 0 || off >= len(r.Raw) {
		return nil
	}
	return r.Raw[off:]
}

func (t *streamTable) finish() ([]Session, []Credential, []CarvedFile, []Finding) {
	var sessions []Session
	var creds []Credential
	var files []CarvedFile
	var findings []Finding

	for _, key := range t.order {
		s := t.streams[key]
		app := s.app
		if guessed := guessApp(s); guessed != "" {
			app = guessed
		}

		sess := Session{
			ID: s.id, Transport: s.transport, App: app,
			Client: s.client, ClientPort: s.clientPort,
			Server: s.server, ServerPort: s.serverPort,
			First: s.first, Last: s.last, Packets: s.packets,
			BytesC2S: s.c2sBytes, BytesS2C: s.s2cBytes,
			RequestPreview:  preview(s.c2s, 4096),
			ResponsePreview: preview(s.s2c, 4096),
		}

		c, failures := extractCredentials(s, app)
		sess.AuthFailures = failures
		creds = append(creds, c...)

		files = append(files, carveFiles(s)...)
		findings = append(findings, scanAttacks(s)...)

		sessions = append(sessions, sess)
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].BytesC2S+sessions[i].BytesS2C > sessions[j].BytesC2S+sessions[j].BytesS2C
	})
	return sessions, creds, files, findings
}

// guessApp names the application protocol from the payload when the per-packet
// dissection did not settle it — a session's first bytes are more informative
// than any single packet in isolation.
func guessApp(s *stream) string {
	head := string(firstN(s.s2c, 64))
	req := string(firstN(s.c2s, 64))
	switch {
	case strings.HasPrefix(head, "220 ") && strings.Contains(strings.ToUpper(head), "FTP"):
		return "FTP"
	case strings.HasPrefix(head, "220 ") && (s.serverPort == 25 || s.serverPort == 587):
		return "SMTP"
	case strings.HasPrefix(head, "+OK"):
		return "POP3"
	case strings.HasPrefix(head, "* OK"):
		return "IMAP"
	case strings.HasPrefix(head, "SSH-"):
		return "SSH"
	case s.serverPort == 23:
		return "Telnet"
	case strings.HasPrefix(req, "GET ") || strings.HasPrefix(req, "POST ") ||
		strings.HasPrefix(req, "HEAD ") || strings.HasPrefix(req, "PUT "):
		return "HTTP"
	}
	return ""
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// preview renders payload bytes as readable text, replacing anything
// unprintable with a dot so a binary body cannot corrupt the UI.
func preview(b []byte, limit int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > limit {
		b = b[:limit]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			out = append(out, c)
		case c >= 0x20 && c < 0x7f:
			out = append(out, c)
		default:
			out = append(out, '.')
		}
	}
	return string(out)
}

// ------------------------------------------------------------ credentials

var (
	reFTPUser   = regexp.MustCompile(`(?im)^USER\s+(.+)\r?$`)
	reFTPPass   = regexp.MustCompile(`(?im)^PASS\s+(.+)\r?$`)
	rePOPUser   = regexp.MustCompile(`(?im)^USER\s+(.+)\r?$`)
	rePOPPass   = regexp.MustCompile(`(?im)^PASS\s+(.+)\r?$`)
	reIMAPLogin = regexp.MustCompile(`(?im)^\S+\s+LOGIN\s+"?([^"\s]+)"?\s+"?([^"\r\n]+)"?\r?$`)
	reHTTPAuth  = regexp.MustCompile(`(?im)^Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)\r?$`)
	reHTTPBody  = regexp.MustCompile(`(?is)\r\n\r\n(.*)$`)
	reFormUser  = regexp.MustCompile(`(?i)(?:^|&)(user(?:name)?|login|email|account|uid)=([^&\s]+)`)
	reFormPass  = regexp.MustCompile(`(?i)(?:^|&)(pass(?:wo?r?d)?|pwd|passcode)=([^&\s]+)`)
	reSMTPAuth  = regexp.MustCompile(`(?im)^AUTH\s+LOGIN\s*\r?$`)
	reAuthFail  = regexp.MustCompile(`(?im)^(530|535|-ERR|NO |401 |403 )`)
)

// extractCredentials pulls plaintext secrets out of a session and counts
// authentication failures (which feeds brute-force detection).
func extractCredentials(s *stream, app string) ([]Credential, int) {
	c2s := string(s.c2s)
	s2c := string(s.s2c)
	var out []Credential

	mk := func(method, user, pass, evidence string) Credential {
		return Credential{
			SessionID: s.id, TS: s.first, Protocol: app, Method: method,
			Client: s.client, Server: s.server,
			Username: strings.TrimSpace(user), Password: strings.TrimSpace(pass),
			Evidence: strings.TrimSpace(evidence),
		}
	}

	switch app {
	case "FTP":
		u := reFTPUser.FindStringSubmatch(c2s)
		p := reFTPPass.FindStringSubmatch(c2s)
		if u != nil || p != nil {
			user, pass, ev := "", "", ""
			if u != nil {
				user, ev = u[1], u[0]
			}
			if p != nil {
				pass, ev = p[1], ev+" / "+p[0]
			}
			out = append(out, mk("ftp", user, pass, ev))
		}
	case "POP3":
		u := rePOPUser.FindStringSubmatch(c2s)
		p := rePOPPass.FindStringSubmatch(c2s)
		if u != nil && p != nil {
			out = append(out, mk("pop3", u[1], p[1], u[0]+" / "+p[0]))
		}
	case "IMAP":
		if m := reIMAPLogin.FindStringSubmatch(c2s); m != nil {
			out = append(out, mk("imap", m[1], m[2], m[0]))
		}
	case "SMTP":
		if reSMTPAuth.MatchString(c2s) {
			// AUTH LOGIN sends base64 username and password on the next lines.
			lines := splitLines(c2s)
			var vals []string
			for i, l := range lines {
				if strings.HasPrefix(strings.ToUpper(l), "AUTH LOGIN") {
					for j := i + 1; j < len(lines) && len(vals) < 2; j++ {
						if v, ok := decodeBase64Line(lines[j]); ok {
							vals = append(vals, v)
						}
					}
				}
			}
			if len(vals) == 2 {
				out = append(out, mk("smtp-auth-login", vals[0], vals[1], "AUTH LOGIN (base64)"))
			}
		}
	case "Telnet":
		// Telnet echoes character by character; the readable rendering is the
		// best available evidence, and it is labeled as such rather than being
		// presented as cleanly parsed fields.
		if txt := preview(s.c2s, 512); strings.TrimSpace(txt) != "" {
			out = append(out, mk("telnet", "", "", "keystrokes: "+strings.TrimSpace(txt)))
		}
	case "HTTP", "HTTP/2 (TLS)", "HTTPS":
		if m := reHTTPAuth.FindStringSubmatch(c2s); m != nil {
			if dec, ok := decodeBase64(m[1]); ok {
				user, pass, _ := strings.Cut(dec, ":")
				out = append(out, mk("http-basic", user, pass, m[0]))
			}
		}
		if m := reHTTPBody.FindStringSubmatch(c2s); m != nil {
			body := m[1]
			u := reFormUser.FindStringSubmatch(body)
			p := reFormPass.FindStringSubmatch(body)
			if u != nil && p != nil {
				user, _ := url.QueryUnescape(u[2])
				pass, _ := url.QueryUnescape(p[2])
				out = append(out, mk("http-form", user, pass, firstLine(body, 200)))
			}
		}
	}

	failures := len(reAuthFail.FindAllString(s2c, -1))
	return out, failures
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func firstLine(s string, limit int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return s
}

// ------------------------------------------------------------ file carving

// fileSignatures are magic numbers used to name a carved body when the HTTP
// headers did not. An .elf or a Windows executable arriving over plain HTTP to
// an IoT device is the classic Mirai-family delivery step (F39).
var fileSignatures = []struct {
	magic []byte
	ext   string
	note  string
}{
	{[]byte{0x7f, 'E', 'L', 'F'}, "elf", "ELF executable — the usual IoT botnet payload format"},
	{[]byte{'M', 'Z'}, "exe", "Windows executable"},
	{[]byte{0x89, 'P', 'N', 'G'}, "png", ""},
	{[]byte{0xff, 0xd8, 0xff}, "jpg", ""},
	{[]byte{'G', 'I', 'F', '8'}, "gif", ""},
	{[]byte{'%', 'P', 'D', 'F'}, "pdf", ""},
	{[]byte{'P', 'K', 0x03, 0x04}, "zip", ""},
	{[]byte{0x1f, 0x8b}, "gz", ""},
	{[]byte{'#', '!', '/'}, "sh", "shell script"},
}

var reContentType = regexp.MustCompile(`(?im)^Content-Type:\s*([^\r\n;]+)`)
var reDisposition = regexp.MustCompile(`(?im)^Content-Disposition:.*filename="?([^"\r\n;]+)"?`)

// carveFiles reconstructs transferred bodies out of a session.
func carveFiles(s *stream) []CarvedFile {
	if len(s.s2c) == 0 {
		return nil
	}
	head := string(firstN(s.s2c, 8192))
	if !strings.HasPrefix(head, "HTTP/") {
		return nil
	}
	idx := strings.Index(head, "\r\n\r\n")
	if idx < 0 {
		return nil
	}
	headers := head[:idx]
	body := s.s2c[idx+4:]
	if len(body) == 0 {
		return nil
	}

	f := CarvedFile{
		SessionID: s.id,
		Size:      len(body),
		Source:    "http",
		Data:      body,
	}
	if m := reContentType.FindStringSubmatch(headers); m != nil {
		f.ContentType = strings.TrimSpace(m[1])
	}
	if m := reDisposition.FindStringSubmatch(headers); m != nil {
		f.Filename = m[1]
	}

	for _, sig := range fileSignatures {
		if len(body) >= len(sig.magic) && string(body[:len(sig.magic)]) == string(sig.magic) {
			if f.Filename == "" {
				f.Filename = fmt.Sprintf("carved-%s.%s", shortHash(body), sig.ext)
			}
			f.Suspicious = sig.note
			break
		}
	}
	if f.Filename == "" {
		f.Filename = "carved-" + shortHash(body) + ".bin"
	}

	sum := sha256.Sum256(body)
	f.SHA256 = hex.EncodeToString(sum[:])
	f.ID = f.SHA256[:16]
	return []CarvedFile{f}
}

func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// ------------------------------------------------------- attack detection

// attackPatterns are heuristics, and every finding they produce says so. They
// match the shapes of common web attacks in request text; a match is a reason
// to look, not a conclusion that an attack succeeded.
var attackPatterns = []struct {
	kind, severity, title string
	re                    *regexp.Regexp
}{
	{"sqli", "high", "SQL injection pattern in request",
		regexp.MustCompile(`(?i)(union\s+(all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|;\s*drop\s+table|sleep\(\d+\)|benchmark\(|information_schema)`)},
	{"xss", "medium", "Cross-site scripting pattern in request",
		regexp.MustCompile(`(?i)(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=\s*["']?javascript)`)},
	{"traversal", "high", "Path traversal pattern in request",
		regexp.MustCompile(`(\.\./\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd|/etc/shadow|\\windows\\win\.ini)`)},
	{"cmdi", "high", "Command injection pattern in request",
		regexp.MustCompile(`(?i)(;\s*(cat|wget|curl|chmod|nc|sh|bash)\s|\|\s*(sh|bash)\b|\$\(.*\)|` + "`" + `.*` + "`" + `)`)},
	{"webshell", "high", "Webshell-like request",
		regexp.MustCompile(`(?i)(eval\s*\(\s*\$_(POST|GET|REQUEST)|c99shell|r57shell|/shell\.(php|jsp|asp)|cmd\.jsp)`)},
	{"scanner", "low", "Automated scanner user-agent",
		regexp.MustCompile(`(?i)User-Agent:.*(sqlmap|nikto|nmap|masscan|acunetix|nessus|zgrab|dirbuster|gobuster|wpscan)`)},
	{"iot_exploit", "high", "Known IoT exploit path",
		regexp.MustCompile(`(?i)(/shell\?|/cgi-bin/\.%2e/|\$\{jndi:|/HNAP1/|/setup\.cgi\?.*telnetd|/board\.cgi|/picsdesc\.xml)`)},
}

func scanAttacks(s *stream) []Finding {
	if len(s.c2s) == 0 {
		return nil
	}
	text := string(firstN(s.c2s, 64<<10))
	var out []Finding
	for _, p := range attackPatterns {
		if m := p.re.FindString(text); m != "" {
			out = append(out, Finding{
				Kind: p.kind, Severity: p.severity, Title: p.title,
				Client: s.client, Server: s.server, TS: s.first,
				Evidence: firstLine(m, 240), SessionID: s.id, Heuristic: true,
			})
		}
	}
	return out
}

// detectBruteForce flags a client that collected many authentication failures
// against one server. The threshold is intentionally not aggressive: a person
// mistyping a password three times must not become a security incident.
func detectBruteForce(sessions []Session) []Finding {
	type key struct{ client, server, app string }
	agg := map[key]*struct {
		failures int
		attempts int
		ts       time.Time
	}{}

	for _, s := range sessions {
		if s.AuthFailures == 0 {
			continue
		}
		k := key{s.Client, s.Server, s.App}
		e := agg[k]
		if e == nil {
			e = &struct {
				failures int
				attempts int
				ts       time.Time
			}{ts: s.First}
			agg[k] = e
		}
		e.failures += s.AuthFailures
		e.attempts++
	}

	var out []Finding
	for k, e := range agg {
		if e.failures < 8 {
			continue
		}
		out = append(out, Finding{
			Kind: "bruteforce", Severity: "high",
			Title:  "Repeated authentication failures — possible brute force",
			Client: k.client, Server: k.server, TS: e.ts,
			Evidence: fmt.Sprintf("%d failed %s authentications across %d sessions",
				e.failures, k.app, e.attempts),
			Heuristic: true,
		})
	}
	return out
}

// detectScanning flags a source that touched many distinct destination ports
// or hosts — the fan-out shape of a scan (§3.11.3).
func detectScanning(convs []Conversation) []Finding {
	ports := map[string]map[int]bool{}
	hosts := map[string]map[string]bool{}
	firstSeen := map[string]time.Time{}

	for _, c := range convs {
		if ports[c.A] == nil {
			ports[c.A] = map[int]bool{}
			hosts[c.A] = map[string]bool{}
			firstSeen[c.A] = c.First
		}
		ports[c.A][c.BPort] = true
		hosts[c.A][c.BPeer] = true
	}

	var out []Finding
	for src, p := range ports {
		switch {
		case len(p) >= 30:
			out = append(out, Finding{
				Kind: "portscan", Severity: "high",
				Title:  "Port scan — one source touched many ports",
				Client: src, TS: firstSeen[src],
				Evidence:  fmt.Sprintf("%d distinct destination ports across %d hosts", len(p), len(hosts[src])),
				Heuristic: true,
			})
		case len(hosts[src]) >= 25:
			out = append(out, Finding{
				Kind: "hostsweep", Severity: "medium",
				Title:  "Host sweep — one source contacted many hosts",
				Client: src, TS: firstSeen[src],
				Evidence:  fmt.Sprintf("%d distinct destination hosts", len(hosts[src])),
				Heuristic: true,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Client < out[j].Client })
	return out
}

// ------------------------------------------------------------------ base64

func decodeBase64(s string) (string, bool) {
	dec, err := base64Decode(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return string(dec), true
}

// decodeBase64Line accepts a line only if it decodes cleanly to printable
// text, which is what separates an AUTH LOGIN credential line from noise.
func decodeBase64Line(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if len(line) < 4 || len(line)%4 != 0 {
		return "", false
	}
	dec, err := base64Decode(line)
	if err != nil {
		return "", false
	}
	for _, c := range dec {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(dec), true
}
