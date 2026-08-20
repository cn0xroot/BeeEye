package analyze

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"BeeEye/internal/live"
)

// writePcap builds an in-memory capture file out of frames, so the tests
// exercise the real reader rather than a stub.
func writePcap(frames [][]byte, start time.Time) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 262144)
	binary.LittleEndian.PutUint32(hdr[20:], 1) // Ethernet
	buf.Write(hdr)

	for i, f := range frames {
		ts := start.Add(time.Duration(i) * 100 * time.Millisecond)
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		buf.Write(rec)
		buf.Write(f)
	}
	return buf.Bytes()
}

var (
	clientMAC = net.HardwareAddr{0x3c, 0x84, 0x6a, 0x11, 0x00, 0x02}
	serverMAC = net.HardwareAddr{0x02, 0x42, 0xbe, 0xee, 0x00, 0x01}
	clientIP  = net.IPv4(192, 168, 1, 11)
	serverIP  = net.IPv4(203, 0, 113, 9)
)

func tcpFrame(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	return live.BuildEthernet(serverMAC, clientMAC, 0x0800,
		live.BuildIPv4(src, dst, 6, 64, 1,
			live.BuildTCP(sport, dport, 1, 1, live.TCPPsh|live.TCPAck, payload)))
}

func TestAnalyzeRejectsNonPcap(t *testing.T) {
	if _, err := Analyze(strings.NewReader("this is not a capture file"), "x.pcap", 26); err == nil {
		t.Error("accepted a file that is not a pcap")
	}
}

func TestAnalyzeBasicStatistics(t *testing.T) {
	frames := [][]byte{
		tcpFrame(clientIP, serverIP, 49152, 80, []byte("GET /index.html HTTP/1.1\r\nHost: example.net\r\nUser-Agent: curl/8.0\r\n\r\n")),
		tcpFrame(serverIP, clientIP, 80, 49152, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>")),
	}
	data := writePcap(frames, time.Unix(1700000000, 0))

	rep, err := Analyze(bytes.NewReader(data), "t.pcap", int64(len(data)))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if rep.Summary.Packets != 2 {
		t.Errorf("packets = %d, want 2", rep.Summary.Packets)
	}
	if rep.Summary.LinkType != "Ethernet" {
		t.Errorf("link type = %q", rep.Summary.LinkType)
	}
	if rep.Summary.UniqueIPs != 2 {
		t.Errorf("unique IPs = %d, want 2", rep.Summary.UniqueIPs)
	}
	if len(rep.Conversations) != 1 {
		t.Fatalf("conversations = %d, want 1 (both directions must fold together)", len(rep.Conversations))
	}
	if len(rep.HTTP) != 1 || rep.HTTP[0].Host != "example.net" {
		t.Errorf("http requests = %+v", rep.HTTP)
	}
	if len(rep.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(rep.Sessions))
	}
	if !strings.Contains(rep.Sessions[0].RequestPreview, "GET /index.html") {
		t.Errorf("request preview missing the request line: %q", rep.Sessions[0].RequestPreview)
	}
}

func TestExtractsPlaintextCredentials(t *testing.T) {
	cases := []struct {
		name                           string
		frames                         [][]byte
		wantUser, wantPass, wantMethod string
	}{
		{
			name: "ftp",
			frames: [][]byte{
				tcpFrame(serverIP, clientIP, 21, 50000, []byte("220 ProFTPD Server ready\r\n")),
				tcpFrame(clientIP, serverIP, 50000, 21, []byte("USER admin\r\nPASS hunter2\r\n")),
			},
			wantUser: "admin", wantPass: "hunter2", wantMethod: "ftp",
		},
		{
			name: "http basic",
			frames: [][]byte{
				tcpFrame(clientIP, serverIP, 50001, 80,
					[]byte("GET /admin HTTP/1.1\r\nHost: nas.local\r\nAuthorization: Basic YWRtaW46czNjcjN0\r\n\r\n")),
			},
			wantUser: "admin", wantPass: "s3cr3t", wantMethod: "http-basic",
		},
		{
			name: "http form post",
			frames: [][]byte{
				tcpFrame(clientIP, serverIP, 50002, 80,
					[]byte("POST /login HTTP/1.1\r\nHost: cam.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=root&password=admin%40123")),
			},
			wantUser: "root", wantPass: "admin@123", wantMethod: "http-form",
		},
		{
			name: "pop3",
			frames: [][]byte{
				tcpFrame(serverIP, clientIP, 110, 50003, []byte("+OK POP3 ready\r\n")),
				tcpFrame(clientIP, serverIP, 50003, 110, []byte("USER bob\r\nPASS letmein\r\n")),
			},
			wantUser: "bob", wantPass: "letmein", wantMethod: "pop3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := writePcap(tc.frames, time.Unix(1700000000, 0))
			rep, err := Analyze(bytes.NewReader(data), "c.pcap", int64(len(data)))
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(rep.Credentials) == 0 {
				t.Fatalf("no credentials extracted; sessions=%+v", rep.Sessions)
			}
			c := rep.Credentials[0]
			if c.Username != tc.wantUser || c.Password != tc.wantPass || c.Method != tc.wantMethod {
				t.Errorf("got %s/%s via %s, want %s/%s via %s",
					c.Username, c.Password, c.Method, tc.wantUser, tc.wantPass, tc.wantMethod)
			}
		})
	}
}

func TestCarvesExecutableDownload(t *testing.T) {
	// An ELF arriving over plain HTTP is the standard IoT botnet delivery step.
	body := append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01}, bytes.Repeat([]byte{0x90}, 512)...)
	resp := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"), body...)
	frames := [][]byte{
		tcpFrame(clientIP, serverIP, 50010, 80, []byte("GET /bins/mirai.arm7 HTTP/1.1\r\nHost: 203.0.113.9\r\n\r\n")),
		tcpFrame(serverIP, clientIP, 80, 50010, resp),
	}
	data := writePcap(frames, time.Unix(1700000000, 0))

	rep, err := Analyze(bytes.NewReader(data), "m.pcap", int64(len(data)))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(rep.Files) != 1 {
		t.Fatalf("carved %d files, want 1", len(rep.Files))
	}
	f := rep.Files[0]
	if !strings.HasSuffix(f.Filename, ".elf") {
		t.Errorf("filename = %q, want an .elf name from the magic number", f.Filename)
	}
	if f.Suspicious == "" {
		t.Error("an ELF download was not flagged as noteworthy")
	}
	if f.Size != len(body) {
		t.Errorf("size = %d, want %d", f.Size, len(body))
	}
	if len(f.SHA256) != 64 {
		t.Errorf("sha256 = %q", f.SHA256)
	}
}

func TestDetectsAttackPatterns(t *testing.T) {
	cases := []struct {
		name, request, wantKind string
	}{
		{"sqli", "GET /p?id=1' OR '1'='1 HTTP/1.1\r\nHost: a\r\n\r\n", "sqli"},
		{"xss", "GET /s?q=<script>alert(1)</script> HTTP/1.1\r\nHost: a\r\n\r\n", "xss"},
		{"traversal", "GET /../../etc/passwd HTTP/1.1\r\nHost: a\r\n\r\n", "traversal"},
		{"scanner", "GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: sqlmap/1.7\r\n\r\n", "scanner"},
		{"iot", "GET /setup.cgi?next_file=netgear.cfg&todo=telnetd HTTP/1.1\r\nHost: a\r\n\r\n", "iot_exploit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frames := [][]byte{tcpFrame(clientIP, serverIP, 50020, 80, []byte(tc.request))}
			data := writePcap(frames, time.Unix(1700000000, 0))
			rep, err := Analyze(bytes.NewReader(data), "a.pcap", int64(len(data)))
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			found := false
			for _, f := range rep.Findings {
				if f.Kind == tc.wantKind {
					found = true
					if !f.Heuristic {
						t.Error("a pattern match must be labeled heuristic, not stated as fact")
					}
					if f.Evidence == "" {
						t.Error("finding carries no evidence")
					}
				}
			}
			if !found {
				t.Errorf("no %s finding; got %+v", tc.wantKind, rep.Findings)
			}
		})
	}
}

func TestCleanTrafficProducesNoFindings(t *testing.T) {
	// The counterpart that matters: ordinary traffic must not be flagged.
	frames := [][]byte{
		tcpFrame(clientIP, serverIP, 50030, 80, []byte("GET /images/logo.png HTTP/1.1\r\nHost: example.net\r\nUser-Agent: Mozilla/5.0\r\n\r\n")),
		tcpFrame(serverIP, clientIP, 80, 50030, []byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n")),
	}
	data := writePcap(frames, time.Unix(1700000000, 0))
	rep, err := Analyze(bytes.NewReader(data), "clean.pcap", int64(len(data)))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for _, f := range rep.Findings {
		t.Errorf("false positive on clean traffic: %s — %s", f.Kind, f.Evidence)
	}
	if len(rep.Credentials) != 0 {
		t.Errorf("invented credentials from traffic with none: %+v", rep.Credentials)
	}
}

func TestTruncatedFileStillReports(t *testing.T) {
	frames := [][]byte{tcpFrame(clientIP, serverIP, 50040, 80, []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))}
	data := writePcap(frames, time.Unix(1700000000, 0))
	// Cut the file mid-record.
	rep, err := Analyze(bytes.NewReader(data[:len(data)-10]), "t.pcap", int64(len(data)))
	if err != nil {
		t.Fatalf("a truncated file should still yield a report: %v", err)
	}
	if len(rep.Warnings) == 0 {
		t.Error("truncation was not reported as a warning")
	}
}
