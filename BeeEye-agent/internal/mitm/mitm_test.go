package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestEndToEndDecryption is the real test for this package: a client that
// has "installed" the CA (trusts it as a root) makes an HTTPS request
// through the proxy to a real TLS origin server, and both (a) gets back the
// correct plaintext response and (b) the proxy recorded the decrypted
// exchange. This is the whole point of F45 — prove decryption actually
// round-trips, not just that the pieces compile.
func TestEndToEndDecryption(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/echo" {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Echo", "yes")
			w.Write(append([]byte("you said: "), body...))
			return
		}
		w.Write([]byte("hello from origin"))
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	p := New(ca, 10)
	// The origin's own cert is signed by httptest's throwaway CA, not a real
	// one — trust it explicitly so forward()'s upstream validation (which is
	// deliberately strict, no InsecureSkipVerify) has something real to
	// check against, same as it would against a real origin's real chain.
	originRoots := x509.NewCertPool()
	originRoots.AddCert(origin.Certificate())
	p.UpstreamRoots = originRoots
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	// The client trusts the proxy's CA and nothing else — a real end-to-end
	// check that the certificate chain the proxy presents actually verifies,
	// not just that a handshake happens with verification disabled.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.PEM()) {
		t.Fatal("failed to load CA PEM into pool")
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from origin" {
		t.Fatalf("unexpected body: %q", body)
	}

	resp2, err := client.Post(origin.URL+"/echo", "text/plain", strings.NewReader("ping"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body2) != "you said: ping" {
		t.Fatalf("unexpected echo body: %q", body2)
	}
	if resp2.Header.Get("X-Echo") != "yes" {
		t.Fatalf("origin response header lost in relay: %v", resp2.Header)
	}

	// p.store.put happens on the server goroutine right after it finishes
	// writing the response to the wire — a client can observe the completed
	// HTTP response a moment before that write lands, so polling briefly
	// here is correct, not a workaround for a real bug (verified: the count
	// is always 2 within a few milliseconds).
	exs := waitForExchanges(t, p, 2, time.Second)
	found := map[string]bool{}
	for _, s := range exs {
		if s.Host != originURL.Hostname() {
			t.Errorf("exchange host = %q, want %q", s.Host, originURL.Hostname())
		}
		found[s.Path] = true
	}
	if !found["/hello"] || !found["/echo"] {
		t.Fatalf("missing expected paths in recorded exchanges: %+v", exs)
	}

	full, ok := p.Exchange(exs[0].ID)
	if !ok {
		t.Fatal("Exchange lookup by id failed")
	}
	if full.StatusCode != 200 {
		t.Fatalf("recorded status = %d, want 200", full.StatusCode)
	}
}

// TestUntrustedClientFailsClosed verifies the core safety property: a client
// that has NOT installed this CA gets a certificate error, not a silent
// plaintext passthrough — the entire opt-in design hinges on this.
func TestUntrustedClientFailsClosed(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never be seen"))
	}))
	defer origin.Close()

	p := New(ca, 10)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	// Default transport: does NOT trust this proxy's CA — only the system
	// root pool, which of course never signed our freshly generated cert.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
		Timeout: 5 * time.Second,
	}

	_, err = client.Get(origin.URL + "/hello")
	if err == nil {
		t.Fatal("expected a certificate verification error, got nil")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Fatalf("expected a certificate-related error, got: %v", err)
	}
}

// TestPlainHTTPRejected checks the documented scope boundary: a non-CONNECT
// request gets a clear 400, not a silent proxy-through.
func TestPlainHTTPRejected(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	p := New(ca, 10)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 400") {
		t.Fatalf("expected 400 response, got: %q", buf[:n])
	}
}

// TestMobileConfigEmbedsRealCert parses the generated .mobileconfig as XML
// and checks the embedded certificate data actually decodes back to this
// CA's real DER bytes — the thing that would silently break if the base64
// wrapping or plist escaping were ever wrong, without any XML-level error.
func TestMobileConfigEmbedsRealCert(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	raw := ca.MobileConfig()

	var doc struct {
		XMLName xml.Name `xml:"plist"`
		Dict    struct {
			Array struct {
				Dict struct {
					Data string `xml:"data"`
				} `xml:"dict"`
			} `xml:"array"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("mobileconfig is not well-formed XML: %v\n---\n%s", err, raw)
	}

	certB64 := strings.Join(strings.Fields(doc.Dict.Array.Dict.Data), "")
	decoded, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		t.Fatalf("embedded PayloadContent is not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, ca.cert.Raw) {
		t.Fatalf("embedded cert does not match CA.cert.Raw (lengths %d vs %d)", len(decoded), len(ca.cert.Raw))
	}

	if !strings.Contains(string(raw), "enable full trust") {
		t.Fatal("mobileconfig description dropped the manual full-trust instruction")
	}
}

// waitForExchanges polls until the store holds at least n exchanges or
// timeout elapses, failing the test in the latter case. See the call site's
// comment for why this is a real race to poll for, not a bug being masked.
func waitForExchanges(t *testing.T, p *Proxy, n int, timeout time.Duration) []Summary {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		exs := p.Exchanges(0)
		if len(exs) >= n {
			return exs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d recorded exchanges, got %d", n, len(exs))
		}
		time.Sleep(2 * time.Millisecond)
	}
}
