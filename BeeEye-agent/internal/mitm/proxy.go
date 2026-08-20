package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	dialTimeout    = 10 * time.Second
	idleTimeout    = 60 * time.Second
	defaultTLSPort = "443"
)

// Proxy is an HTTP CONNECT proxy that terminates TLS with a certificate this
// CA just minted, decrypts one request/response pair at a time, forwards it
// to the real origin over a real (fully validated — no InsecureSkipVerify)
// TLS connection, and relays the response back unmodified except where the
// framing has to change (see relayResponse). It only understands CONNECT: a
// plain (non-TLS) request gets a 400 explaining why, because plain HTTP is
// already visible on the wire without any of this — decrypting HTTPS is the
// entire point of the feature.
type Proxy struct {
	ca    *CA
	store *exchangeStore

	// UpstreamRoots overrides the trust pool used to validate the real
	// origin's certificate. nil (the default, and what production always
	// runs with) means "the system root pool" — set only by tests, to trust
	// an httptest.Server's ephemeral CA instead of requiring a real one.
	UpstreamRoots *x509.CertPool

	mu     sync.Mutex
	ln     net.Listener
	closed bool
}

// New returns a proxy that will record at most maxExchanges decrypted
// request/response pairs (oldest evicted first); 0 uses a sane default.
func New(ca *CA, maxExchanges int) *Proxy {
	return &Proxy{ca: ca, store: newExchangeStore(maxExchanges)}
}

func (p *Proxy) CA() *CA { return p.ca }

// Exchanges returns the n most recent decrypted exchanges' summaries, newest
// first. n<=0 returns all of them.
func (p *Proxy) Exchanges(n int) []Summary { return p.store.list(n) }

// Exchange returns one full exchange (headers + captured body) by id.
func (p *Proxy) Exchange(id string) (*Exchange, bool) { return p.store.get(id) }

// Addr is the address the proxy is actually listening on, valid once
// ListenAndServe has started (e.g. useful when the configured port was 0).
func (p *Proxy) Addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// ListenAndServe accepts connections on addr until Close is called. Runs
// until then — call it from its own goroutine, matching every other
// long-running server in this codebase (main.go's http.ListenAndServe,
// live.WatchLinks's watch loop).
func (p *Proxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mitm: listen on %s: %w", addr, err)
	}
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("mitm: accept: %w", err)
		}
		go p.handleConn(conn)
	}
}

// Close stops accepting new connections. Connections already mid-flight are
// left to finish on their own.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	ln := p.ln
	p.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != http.MethodConnect {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"+
			"BeeEye MITM proxy only handles CONNECT (HTTPS). Point only HTTPS traffic, or the device's HTTPS proxy setting, here — plain HTTP needs no decryption to begin with.\n")
		return
	}

	clientAddr := conn.RemoteAddr().String()
	hostname, port := splitHostPort(req.Host, defaultTLSPort)

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			h := hello.ServerName
			if h == "" {
				h = hostname
			}
			return p.ca.IssueLeaf(h)
		},
	})
	// The handshake fails, silently from this proxy's point of view, for the
	// single most common reason: the device hasn't installed the root CA yet
	// and correctly refuses to trust the certificate we just presented. That
	// is the feature working as intended (fail closed), not an error to log.
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	p.serveDecrypted(tlsConn, hostname, port, clientAddr)
}

// serveDecrypted runs the decrypted request/response loop for one CONNECT
// tunnel. Each iteration forwards exactly one request upstream over a fresh
// TLS connection (no upstream connection pooling — simplicity over
// throughput, matching the scale this runs at: one household's devices, not
// a datacenter proxy) and relays the response back before reading the next
// pipelined/keep-alive request, if any.
func (p *Proxy) serveDecrypted(conn net.Conn, hostname, port, clientAddr string) {
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return // client closed the tunnel, or sent nothing more — normal
		}

		ex := &Exchange{
			Time: time.Now(), ClientAddr: clientAddr,
			Method: req.Method, Host: hostname, Path: pathOrRoot(req.URL.Path),
			ReqHeaders: req.Header.Clone(),
		}

		resp, upstream, reqBody, reqTrunc, err := p.forward(hostname, port, req)
		ex.ReqBody, ex.ReqTrunc = reqBody, reqTrunc
		if err != nil {
			ex.Err = err.Error()
			p.store.put(ex)
			io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"+err.Error()+"\n")
			return
		}

		ex.StatusCode = resp.StatusCode
		ex.RespHeaders = resp.Header.Clone()

		respBody, respTrunc, knownLength, werr := relayResponse(conn, resp)
		resp.Body.Close()
		upstream.Close()
		ex.RespBody, ex.RespTrunc = respBody, respTrunc
		p.store.put(ex)

		if werr != nil || !knownLength || req.Close {
			// !knownLength means the response had no Content-Length (chunked
			// or origin closed the connection to signal end-of-body) — we
			// already told the client Connection: close for that response,
			// so reusing this tunnel for another request would desync it.
			return
		}
	}
}

// forward sends req to the real origin over a freshly dialed, fully
// certificate-validated TLS connection and returns the parsed response. The
// caller owns closing both resp.Body and the returned connection. reqBody is
// a capped copy of what was actually sent — captured via TeeReader while the
// request streams to the origin, never by buffering it up front, so a large
// request body is neither corrupted nor fully buffered in memory.
func (p *Proxy) forward(hostname, port string, req *http.Request) (resp *http.Response, upstream net.Conn, reqBody []byte, reqTrunc bool, err error) {
	upstream, err = tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp",
		net.JoinHostPort(hostname, port), &tls.Config{ServerName: hostname, RootCAs: p.UpstreamRoots})
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("dial upstream %s: %w", net.JoinHostPort(hostname, port), err)
	}

	reqCap := &cappedBuffer{limit: maxBodyCapture}
	outReq := req.Clone(req.Context())
	outReq.URL.Scheme = ""
	outReq.URL.Host = ""
	outReq.Close = false
	if req.Body != nil {
		outReq.Body = io.NopCloser(io.TeeReader(req.Body, reqCap))
	}

	if err = outReq.Write(upstream); err != nil {
		upstream.Close()
		return nil, nil, reqCap.buf.Bytes(), reqCap.trunc, fmt.Errorf("write upstream request: %w", err)
	}

	resp, err = http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		upstream.Close()
		return nil, nil, reqCap.buf.Bytes(), reqCap.trunc, fmt.Errorf("read upstream response: %w", err)
	}
	return resp, upstream, reqCap.buf.Bytes(), reqCap.trunc, nil
}

// relayResponse writes resp back to the client conn, streaming the body
// through so a large response is never fully buffered — only up to
// maxBodyCapture bytes of it are kept (for the recorded Exchange), the wire
// relay itself is never truncated. When the origin gave a real
// Content-Length, that framing is preserved exactly and the tunnel can serve
// another request afterward (knownLength=true). Otherwise (chunked, or
// length signalled by connection close) the body is de-chunked and
// re-sent as an identity stream terminated by closing the connection —
// simpler and just as correct as re-chunking, at the cost of one request per
// tunnel in that case.
func relayResponse(conn net.Conn, resp *http.Response) (body []byte, trunc bool, knownLength bool, err error) {
	respCap := &cappedBuffer{limit: maxBodyCapture}
	knownLength = resp.ContentLength >= 0

	h := resp.Header.Clone()
	if knownLength {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		h.Del("Transfer-Encoding")
	} else {
		h.Del("Content-Length")
		h.Del("Transfer-Encoding")
		h.Set("Connection", "close")
	}

	statusText := http.StatusText(resp.StatusCode)
	if _, werr := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", resp.StatusCode, statusText); werr != nil {
		return nil, false, knownLength, werr
	}
	if werr := h.Write(conn); werr != nil {
		return nil, false, knownLength, werr
	}
	if _, werr := io.WriteString(conn, "\r\n"); werr != nil {
		return nil, false, knownLength, werr
	}

	mw := io.MultiWriter(conn, respCap)
	if _, werr := io.Copy(mw, resp.Body); werr != nil {
		return respCap.buf.Bytes(), respCap.trunc, knownLength, werr
	}
	return respCap.buf.Bytes(), respCap.trunc, knownLength, nil
}

// cappedBuffer accumulates up to limit bytes and silently drops the rest,
// flagging Trunc — it always reports every byte written as consumed (never
// errors), so it is safe as the side channel of an io.TeeReader or
// io.MultiWriter without disturbing the primary stream.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
	trunc bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	room := c.limit - c.buf.Len()
	if room > n {
		room = n
	}
	if room > 0 {
		c.buf.Write(p[:room])
	}
	if room < n {
		c.trunc = true
	}
	return n, nil
}

func pathOrRoot(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func splitHostPort(hostport, defaultPort string) (host, port string) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defaultPort
	}
	return h, p
}
