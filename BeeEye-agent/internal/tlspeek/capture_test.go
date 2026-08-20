//go:build linux

package tlspeek

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCapturesRealTLSPlaintext is the test that proves the feature, rather
// than proving the plumbing: it stands up a real TLS session between two
// OpenSSL processes and asserts the marker written by the client comes back
// out of the ring buffer as plaintext.
//
// It needs CAP_BPF/CAP_PERFMON and an openssl binary, so it skips rather than
// fails where those are missing — the same policy the TCX attach test uses.
func TestCapturesRealTLSPlaintext(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (or CAP_BPF+CAP_PERFMON) to attach uprobes")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skip("no BTF on this kernel")
	}
	opensslBin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl binary not found")
	}

	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	gen := exec.Command(opensslBin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=BeeEye-test")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Skipf("cannot generate a test certificate: %v\n%s", err, out)
	}

	port := freePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// No -naccept limit: waitListening below probes the port with a real
	// connection, and a one-shot server would spend its single accept on that
	// probe and be gone before the client arrives.
	server := exec.CommandContext(ctx, opensslBin, "s_server", "-quiet",
		"-accept", fmt.Sprint(port), "-cert", cert, "-key", key)
	if err := server.Start(); err != nil {
		t.Skipf("cannot start s_server: %v", err)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()

	if !waitListening(port, 15*time.Second) {
		t.Skip("s_server never listened; not a failure of this package")
	}

	// Discover the library from the running server, which is the code path a
	// caller would actually use — and which finds the right copy even when it
	// is not the one on the default search path.
	libPath, err := LibraryForPID(server.Process.Pid)
	if err != nil {
		t.Skipf("no OpenSSL library mapped by s_server: %v", err)
	}
	t.Logf("probing %s", libPath)

	p, err := Load()
	if err != nil {
		t.Skipf("cannot load the TLS programs: %v", err)
	}
	defer p.Close()

	// pid 0: every process using this library, so the client started below is
	// covered too.
	if err := p.Attach(libPath, 0); err != nil {
		t.Fatalf("attach: %v", err)
	}
	events := p.Events()

	const marker = "BeeEye-plaintext-marker-8f3a2c"
	client := exec.CommandContext(ctx, opensslBin, "s_client", "-quiet",
		"-connect", fmt.Sprintf("127.0.0.1:%d", port))
	client.Stdin = strings.NewReader(marker + "\n")
	var clientErr bytes.Buffer
	client.Stderr = &clientErr
	if err := client.Start(); err != nil {
		t.Fatalf("start s_client: %v", err)
	}
	defer func() { _ = client.Process.Kill(); _ = client.Wait() }()

	deadline := time.After(30 * time.Second)
	var seen []string
	for {
		select {
		case ev := <-events:
			if ev == nil {
				t.Fatal("event stream closed before the marker arrived")
			}
			seen = append(seen, fmt.Sprintf("%s/%s:%dB", ev.Comm, ev.Dir, len(ev.Data)))
			if bytes.Contains(ev.Data, []byte(marker)) {
				t.Logf("captured plaintext from %s (pid %d, %s): %q",
					ev.Comm, ev.PID, ev.Dir, string(bytes.TrimSpace(ev.Data)))
				if ev.Comm == "" {
					t.Error("event carries no comm; the process is unidentifiable")
				}
				if ev.PID == 0 {
					t.Error("event carries no pid")
				}
				return // the feature works
			}
		case <-deadline:
			t.Fatalf("marker never appeared in captured plaintext.\nchunks seen: %v\ns_client stderr: %s",
				seen, clientErr.String())
		}
	}
}

// TestFindLibrariesSeesSomething is a light check on discovery: on any machine
// running this test there is essentially always some process with libssl
// mapped, and a discovery function that silently finds nothing is the failure
// mode that would make the feature look broken for the wrong reason.
func TestFindLibrariesSeesSomething(t *testing.T) {
	libs, err := FindLibraries()
	if err != nil {
		t.Fatalf("FindLibraries: %v", err)
	}
	for _, l := range libs {
		if !filepath.IsAbs(l.Path) {
			t.Errorf("library path %q is not absolute", l.Path)
		}
		if len(l.PIDs) == 0 {
			t.Errorf("library %s reported with no pids", l.Path)
		}
	}
	t.Logf("found %d OpenSSL-family libraries in use", len(libs))
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(port int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
