//go:build linux

package tlspeek

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Library is one TLS implementation found mapped into a live process.
type Library struct {
	Path   string // absolute path as the kernel sees it
	Family string // which rule matched: "OpenSSL", "GnuTLS", …
	PIDs   []int  // processes with it mapped
}

// FindLibraries reports the OpenSSL-family libraries currently mapped by
// running processes, newest-busiest first.
//
// Scanning /proc rather than trusting a configured path matters because a
// process can be running against a library that is no longer the one on the
// default search path — an upgrade with the old file still open, a container
// with its own copy, an application shipping its own build.
func FindLibraries() ([]Library, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("tlspeek: read /proc: %w", err)
	}
	byPath := map[string]map[int]bool{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		for _, p := range mappedSSL(pid) {
			if byPath[p] == nil {
				byPath[p] = map[int]bool{}
			}
			byPath[p][pid] = true
		}
	}
	out := make([]Library, 0, len(byPath))
	for p, pids := range byPath {
		l := Library{Path: p}
		if r := matchRule(p); r != nil {
			l.Family = r.Name
		}
		for pid := range pids {
			l.PIDs = append(l.PIDs, pid)
		}
		sort.Ints(l.PIDs)
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].PIDs) != len(out[j].PIDs) {
			return len(out[i].PIDs) > len(out[j].PIDs)
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// ScanPathBinaries finds OpenSSL-family libraries by resolving the dynamic
// dependencies of every executable on $PATH, rather than waiting to see one
// mapped by a running process.
//
// This exists because FindLibraries has a real blind spot: it only sees
// libraries in use at the instant it runs, so a command that finishes in
// milliseconds (curl, a one-shot CLI tool) can come and go between scans and
// never get attached. It also misses any library outside the small set of
// currently-running processes' maps, such as a language runtime's own bundled
// copy (a conda/venv Python's libssl.so, not the system one) that nothing has
// loaded yet.
//
// Uprobes attach to a library FILE, not to a live process — so discovering a
// path this way and attaching to it ahead of time means every future
// invocation of that command is covered from its very first TLS call, no
// matter how short-lived the process turns out to be.
//
// This is a one-time, best-effort sweep (call it once at startup, not on
// every rescan): resolving thousands of PATH entries via `ldd` is too heavy
// to repeat on a timer. deadline bounds the total time spent, since a PATH
// with a large language-runtime bin/ directory can hold thousands of entries.
func ScanPathBinaries(deadline time.Duration) []Library {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	var files []string
	seenDir := map[string]bool{}
	for _, dir := range strings.Split(os.Getenv("PATH"), ":") {
		if dir == "" || seenDir[dir] {
			continue
		}
		seenDir[dir] = true
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil || info.Mode()&0111 == 0 {
				continue // not executable
			}
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	// ldd is a shell script wrapping the dynamic linker; forking one per file
	// serially would take too long on a large PATH (thousands of conda/venv
	// binaries), so resolve concurrently and stop at the deadline rather than
	// waiting for stragglers — a partial sweep beats none.
	const workers = 16
	jobs := make(chan string)
	results := make(chan string, len(files))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				for _, p := range lddSSLPaths(ctx, f) {
					results <- p
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, f := range files {
			select {
			case jobs <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	byPath := map[string]bool{}
	for p := range results {
		byPath[p] = true
	}

	out := make([]Library, 0, len(byPath))
	for p := range byPath {
		l := Library{Path: p}
		if r := matchRule(p); r != nil {
			l.Family = r.Name
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// lddSSLPaths runs ldd on one file and returns the resolved paths of any
// dependency matching a decryption rule's SONAME.
func lddSSLPaths(ctx context.Context, path string) []string {
	out, err := exec.CommandContext(ctx, "ldd", path).Output()
	if err != nil {
		return nil // not a dynamic ELF, or ldd refused it — not a target
	}
	var found []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// Typical line: "libssl.so.3 => /usr/lib/x86_64-linux-gnu/libssl.so.3 (0x…)"
		line := sc.Text()
		_, rhs, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}
		rhs = strings.TrimSpace(rhs)
		libPath, _, _ := strings.Cut(rhs, " ")
		if libPath == "" || !strings.HasPrefix(libPath, "/") || !soNamePattern.MatchString(libPath) {
			continue
		}
		if _, err := os.Stat(libPath); err != nil {
			continue // named but not actually resolvable from here
		}
		found = append(found, libPath)
	}
	return found
}

// LibraryForPID reports the OpenSSL-family library a specific process has
// mapped. A process with none is not an error: plenty of processes do no TLS,
// and statically linked binaries carry the code without a separate mapping.
func LibraryForPID(pid int) (string, error) {
	paths := mappedSSL(pid)
	if len(paths) == 0 {
		return "", fmt.Errorf("tlspeek: pid %d has no OpenSSL-family library mapped "+
			"(it may do no TLS, or be statically linked — pass the executable's own path instead)", pid)
	}
	// Prefer a path that matches a decryption rule (OpenSSL/GnuTLS/…); that is
	// the one carrying the symbols to hook.
	for _, p := range paths {
		if matchRule(p) != nil {
			return p, nil
		}
	}
	return paths[0], nil
}

// mappedSSL returns the distinct library paths matching sslNames in one
// process's memory map. Unreadable processes are skipped rather than reported:
// on a busy machine a pid disappearing mid-scan is routine, not a failure.
func mappedSSL(pid int) []string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Only executable mappings can hold the functions being probed.
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		path := fields[5]
		if !strings.HasPrefix(path, "/") || !soNamePattern.MatchString(path) {
			continue
		}
		// A mapping can name a path not visible from our mount namespace (a
		// container, a snap, or a process that has since exited). Skip anything
		// we cannot actually open, so attach does not later fail on it.
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}
