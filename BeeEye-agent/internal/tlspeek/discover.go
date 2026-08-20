//go:build linux

package tlspeek

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
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
