// Command BeeEye-tlspeek captures the TLS plaintext of processes on this host
// by attaching uprobes to their OpenSSL-family library (F14).
//
// # Scope, stated up front
//
// A uprobe reaches only libraries running on THIS kernel. This tool sees the
// gateway's own processes — curl, a browser, a service you run here — and can
// never decrypt a camera, a lock or a phone: their TLS runs on their own
// hardware. It is the content-level companion to the analyzer's process
// attribution, which covers exactly the same set of flows. See TLS-DECRYPT.md.
//
// # Why it is a separate command
//
// It reads application content, not packet metadata — the one thing the rest
// of BeeEye deliberately does not do. Keeping it out of the always-on analyzer
// means content capture is never running unless someone started this process
// and named a target. There is no "attach to everything on the machine" flag.
//
// Privileges: needs CAP_BPF + CAP_PERFMON (kernel ≥5.8 with BTF). Grant them
// without root:
//
//	sudo setcap cap_bpf,cap_perfmon+ep ./bin/BeeEye-tlspeek
//
// Usage:
//
//	BeeEye-tlspeek -list                 # show libraries in use and exit
//	BeeEye-tlspeek -pid 1234             # capture one process
//	BeeEye-tlspeek -lib /path/libssl.so  # capture every process using this lib
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"BeeEye/internal/tlspeek"
)

func main() {
	var (
		pid     = flag.Int("pid", 0, "capture only this process id")
		lib     = flag.String("lib", "", "path to the TLS library to probe (default: auto-discover)")
		list    = flag.Bool("list", false, "list matching TLS libraries currently in use, then exit")
		detect  = flag.Bool("detect", false, "detect crypto libraries and whether each is decryptable, then exit")
		maxLen  = flag.Int("max", 512, "bytes of each chunk to print (the capture keeps up to 2047)")
		rawText = flag.Bool("raw", false, "print raw bytes instead of escaping non-printable ones")
	)
	flag.Parse()

	if *detect {
		if err := detectLibraries(); err != nil {
			fatal(err)
		}
		return
	}
	if *list {
		if err := listLibraries(); err != nil {
			fatal(err)
		}
		return
	}

	libPath, err := resolveLib(*lib, *pid)
	if err != nil {
		fatal(err)
	}

	p, err := tlspeek.Load()
	if err != nil {
		if errors.Is(err, tlspeek.ErrNotSupported) {
			fatal(fmt.Errorf("%w\nthis needs a kernel ≥5.8 with BTF", err))
		}
		fatal(err)
	}
	defer p.Close()

	if err := p.Attach(libPath, *pid); err != nil {
		fatal(err)
	}

	scope := "every process using it"
	if *pid > 0 {
		scope = fmt.Sprintf("pid %d only", *pid)
	}
	fmt.Fprintf(os.Stderr, "蜂眼 tlspeek: probing %s (%s)\n", libPath, scope)
	fmt.Fprintln(os.Stderr, "reading plaintext — Ctrl-C to stop")

	events := p.Events()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case ev := <-events:
			if ev == nil {
				return
			}
			printEvent(ev, *maxLen, *rawText)
		case <-sig:
			fmt.Fprintln(os.Stderr, "\nstopping")
			return
		}
	}
}

func resolveLib(lib string, pid int) (string, error) {
	if lib != "" {
		if _, err := os.Stat(lib); err != nil {
			return "", fmt.Errorf("library %q: %w", lib, err)
		}
		return lib, nil
	}
	if pid > 0 {
		return tlspeek.LibraryForPID(pid)
	}
	libs, err := tlspeek.FindLibraries()
	if err != nil {
		return "", err
	}
	if len(libs) == 0 {
		return "", errors.New("no OpenSSL-family library is currently in use; " +
			"name one with -lib, or a process with -pid")
	}
	// The busiest library is the useful default, but say what was chosen so it
	// is never a silent guess.
	fmt.Fprintf(os.Stderr, "auto-selected %s (%d processes using it); override with -lib or -pid\n",
		libs[0].Path, len(libs[0].PIDs))
	return libs[0].Path, nil
}

func detectLibraries() error {
	libs, err := tlspeek.Detect()
	if err != nil {
		return err
	}
	fmt.Printf("supported families (rules): %v\n\n", tlspeek.RuleNames())
	if len(libs) == 0 {
		fmt.Println("no matching crypto library is currently mapped by any process")
		return nil
	}
	fmt.Printf("%-3s  %-8s  %-10s  %s\n", "OK", "FAMILY", "PROCS", "PATH")
	for _, l := range libs {
		mark := "✗"
		if l.Attachable {
			mark = "✓"
		}
		fmt.Printf("%-3s  %-8s  %-10d  %s\n", mark, l.Family, l.Processes, l.Path)
		if l.Note != "" {
			fmt.Printf("       %s\n", l.Note)
		}
	}
	return nil
}

func listLibraries() error {
	libs, err := tlspeek.FindLibraries()
	if err != nil {
		return err
	}
	if len(libs) == 0 {
		fmt.Println("no OpenSSL-family libraries are currently mapped by any process")
		return nil
	}
	fmt.Printf("%-4s  %s\n", "PROC", "LIBRARY")
	for _, l := range libs {
		fmt.Printf("%-4d  %s\n", len(l.PIDs), l.Path)
		fmt.Printf("      pids: %s\n", joinInts(l.PIDs))
	}
	return nil
}

func printEvent(ev *tlspeek.Event, maxLen int, raw bool) {
	ts := time.Unix(0, int64(ev.TimeNS)).Format("15:04:05.000")
	arrow := "→"
	if ev.Dir == tlspeek.DirRead {
		arrow = "←"
	}
	trunc := ""
	if ev.Truncated() {
		trunc = fmt.Sprintf(" (+%d more)", ev.OrigLen-len(ev.Data))
	}
	body := ev.Data
	if len(body) > maxLen {
		body = body[:maxLen]
	}
	text := string(body)
	if !raw {
		text = escape(text)
	}
	fmt.Printf("%s %s %-16s pid=%-7d %dB%s\n%s\n",
		ts, arrow, ev.Comm, ev.PID, len(ev.Data), trunc, text)
}

// escape keeps printable text and common whitespace readable while rendering
// the rest as \xNN, so a binary body cannot scramble the terminal.
func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r > 0x7f && !unicode.IsPrint(r)):
			fmt.Fprintf(&b, "\\x%02x", r&0xff)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, " ")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
