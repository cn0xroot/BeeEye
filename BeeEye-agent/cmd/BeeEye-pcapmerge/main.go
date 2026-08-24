// Command BeeEye-pcapmerge combines a capture file with a TLS key-log file
// into a single pcapng file carrying an embedded Decryption Secrets Block
// (F14 phase two). Wireshark opens the result and decrypts the TLS in it
// automatically — no separate "Edit > Preferences > TLS > (Pre)-Master-Secret
// log filename" pointed at a second file.
//
// This is the file-merge half of scripts/tls-decrypt.sh's SSLKEYLOGFILE
// route: that script already produces a classic-pcap capture and a
// keys-*.log in lockstep (cmd_capture); this tool is what turns that pair
// into the one file worth handing someone. It does not itself capture
// anything or run tshark — see TLS-DECRYPT.md for the full pipeline.
//
// Usage:
//
//	BeeEye-pcapmerge -pcap cap-20260101-120000.pcap -keys keys-20260101-120000.log -out cap-20260101-120000.pcapng
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"BeeEye/internal/pcapfile"
)

func main() {
	pcapPath := flag.String("pcap", "", "capture file to read (classic pcap or pcapng)")
	keysPath := flag.String("keys", "", "SSLKEYLOGFILE-format key log to embed")
	outPath := flag.String("out", "", "output .pcapng path (default: -pcap with its extension replaced by .pcapng)")
	flag.Parse()

	if *pcapPath == "" || *keysPath == "" {
		fmt.Fprintln(os.Stderr, "usage: BeeEye-pcapmerge -pcap <file> -keys <keylog file> [-out <file.pcapng>]")
		os.Exit(2)
	}
	out := *outPath
	if out == "" {
		out = defaultOutPath(*pcapPath)
	}

	if err := merge(*pcapPath, *keysPath, out); err != nil {
		log.Fatalf("BeeEye-pcapmerge: %v", err)
	}
	fmt.Printf("wrote %s (capture + embedded TLS key log — open this one file in Wireshark)\n", out)
}

// defaultOutPath swaps a known capture extension for .pcapng, or appends it
// when the input has no extension this recognises (e.g. tcpdump's cap-*.pcap
// naming, but also handles a bare filename gracefully).
func defaultOutPath(pcapPath string) string {
	for _, ext := range []string{".pcapng", ".pcap", ".cap"} {
		if strings.HasSuffix(pcapPath, ext) {
			return strings.TrimSuffix(pcapPath, ext) + ".pcapng"
		}
	}
	return pcapPath + ".pcapng"
}

// merge reads every packet out of pcapPath, unmodified, and writes them plus
// one Decryption Secrets Block (the raw bytes of keysPath) to a new pcapng
// file at outPath. Link type and snap length are carried over from the
// source when it is a classic pcap (which is what tcpdump — and hence
// scripts/tls-decrypt.sh — writes); a pcapng source's own per-packet
// LinkType is used instead, defaulting to Ethernet, matching how
// pcapfile.Open's callers elsewhere in BeeEye already treat an unset one.
func merge(pcapPath, keysPath, outPath string) error {
	keys, err := os.ReadFile(keysPath)
	if err != nil {
		return fmt.Errorf("reading key log: %w", err)
	}
	if len(strings.TrimSpace(string(keys))) == 0 {
		return fmt.Errorf("%s is empty — nothing to embed (see tls-decrypt.sh's own check for why this usually means the source process never wrote any keys)", keysPath)
	}

	in, err := os.Open(pcapPath)
	if err != nil {
		return fmt.Errorf("opening capture: %w", err)
	}
	defer in.Close()

	pr, err := pcapfile.Open(in)
	if err != nil {
		return fmt.Errorf("reading capture: %w", err)
	}
	linkType := uint32(pcapfile.LinkEthernet)
	var snapLen uint32 = 262144
	if r, ok := pr.(*pcapfile.Reader); ok {
		linkType = r.Header().LinkType
		if r.Header().SnapLen > 0 {
			snapLen = r.Header().SnapLen
		}
	}

	outF, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", outPath, err)
	}
	defer outF.Close()

	nw, err := pcapfile.NewNgWriter(outF, linkType, snapLen)
	if err != nil {
		return fmt.Errorf("writing pcapng header: %w", err)
	}
	// Written before any packet, matching the pcapng spec's SHOULD for a
	// DSB to precede the blocks it decrypts (see NgWriter.WriteSecrets).
	if err := nw.WriteSecrets(pcapfile.SecretsTypeTLS, keys); err != nil {
		return fmt.Errorf("writing decryption secrets block: %w", err)
	}

	n := 0
	for {
		pkt, err := pr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading packet %d: %w", n+1, err)
		}
		if err := nw.WritePacket(pkt.TS, pkt.Data, pkt.OrigLen); err != nil {
			return fmt.Errorf("writing packet %d: %w", n+1, err)
		}
		n++
	}
	if err := nw.Flush(); err != nil {
		return fmt.Errorf("flushing %s: %w", outPath, err)
	}
	if n == 0 {
		return fmt.Errorf("%s carried no packets — nothing to merge", pcapPath)
	}
	log.Printf("merged %d packets + %d bytes of TLS key log", n, len(keys))
	return nil
}
