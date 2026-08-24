#!/usr/bin/env bash
# 蜂眼 BeeEye — Chromium-family TLS decryption via SSLKEYLOGFILE.
#
# Chrome, AdsPower and every other Chromium/Electron build statically link a
# stripped BoringSSL, so the uprobe tool (BeeEye-tlspeek) cannot hook them by
# symbol name — see TLS-DECRYPT.md §1. The route that does work for these
# browsers is the one they were built to support: the SSLKEYLOGFILE env var.
# Set it at launch and the browser writes out the TLS master secrets; capture
# the packets alongside and the plaintext is recoverable.
#
# This script runs the whole loop:
#   1. start a packet capture on the default-route NIC
#   2. launch the target browser with SSLKEYLOGFILE pointed at a fresh file
#   3. on exit, decrypt the capture with those keys and print the plaintext
#
# The keys only cover sessions that begin AFTER launch, so the browser must be
# started by this script (or relaunched under it). An already-running Chrome
# whose env does not carry the variable cannot be decrypted retroactively —
# that is a property of TLS forward secrecy, not a limitation of the tool.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$(pwd)
OUT_DIR="${BEEEYE_TLS_OUT:-$ROOT/.run/tls}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法 / usage: ./scripts/tls-decrypt.sh <command> [options]

commands:
  capture     start a capture, launch the browser, decrypt on exit (the loop)
  decrypt     decrypt an existing capture with an existing key log
  help        this text

capture options:
  --app NAME        chrome | adspower | a path to any Chromium/Electron binary
                    (default: chrome)
  --url URL         open this URL; with headless, fetch it and exit
  --headless        run the browser headless and exit after --url loads
                    (default for chrome when --url is given; adspower is a GUI)
  --iface NAME      capture interface (default: the default-route NIC)
  --filter EXPR     tshark display filter for the decrypted output
                    (default: http2 or http)

decrypt options:
  --pcap FILE       the capture to decrypt        (default: newest in .run/tls)
  --keys FILE       the SSLKEYLOGFILE to use       (default: newest in .run/tls)
  --filter EXPR     tshark display filter          (default: http2 or http)

Chrome/AdsPower statically link a stripped BoringSSL, so BeeEye-tlspeek cannot
hook them by symbol; this SSLKEYLOGFILE route is the one that works for them.
For a dynamically-linked OpenSSL process (curl, many services), prefer the live
uprobe tool: ./BeeEye-agent/bin/BeeEye-tlspeek -pid <pid>
USAGE
}

need() { command -v "$1" >/dev/null || die "$1 not found — install it first ($2)"; }

PCAPMERGE_BIN="$ROOT/BeeEye-agent/bin/BeeEye-pcapmerge"

# merge_pcapng combines pcap+keys into one Wireshark-openable .pcapng carrying
# an embedded Decryption Secrets Block (F14 phase two), so a capture handed to
# someone else doesn't need its key log pointed at separately in Wireshark's
# preferences. Best-effort: a missing BeeEye-pcapmerge binary (not built via
# `make pcapmerge`) just means this step is skipped, not a hard failure — the
# separate pcap+keys files this script has always produced are still there
# and still work with `decrypt` / a manual `-o tls.keylog_file:`.
merge_pcapng() {
  local pcap="$1" keys="$2"
  if [[ ! -x "$PCAPMERGE_BIN" ]]; then
    dim "  (skipping merged .pcapng — build it once with: make pcapmerge)"
    return 0
  fi
  local out="${pcap%.pcap}.pcapng"
  if "$PCAPMERGE_BIN" -pcap "$pcap" -keys "$keys" -out "$out" >/dev/null 2>&1; then
    dim "  merged : $out (capture + keys in one file — open this in Wireshark)"
  else
    warn "  BeeEye-pcapmerge failed — falling back to the separate pcap+keys files"
  fi
}

default_iface() {
  ip -o route get 1.1.1.1 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1
}

# resolve_app turns a friendly name into an executable and prints, on a second
# line, whether it is a GUI the user drives or something we can run headless.
resolve_app() {
  case "$1" in
    chrome)
      for c in google-chrome google-chrome-stable chromium chromium-browser; do
        command -v "$c" >/dev/null && { echo "$c"; return; }
      done
      die "no chrome/chromium binary found on PATH" ;;
    adspower|AdsPower)
      local p="/opt/AdsPower Global/adspower_global"
      [[ -x "$p" ]] || p=$(find /opt -maxdepth 2 -iname 'adspower_global' -type f 2>/dev/null | head -1)
      [[ -n "$p" && -x "$p" ]] || die "AdsPower binary not found under /opt"
      echo "$p" ;;
    *)
      [[ -x "$1" ]] || die "not an executable: $1"
      echo "$1" ;;
  esac
}

cmd_capture() {
  local app="chrome" url="" headless="" iface="" filter=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --app) shift; app="$1" ;;
      --url) shift; url="$1" ;;
      --headless) headless=1 ;;
      --iface) shift; iface="$1" ;;
      --filter) shift; filter="$1" ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
  done

  need tcpdump "apt install tcpdump"
  local bin; bin=$(resolve_app "$app")
  [[ -z "$iface" ]] && iface=$(default_iface)
  [[ -n "$iface" ]] || die "could not determine a capture interface; pass --iface"

  mkdir -p "$OUT_DIR"
  local stamp; stamp=$(date +%Y%m%d-%H%M%S)
  local keys="$OUT_DIR/keys-$stamp.log"
  local pcap="$OUT_DIR/cap-$stamp.pcap"
  : > "$keys"

  bold "蜂眼 TLS 解密 — $app"
  dim  "  binary : $bin"
  dim  "  iface  : $iface"
  dim  "  keys   : $keys"
  dim  "  pcap   : $pcap"

  # tcpdump needs privilege; say so clearly rather than failing opaquely.
  if ! tcpdump -i "$iface" -w "$pcap" 'tcp port 443 or tcp port 8443' -U >/dev/null 2>&1 &
  then :; fi
  local tcpd=$!
  sleep 1
  if ! kill -0 "$tcpd" 2>/dev/null; then
    die "tcpdump could not start — it needs root or CAP_NET_RAW. Try: sudo ./scripts/tls-decrypt.sh capture ..."
  fi
  # Ensure the capture is always stopped, however this function returns.
  trap 'kill '"$tcpd"' 2>/dev/null || true' RETURN

  bold "capturing — the key log fills as the browser opens TLS connections"

  # Chrome headless with a URL is scriptable end to end; AdsPower is a GUI the
  # operator drives, so there we launch and wait for them to close it.
  local -a args=(--user-data-dir="$OUT_DIR/profile-$stamp")
  if [[ "$app" == chrome || "$bin" == *chrom* ]]; then
    args+=(--no-first-run --no-default-browser-check)
  fi

  if [[ -n "$url" && ( -n "$headless" || "$app" == chrome || "$bin" == *chrom* ) && -z "${FORCE_GUI:-}" ]]; then
    # Headless one-shot: fetch the URL, then stop.
    dim "  mode   : headless, fetching $url"
    SSLKEYLOGFILE="$keys" "$bin" --headless --disable-gpu --no-sandbox \
      "${args[@]}" --ignore-certificate-errors --dump-dom "$url" >/dev/null 2>&1 || true
    sleep 2
  else
    # Interactive: launch and wait for the operator to close the window.
    [[ -n "$url" ]] && args+=("$url")
    warn "  launching $app — browse as usual, then CLOSE the window to decrypt"
    SSLKEYLOGFILE="$keys" "$bin" "${args[@]}" >/dev/null 2>&1 || true
    sleep 2
  fi

  kill "$tcpd" 2>/dev/null || true
  wait "$tcpd" 2>/dev/null || true
  trap - RETURN

  local nkeys; nkeys=$(wc -l < "$keys" 2>/dev/null || echo 0)
  local npkts; npkts=$(tcpdump -r "$pcap" 2>/dev/null | wc -l || echo 0)
  echo
  bold "captured $npkts packets, $nkeys key-log lines"
  [[ "$nkeys" -gt 0 ]] || die "the key log is empty — the browser wrote no keys.
Was it already running? SSLKEYLOGFILE only applies to a fresh launch."

  decrypt_pcap "$pcap" "$keys" "$filter"
  echo
  dim "saved: $pcap"
  dim "       $keys"
  merge_pcapng "$pcap" "$keys"
  dim "re-run just the decode with:  ./scripts/tls-decrypt.sh decrypt --pcap $pcap --keys $keys"
}

cmd_decrypt() {
  local pcap="" keys="" filter=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pcap) shift; pcap="$1" ;;
      --keys) shift; keys="$1" ;;
      --filter) shift; filter="$1" ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
    shift
  done
  [[ -z "$pcap" ]] && pcap=$(ls -t "$OUT_DIR"/cap-*.pcap 2>/dev/null | head -1)
  [[ -z "$keys" ]] && keys=$(ls -t "$OUT_DIR"/keys-*.log 2>/dev/null | head -1)
  [[ -n "$pcap" && -f "$pcap" ]] || die "no pcap given and none found in $OUT_DIR"
  [[ -n "$keys" && -f "$keys" ]] || die "no key log given and none found in $OUT_DIR"
  decrypt_pcap "$pcap" "$keys" "$filter"
  echo
  merge_pcapng "$pcap" "$keys"
}

# decrypt_pcap is the one place tshark is invoked, so the two entry points
# above cannot drift in how they decode.
decrypt_pcap() {
  local pcap="$1" keys="$2" filter="${3:-}"
  need tshark "apt install tshark"

  bold "── decrypted SNI (which sites were visited) ──────────────"
  tshark -r "$pcap" -o "tls.keylog_file:$keys" \
    -Y 'tls.handshake.extensions_server_name' \
    -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u | sed 's/^/  /'

  bold "── decrypted HTTP/2 requests ─────────────────────────────"
  tshark -r "$pcap" -o "tls.keylog_file:$keys" \
    -Y "${filter:-http2.headers.method}" \
    -T fields -e http2.headers.method -e http2.headers.authority -e http2.headers.path \
    2>/dev/null | awk 'NF' | sed 's/\t/ /g; s/^/  /' | head -40

  bold "── decrypted HTTP/2 responses (status · type · server) ───"
  tshark -r "$pcap" -o "tls.keylog_file:$keys" \
    -Y 'http2.headers.status' \
    -T fields -e http2.headers.status -e http2.headers.content_type -e http2.headers.server \
    2>/dev/null | awk 'NF' | sed 's/\t/ /g; s/^/  /' | head -40

  # Older sites still speak HTTP/1.1 inside TLS; surface those too.
  local h1
  h1=$(tshark -r "$pcap" -o "tls.keylog_file:$keys" -Y 'http.request or http.response' \
        -T fields -e http.request.full_uri -e http.response.code 2>/dev/null | awk 'NF' | head -20 || true)
  if [[ -n "$h1" ]]; then
    bold "── decrypted HTTP/1.1 ────────────────────────────────────"
    sed 's/^/  /' <<<"$h1"
  fi
}

case "${1:-help}" in
  capture) shift; cmd_capture "$@" ;;
  decrypt) shift; cmd_decrypt "$@" ;;
  help|-h|--help) usage ;;
  *) usage >&2; die "unknown command: ${1:-}" ;;
esac
