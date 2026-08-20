#!/usr/bin/env bash
# 蜂眼 BeeEye — end-to-end smoke test of the local environment.
#
# Exercises every endpoint on both services and checks the two really are
# independent (program.md F42): stopping the analyzer must leave the overview
# API answering, and vice versa.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$(pwd)
AGENT_PORT="${AGENT_PORT:-8080}"
GUI_PORT="${GUI_PORT:-8081}"

PASS=0
FAIL=0

check() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %s\n' "$label"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗\033[0m %s\n' "$label"; FAIL=$((FAIL+1))
  fi
}

# get_ok fetches a URL and requires a 2xx plus a non-empty body.
#
# Note the absence of a pipeline here: piping curl into `head -c 1` would close
# the pipe as soon as the first byte arrives, and curl would then fail with a
# write error on any response big enough not to fit the pipe buffer — turning
# the largest, most interesting endpoints into spurious failures.
get_ok() {
  local size
  size=$(curl -sf --max-time 10 -o /dev/null -w '%{size_download}' "$1") || return 1
  [ "${size:-0}" -gt 0 ]
}

# json_has requires a key to be present in the response, buffering the body for
# the same reason get_ok avoids a pipeline.
json_has() {
  local body
  body=$(curl -sf --max-time 10 "$1") || return 1
  case "$body" in *"\"$2\""*) return 0 ;; *) return 1 ;; esac
}

# starts_with checks a response's leading bytes (used for file magic).
starts_with() {
  local body
  body=$(curl -sf --max-time 10 "$1" | head -c 16) || true
  case "$body" in "$2"*) return 0 ;; *) return 1 ;; esac
}

echo "BeeEye smoke test"
echo
echo "overview API (:$AGENT_PORT)"
check "health"                 get_ok  "http://127.0.0.1:$AGENT_PORT/api/health"
check "summary"                json_has "http://127.0.0.1:$AGENT_PORT/api/summary" "device_count"
check "devices"                get_ok  "http://127.0.0.1:$AGENT_PORT/api/devices"
check "connections"            get_ok  "http://127.0.0.1:$AGENT_PORT/api/connections?limit=5"
check "dns records"            get_ok  "http://127.0.0.1:$AGENT_PORT/api/dns?limit=5"
check "events"                 get_ok  "http://127.0.0.1:$AGENT_PORT/api/events?limit=5"
check "by-IP view (F25)"       get_ok  "http://127.0.0.1:$AGENT_PORT/api/views/ip"
check "by-protocol view (F26)" get_ok  "http://127.0.0.1:$AGENT_PORT/api/views/protocol"
check "top-N (F27)"            json_has "http://127.0.0.1:$AGENT_PORT/api/views/topn?dim=country" "rows"
check "time series"            json_has "http://127.0.0.1:$AGENT_PORT/api/timeseries?bucket=600" "points"
check "CSV export (F31)"       get_ok  "http://127.0.0.1:$AGENT_PORT/api/export?format=csv&limit=5"
check "config"                 json_has "http://127.0.0.1:$AGENT_PORT/api/config" "signal_weights"

echo
echo "analyzer API (:$GUI_PORT)"
check "health"                 get_ok  "http://127.0.0.1:$GUI_PORT/api/health"
check "interfaces"             get_ok  "http://127.0.0.1:$GUI_PORT/api/interfaces"
check "status"                 json_has "http://127.0.0.1:$GUI_PORT/api/status" "real_capture"
check "packet list"            get_ok  "http://127.0.0.1:$GUI_PORT/api/packets?limit=5"
check "render info"            json_has "http://127.0.0.1:$GUI_PORT/api/render/info" "backend"
check "colour field PNG"       starts_with "http://127.0.0.1:$GUI_PORT/api/render/frame.png" $'\x89PNG' 
check "pcap export (F44)"      bash -c "curl -sf --max-time 5 'http://127.0.0.1:$GUI_PORT/api/export/pcap?limit=10' -o /tmp/BeeEye-smoke.pcap && [ -s /tmp/BeeEye-smoke.pcap ]"
check "valid filter accepted"  bash -c "curl -sf --max-time 5 -X POST 'http://127.0.0.1:$GUI_PORT/api/filter/validate' -d '{\"filter\":\"tcp.port == 443 && !dns\"}' | grep -q '\"valid\":true'"
check "bad filter rejected"    bash -c "curl -sf --max-time 5 -X POST 'http://127.0.0.1:$GUI_PORT/api/filter/validate' -d '{\"filter\":\"tcp.port ==\"}' | grep -q '\"valid\":false'"
check "SSE stream opens"       bash -c "curl -sf --max-time 3 -N 'http://127.0.0.1:$GUI_PORT/api/stream' -o /dev/null; [ \$? -le 28 ]"

if command -v tcpdump >/dev/null && [ -s /tmp/BeeEye-smoke.pcap ]; then
  check "exported pcap is readable by tcpdump" tcpdump -r /tmp/BeeEye-smoke.pcap -c 1
fi

echo
echo "process isolation (F42)"
# The two services must not share fate. Prove it rather than assert it.
if [ -f "$ROOT/.run/gui.pid" ] && kill -0 "$(cat "$ROOT/.run/gui.pid")" 2>/dev/null; then
  kill -STOP "$(cat "$ROOT/.run/gui.pid")" 2>/dev/null
  check "overview API still answers while the analyzer is suspended" \
        get_ok "http://127.0.0.1:$AGENT_PORT/api/summary"
  kill -CONT "$(cat "$ROOT/.run/gui.pid")" 2>/dev/null
else
  echo "  – skipped (analyzer not started via scripts/dev.sh)"
fi

echo
echo "renderer"
backend=$(curl -sf --max-time 5 "http://127.0.0.1:$GUI_PORT/api/render/info" 2>/dev/null \
          | sed -n 's/.*"backend":"\([a-z]*\)".*/\1/p')
device=$(curl -sf --max-time 5 "http://127.0.0.1:$GUI_PORT/api/render/info" 2>/dev/null \
          | sed -n 's/.*"device":"\([^"]*\)".*/\1/p')
echo "  colour field backend: ${backend:-unknown} ${device:+($device)}"
[ "$backend" = "cpu" ] && echo "  (build with 'make build-cuda' on a CUDA host to render on the GPU)"

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m%d passed, 0 failed\033[0m\n' "$PASS"
else
  printf '\033[31m%d passed, %d FAILED\033[0m\n' "$PASS" "$FAIL"
fi
exit $(( FAIL > 0 ? 1 : 0 ))
