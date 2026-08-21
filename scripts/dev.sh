#!/usr/bin/env bash
# 蜂眼 BeeEye — local test environment control.
#
# Starts the two services as independent background processes (program.md F42):
# one can be stopped, crashed or upgraded without touching the other. Logs and
# pidfiles live under .run/ so nothing lands in /tmp where a reboot eats it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$(pwd)
RUN_DIR="$ROOT/.run"
BIN="$ROOT/BeeEye-agent/bin"

AGENT_PORT="${AGENT_PORT:-8080}"
GUI_PORT="${GUI_PORT:-8081}"
IFACE="${IFACE:-}"

mkdir -p "$RUN_DIR" "$ROOT/data"

# Pick the analyzer binary: the CUDA build when it exists, otherwise the
# portable one. Both render the same picture; only the speed differs.
gui_binary() {
  if [[ -x "$BIN/BeeEye-gui-cuda" ]]; then
    echo "$BIN/BeeEye-gui-cuda"
  else
    echo "$BIN/BeeEye-gui"
  fi
}

# Same preference for the overview agent, which since F7's traffic-trend
# curve also has a render.Renderer to pick a backend for.
agent_binary() {
  if [[ -x "$BIN/BeeEye-agent-cuda" ]]; then
    echo "$BIN/BeeEye-agent-cuda"
  else
    echo "$BIN/BeeEye-agent"
  fi
}

# default_iface picks the interface carrying the default route, so `make dev`
# on a laptop captures something real instead of an empty loopback.
default_iface() {
  local dev
  dev=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  echo "${dev:-lo}"
}

is_running() {
  local pidfile="$RUN_DIR/$1.pid"
  [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

start_one() {
  local name="$1"; shift
  if is_running "$name"; then
    echo "  $name already running (pid $(cat "$RUN_DIR/$name.pid"))"
    return
  fi
  "$@" > "$RUN_DIR/$name.log" 2>&1 &
  echo $! > "$RUN_DIR/$name.pid"
  echo "  $name started (pid $!) → $RUN_DIR/$name.log"
}

cmd_start() {
  if [[ ! -x "$BIN/BeeEye-agent" ]]; then
    echo "binaries not built yet — run: make build" >&2
    exit 1
  fi
  [[ -z "$IFACE" ]] && IFACE=$(default_iface)

  echo "starting BeeEye…"
  BEEEYE_LISTEN=":$AGENT_PORT" \
    start_one agent "$(agent_binary)" -config "$ROOT/config/config.yaml"
  start_one gui "$(gui_binary)" -listen ":$GUI_PORT" -iface "$IFACE"

  # Wait for both to answer rather than guessing with a fixed sleep.
  for svc in "agent:$AGENT_PORT" "gui:$GUI_PORT"; do
    local name="${svc%%:*}" port="${svc##*:}"
    for _ in $(seq 50); do
      if curl -sf "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; then break; fi
      sleep 0.1
    done
    if ! curl -sf "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; then
      echo "  WARNING: $name did not become healthy; see $RUN_DIR/$name.log" >&2
    fi
  done

  echo
  echo "  overview UI : http://localhost:$AGENT_PORT"
  echo "  analyzer    : http://localhost:$GUI_PORT   (capturing on $IFACE)"

  # Only comment on the capture source if the analyzer actually answered.
  # Warning about simulated data when the service is merely still starting
  # sends people chasing a permissions problem they do not have.
  local status
  if status=$(curl -sf "http://127.0.0.1:$GUI_PORT/api/status" 2>/dev/null); then
    if ! grep -q '"real_capture":true' <<<"$status"; then
      echo
      echo "  NOTE: real packet capture is unavailable, so the analyzer is showing"
      echo "        SIMULATED traffic. To capture for real:"
      echo "          sudo setcap cap_net_raw,cap_net_admin+ep $(gui_binary)"
      echo "        then: make stop && make run"
    fi
  else
    echo
    echo "  WARNING: the analyzer is not answering on :$GUI_PORT — see $RUN_DIR/gui.log"
  fi
}

cmd_stop() {
  for name in agent gui; do
    local pidfile="$RUN_DIR/$name.pid"
    if is_running "$name"; then
      local pid
      pid=$(cat "$pidfile")
      kill "$pid" 2>/dev/null || true
      # Wait for the process to actually go. Returning before the socket is
      # released makes `restart` fail with "address already in use", which
      # looks like a bug in the service rather than in this script.
      for _ in $(seq 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then
        echo "  $name did not exit in 3s; sending SIGKILL"
        kill -9 "$pid" 2>/dev/null || true
        sleep 0.2
      fi
      echo "  $name stopped"
    fi
    rm -f "$pidfile"
  done
}

cmd_status() {
  for name in agent gui; do
    if is_running "$name"; then
      echo "  $name: running (pid $(cat "$RUN_DIR/$name.pid"))"
    else
      echo "  $name: stopped"
    fi
  done
  echo
  curl -sf "http://127.0.0.1:$GUI_PORT/api/status" 2>/dev/null | head -c 400 || true
  echo
}

case "${1:-start}" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_stop; cmd_start ;;
  status)  cmd_status ;;
  logs)    tail -f "$RUN_DIR"/*.log ;;
  *) echo "usage: $0 {start|stop|restart|status|logs}" >&2; exit 2 ;;
esac
