#!/usr/bin/env bash
# 蜂眼 BeeEye — 一键启动 / one-command start.
#
# Everything the README's Quick start does by hand, in the right order, with
# each build step skipped when its output is already newer than its input:
#
#   ./start.sh              build what is stale, start both services
#   ./start.sh --dev        …and run the two Vite dev servers with HMR
#   ./start.sh stop         stop everything this script started
#   ./start.sh status       what is running
#   ./start.sh logs         follow every log
#
# Service supervision itself lives in scripts/dev.sh — this script is the
# layer above it: preflight, build, then delegate. Two places that both know
# how to kill the agent is one place too many.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT=$(pwd)
RUN_DIR="$ROOT/.run"
BIN="$ROOT/BeeEye-agent/bin"

AGENT_PORT="${AGENT_PORT:-8080}"
GUI_PORT="${GUI_PORT:-8081}"
WEB_DEV_PORT="${WEB_DEV_PORT:-5173}"
GUI_DEV_PORT="${GUI_DEV_PORT:-5174}"

DEV_MODE=0
FORCE_REBUILD=0
SKIP_BUILD=0
CMD=start

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法 / usage: ./start.sh [command] [options]

commands:
  start (default)   build anything stale, then start the services
  stop              stop the services (and the dev servers)
  restart           stop, then start
  status            show what is running
  logs              follow all logs in .run/

options:
  --dev             also start the Vite dev servers (HMR) for both UIs
  --rebuild         rebuild everything, even if it looks up to date
  --no-build        start whatever is already built, build nothing
  --iface NAME      capture interface for the analyzer (default: auto)
  --setcap          grant capture capabilities to the binaries (uses sudo)
  -h, --help        this text
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    start|stop|restart|status|logs) CMD="$1" ;;
    --dev)       DEV_MODE=1 ;;
    --rebuild)   FORCE_REBUILD=1 ;;
    --no-build)  SKIP_BUILD=1 ;;
    --iface)     shift; export IFACE="${1:?--iface needs an interface name}" ;;
    --setcap)    CMD=setcap ;;
    -h|--help)   usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

# ------------------------------------------------------------------ preflight

# need_tool reports a missing tool with the exact command that installs it,
# rather than letting make fail 40 lines later with a bare "not found".
need_tool() {
  local tool="$1" hint="$2"
  command -v "$tool" >/dev/null && return 0
  die "$tool not found — install it with: $hint"
}

preflight() {
  need_tool go   "https://go.dev/dl/  (BeeEye needs Go ≥ 1.25)"
  need_tool npm  "apt install nodejs npm   (Node ≥ 18)"
  need_tool clang "apt install clang"
  if [[ ! -f "$ROOT/BeeEye-agent/bpf/vmlinux.h" ]]; then
    need_tool bpftool "apt install linux-tools-common linux-tools-\$(uname -r)"
    [[ -r /sys/kernel/btf/vmlinux ]] ||
      die "/sys/kernel/btf/vmlinux missing — this kernel has no BTF, so CO-RE eBPF cannot be built here"
  fi
}

# ---------------------------------------------------------------------- build

# stale PATTERN_DIR TARGET — true when any source file is newer than the built
# artifact, or the artifact does not exist at all.
stale() {
  local src_dir="$1" target="$2" ; shift 2
  [[ -e "$target" ]] || return 0
  [[ -n "$(find "$src_dir" -newer "$target" -type f "$@" -print -quit 2>/dev/null)" ]]
}

build_backend() {
  if (( FORCE_REBUILD )) || stale "$ROOT/BeeEye-agent/bpf" "$ROOT/BeeEye-agent/internal/ebpf/BeeEye.bpf.o" \( -name '*.c' -o -name '*.h' \); then
    bold "· compiling the eBPF program"
    make -s bpf
  else
    dim  "· eBPF object up to date"
  fi

  if (( FORCE_REBUILD )) || stale "$ROOT/BeeEye-agent" "$BIN/BeeEye-agent" -name '*.go' \
     || [[ ! -x "$BIN/BeeEye-gui" ]]; then
    bold "· building BeeEye-agent and BeeEye-gui"
    make -s build >/dev/null
  else
    dim  "· binaries up to date"
  fi

  # dev.sh runs the CUDA analyzer in preference to the portable one whenever it
  # exists, so leaving it stale would silently run yesterday's renderer while
  # every other artifact was rebuilt. Rebuild it on the same terms — but only
  # if it is already there; its absence means this host has no nvcc and the
  # portable binary is the intended one.
  if [[ -x "$BIN/BeeEye-gui-cuda" ]]; then
    if (( FORCE_REBUILD )) || stale "$ROOT/BeeEye-agent" "$BIN/BeeEye-gui-cuda" -name '*.go' \
       || [[ "$ROOT/BeeEye-agent/cuda/BeeEye_render.cu" -nt "$BIN/BeeEye-gui-cuda" ]]; then
      bold "· building BeeEye-gui-cuda"
      make -s build-cuda >/dev/null
    else
      dim  "· CUDA analyzer up to date"
    fi
  fi
}

# build_frontend UI_DIR — npm install only when node_modules is older than the
# lockfile, vite build only when dist is older than the sources. A full
# reinstall on every start turns a 3-second launch into a 90-second one.
build_frontend() {
  local dir="$1" name="$2"
  if [[ ! -d "$dir/node_modules" ]] || [[ "$dir/package-lock.json" -nt "$dir/node_modules" ]]; then
    bold "· installing $name dependencies"
    (cd "$dir" && npm install --no-fund --no-audit >/dev/null)
  fi
  if (( FORCE_REBUILD )) || [[ ! -d "$dir/dist" ]] \
     || stale "$dir/src" "$dir/dist/index.html" \
     || [[ "$dir/index.html" -nt "$dir/dist/index.html" ]]; then
    bold "· building $name"
    (cd "$dir" && npm run build >/dev/null)
  else
    dim  "· $name up to date"
  fi
}

# ----------------------------------------------------------------- dev servers

# The Vite servers are only started with --dev. They proxy /api to the two Go
# services, so the backends must already be up when these come alive.
start_dev_servers() {
  local specs=("web:$ROOT/BeeEye-web:$WEB_DEV_PORT" "guiweb:$ROOT/BeeEye-gui:$GUI_DEV_PORT")
  for spec in "${specs[@]}"; do
    local name="${spec%%:*}" rest="${spec#*:}"
    local dir="${rest%%:*}" port="${rest##*:}"
    local pidfile="$RUN_DIR/$name.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "  $name dev server already running (pid $(cat "$pidfile"))"
      continue
    fi
    # setsid, because `npm run dev` is npm → sh → node: a HUP aimed at the
    # shell that launched it takes the whole tree down with it, which is how
    # these servers kept disappearing while the two Go binaries stayed up.
    # Their own session means only an explicit `./start.sh stop` ends them.
    setsid bash -c "cd '$dir' && exec npm run dev -- --port $port --strictPort" \
      > "$RUN_DIR/$name.log" 2>&1 &
    echo $! > "$pidfile"
    echo "  $name dev server started (pid $!) → $RUN_DIR/$name.log"
  done
}

stop_dev_servers() {
  for name in web guiweb; do
    local pidfile="$RUN_DIR/$name.pid"
    [[ -f "$pidfile" ]] || continue
    local pid; pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      # Vite spawns an esbuild child; kill the process group so nothing keeps
      # the port and makes the next --strictPort start fail.
      kill -- "-$(ps -o pgid= "$pid" | tr -d ' ')" 2>/dev/null || kill "$pid" 2>/dev/null || true
      echo "  $name dev server stopped"
    fi
    rm -f "$pidfile"
  done
}

# --------------------------------------------------------------------- health

wait_healthy() {
  local port="$1" name="$2"
  for _ in $(seq 60); do
    curl -sf --noproxy '*' "http://127.0.0.1:$port/api/health" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  warn "  WARNING: $name is not answering on :$port — see $RUN_DIR/$name.log"
  return 1
}

cmd_setcap() {
  command -v setcap >/dev/null || die "setcap not found — apt install libcap2-bin"
  [[ -x "$BIN/BeeEye-agent" ]] || die "binaries not built yet — run ./start.sh first"
  bold "granting capture capabilities (sudo)"
  sudo setcap cap_net_raw,cap_net_admin+ep "$BIN/BeeEye-gui"
  [[ -x "$BIN/BeeEye-gui-cuda" ]] && sudo setcap cap_net_raw,cap_net_admin+ep "$BIN/BeeEye-gui-cuda"
  sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep "$BIN/BeeEye-agent"
  echo "done — restart with: ./start.sh restart"
}

cmd_start() {
  mkdir -p "$RUN_DIR" "$ROOT/data"
  if (( SKIP_BUILD )); then
    [[ -x "$BIN/BeeEye-agent" ]] || die "--no-build given but $BIN/BeeEye-agent does not exist"
    dim "· skipping build (--no-build)"
  else
    preflight
    build_backend
    build_frontend "$ROOT/BeeEye-web" "overview UI"
    build_frontend "$ROOT/BeeEye-gui" "analyzer UI"
  fi

  echo
  ./scripts/dev.sh start

  if (( DEV_MODE )); then
    echo
    bold "starting Vite dev servers…"
    start_dev_servers
    for spec in "$WEB_DEV_PORT:overview" "$GUI_DEV_PORT:analyzer"; do
      local port="${spec%%:*}"
      for _ in $(seq 100); do
        curl -sf --noproxy '*' -o /dev/null "http://127.0.0.1:$port/" && break
        sleep 0.1
      done
    done
    echo
    echo "  overview UI (HMR) : http://localhost:$WEB_DEV_PORT"
    echo "  analyzer UI (HMR) : http://localhost:$GUI_DEV_PORT"
  fi
}

cmd_stop() {
  stop_dev_servers
  ./scripts/dev.sh stop
}

case "$CMD" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_stop; cmd_start ;;
  status)  ./scripts/dev.sh status
           for name in web guiweb; do
             p="$RUN_DIR/$name.pid"
             if [[ -f "$p" ]] && kill -0 "$(cat "$p")" 2>/dev/null; then
               echo "  $name dev server: running (pid $(cat "$p"))"
             fi
           done ;;
  logs)    tail -f "$RUN_DIR"/*.log ;;
  setcap)  cmd_setcap ;;
esac
