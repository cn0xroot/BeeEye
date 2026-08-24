#!/usr/bin/env bash
# 蜂眼 BeeEye — device-fingerprint database setup helper (F1).
#
# identity runs on a built-in ~19-entry OUI table until a full IEEE registry
# CSV is present. This script only helps you FETCH one into ./data — it
# never runs automatically and BeeEye never performs a live per-device
# lookup against any online service (the same §3.9 privacy requirement
# geoip-setup.sh follows); once the file is on disk, every lookup after that
# is 100% local.
#
# Unlike MaxMind's GeoLite2, IEEE's OUI registry is public and needs no
# account or API key — it's just a CSV.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
DATA_DIR="./data"
OUI_URL="https://standards-oui.ieee.org/oui/oui.csv"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法 / usage: ./scripts/fingerprint-setup.sh [command]

commands:
  status      show what identity is currently using (calls the running
              agent's /api/identity/status if it is up, else inspects ./data
              and ./config)
  fetch-oui   download the full IEEE OUI registry (MA-L, ~50k entries) into
              ./data/oui.csv — public, no account/API key needed
  help        this text

Without ./data/oui.csv, vendor lookup uses a small built-in table (~19
entries) — still fully offline, just coarse. Nothing here is required to run
BeeEye. Device category/model hints are a separate, always-editable file:
see config/device-fingerprints.yaml.
USAGE
}

cmd_status() {
  if curl -sf --max-time 2 http://127.0.0.1:8080/api/identity/status 2>/dev/null | grep -q oui; then
    curl -s http://127.0.0.1:8080/api/identity/status | python3 -m json.tool 2>/dev/null || \
      curl -s http://127.0.0.1:8080/api/identity/status
    return
  fi
  dim "agent not reachable on :8080 — inspecting ./data and ./config instead"
  if [[ -f "$DATA_DIR/oui.csv" ]]; then
    echo "  found: $DATA_DIR/oui.csv ($(wc -l < "$DATA_DIR/oui.csv") lines)"
  else
    echo "  no $DATA_DIR/oui.csv — vendor lookup will use the built-in ~19-entry table"
  fi
  if [[ -f "./config/device-fingerprints.yaml" ]]; then
    echo "  found: ./config/device-fingerprints.yaml"
  else
    echo "  no ./config/device-fingerprints.yaml — category hints will use the built-in table"
  fi
}

cmd_fetch_oui() {
  command -v curl >/dev/null || die "curl not found — install it first"
  mkdir -p "$DATA_DIR"
  bold "fetching IEEE OUI registry…"
  if ! curl -sfL "$OUI_URL" -o "$DATA_DIR/oui.csv"; then
    die "download failed — check your network, or fetch $OUI_URL manually and save it as $DATA_DIR/oui.csv"
  fi
  local n; n=$(wc -l < "$DATA_DIR/oui.csv")
  [[ "$n" -gt 100 ]] || die "downloaded file looks too small ($n lines) — fetch may have returned an error page"
  dim "  saved $DATA_DIR/oui.csv ($n lines)"
  echo
  bold "done — restart BeeEye to pick it up:"
  echo "  ./start.sh restart"
  echo
  dim "From here every vendor lookup is served from this local file — nothing is"
  dim "sent per-device to IEEE or anyone else at runtime."
}

case "${1:-status}" in
  status)     cmd_status ;;
  fetch-oui)  cmd_fetch_oui ;;
  help|-h|--help) usage ;;
  *) usage >&2; die "unknown command: $1" ;;
esac
