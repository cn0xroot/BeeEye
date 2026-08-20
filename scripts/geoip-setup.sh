#!/usr/bin/env bash
# 蜂眼 BeeEye — GeoIP database setup helper (F22).
#
# geoip runs on a built-in coarse first-octet table until a real MaxMind-format
# database is present. This script only helps you FETCH one into ./data — it
# never runs automatically and BeeEye itself never performs a live per-IP
# lookup against any online service (that is the privacy requirement §3.9);
# once the file is on disk, every lookup after that is 100% local.
#
# MaxMind's GeoLite2 requires a free account + license key (their terms, not
# ours); this script accepts the key as an argument or env var and does the
# download, or tells you exactly where to get one if you have neither.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
DATA_DIR="./data"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法 / usage: ./scripts/geoip-setup.sh [command]

commands:
  status              show what geoip is currently using (calls the running
                       agent's /api/geoip/status if it is up, else inspects ./data)
  fetch <LICENSE_KEY>  download GeoLite2-City + GeoLite2-ASN from MaxMind into
                       ./data (needs a free account: https://www.maxmind.com/en/geolite2/signup)
  fetch                same, reading the key from $MAXMIND_LICENSE_KEY
  help                 this text

Without a database, geoip resolves country only, from a small built-in table —
still fully offline, just coarse. Nothing here is required to run BeeEye.
USAGE
}

cmd_status() {
  if curl -sf --max-time 2 http://127.0.0.1:8080/api/geoip/status 2>/dev/null | grep -q accuracy; then
    curl -s http://127.0.0.1:8080/api/geoip/status | python3 -m json.tool 2>/dev/null || \
      curl -s http://127.0.0.1:8080/api/geoip/status
    return
  fi
  dim "agent not reachable on :8080 — inspecting $DATA_DIR instead"
  local found=0
  for f in "$DATA_DIR"/GeoLite2-City.mmdb "$DATA_DIR"/GeoLite2-ASN.mmdb "$DATA_DIR"/GeoCN.mmdb "$DATA_DIR"/Country.mmdb; do
    [[ -f "$f" ]] && { echo "  found: $f"; found=1; }
  done
  [[ $found -eq 0 ]] && echo "  no .mmdb file in $DATA_DIR — geoip will use the built-in coarse table"
}

cmd_fetch() {
  local key="${1:-${MAXMIND_LICENSE_KEY:-}}"
  if [[ -z "$key" ]]; then
    cat <<'MSG'
No license key given.

GeoLite2 is free but requires a MaxMind account (their terms):
  1. sign up:  https://www.maxmind.com/en/geolite2/signup
  2. create a license key: https://www.maxmind.com/en/accounts/current/license-key
  3. re-run:   ./scripts/geoip-setup.sh fetch <YOUR_LICENSE_KEY>
     or:       MAXMIND_LICENSE_KEY=<key> ./scripts/geoip-setup.sh fetch

This step is entirely optional — BeeEye runs fine on the built-in coarse table
without it, and every lookup stays local either way (§3.9).
MSG
    exit 1
  fi
  need_tool() { command -v "$1" >/dev/null || die "$1 not found — install it first"; }
  need_tool curl; need_tool tar

  mkdir -p "$DATA_DIR"
  local tmp; tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  for edition in GeoLite2-City GeoLite2-ASN; do
    bold "fetching $edition…"
    local url="https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${key}&suffix=tar.gz"
    if ! curl -sfL "$url" -o "$tmp/$edition.tar.gz"; then
      die "download failed for $edition — check the license key and your network"
    fi
    tar -xzf "$tmp/$edition.tar.gz" -C "$tmp"
    local mmdb; mmdb=$(find "$tmp" -name "${edition}.mmdb" -print -quit)
    [[ -n "$mmdb" ]] || die "$edition.tar.gz did not contain a .mmdb file"
    cp "$mmdb" "$DATA_DIR/${edition}.mmdb"
    dim "  saved $DATA_DIR/${edition}.mmdb"
  done

  echo
  bold "done — restart BeeEye to pick them up:"
  echo "  ./start.sh restart"
  echo
  dim "From here every lookup is served from these local files — nothing is"
  dim "sent per-IP to MaxMind or anyone else at runtime."
}

case "${1:-status}" in
  status) cmd_status ;;
  fetch)  shift; cmd_fetch "$@" ;;
  help|-h|--help) usage ;;
  *) usage >&2; die "unknown command: $1" ;;
esac
