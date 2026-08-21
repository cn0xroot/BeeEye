#!/usr/bin/env bash
# 蜂眼 BeeEye — install BeeEye-desktop into the current user's app launcher.
#
# BeeEye-desktop (see BeeEye-desktop/src-tauri) is a Tauri shell window, not a
# packaged .deb/AppImage — its tauri.conf.json deliberately keeps
# `bundle.active: false` (the frontend is just a redirect to a locally-running
# BeeEye-gui, there is nothing to bundle). So getting it into the GNOME/KDE
# app grid and the dock is a plain XDG desktop-entry install, done here rather
# than through `cargo tauri build`.
#
# What this does, all under the current user's own XDG dirs (no root, no
# system-wide install):
#   1. build the release binary if it is not already built
#   2. install the icon into the hicolor icon theme at every size that ships
#      in BeeEye-desktop/src-tauri/icons/
#   3. write a .desktop entry pointing at the built binary's real path
#   4. refresh the desktop/icon caches so it shows up without a re-login
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$(pwd)
DESKTOP_DIR="$ROOT/BeeEye-desktop/src-tauri"
BIN="$DESKTOP_DIR/target/release/BeeEye-desktop"
ICON_SRC="$DESKTOP_DIR/icons"

APP_ID="io.beeeye.desktop"
ICON_NAME="beeeye-desktop"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null || die "cargo not found — install Rust first (https://rustup.rs)"

if [[ ! -x "$BIN" ]]; then
  bold "building BeeEye-desktop (first run only)…"
  (cd "$DESKTOP_DIR" && cargo build --release)
fi
[[ -x "$BIN" ]] || die "build finished but $BIN is still missing"

# ---- icon: install every size BeeEye-desktop ships, hicolor theme layout ----
ICON_BASE="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
install_icon() {
  local src="$1" size="$2"
  [[ -f "$src" ]] || return 0
  local dir="$ICON_BASE/${size}x${size}/apps"
  mkdir -p "$dir"
  install -m 0644 "$src" "$dir/$ICON_NAME.png"
}
install_icon "$ICON_SRC/32x32.png" 32
install_icon "$ICON_SRC/128x128.png" 128
install_icon "$ICON_SRC/128x128@2x.png" 256
# A 512 source is common; hicolor's largest bucketed size is 512x512.
if [[ -f "$ICON_SRC/icon.png" ]]; then
  install_icon "$ICON_SRC/icon.png" 512
fi
dim "  icon installed under $ICON_BASE/*/apps/$ICON_NAME.png"

# ---- .desktop entry ----
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS_DIR"
DESKTOP_FILE="$APPS_DIR/$APP_ID.desktop"

cat > "$DESKTOP_FILE" <<DESKTOP
[Desktop Entry]
Type=Application
Version=1.1
Name=BeeEye
Name[zh_CN]=蜂眼 BeeEye
GenericName=Live Traffic Analyzer
GenericName[zh_CN]=实时流量分析器
Comment=Live packet capture and protocol analysis for your home network
Comment[zh_CN]=家庭网络实时抓包与协议分析
Exec="$BIN"
Icon=$ICON_NAME
Terminal=false
Categories=Network;Security;
StartupWMClass=BeeEye-desktop
StartupNotify=true
DESKTOP
chmod 0644 "$DESKTOP_FILE"
dim "  launcher entry written to $DESKTOP_FILE"

# ---- refresh caches so it appears without a re-login ----
if command -v update-desktop-database >/dev/null; then
  update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null; then
  gtk-update-icon-cache -q -t -f "$ICON_BASE" 2>/dev/null || true
fi

echo
bold "done — BeeEye should now appear in the app launcher/grid as \"BeeEye\"."
dim "if it does not show up immediately, log out and back in once."
echo
dim "to remove it: rm '$DESKTOP_FILE' '$ICON_BASE'/*/apps/$ICON_NAME.png"
