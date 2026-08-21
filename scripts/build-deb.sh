#!/usr/bin/env bash
# 蜂眼 BeeEye — build a .deb package for BeeEye-desktop.
#
# BeeEye-desktop is a thin Tauri window shell (see BeeEye-desktop/src-tauri) —
# it duplicates no frontend/backend code, and on its own does nothing but open
# a window pointed at a BeeEye-gui backend. That shapes what this .deb can
# honestly promise:
#
#   - it installs the shell, its icon, and its launcher entry — a complete,
#     standard Debian package for THAT
#   - it does NOT install BeeEye-agent/BeeEye-gui, and does not attempt to,
#     because those need eBPF/AF_PACKET capabilities that vary by machine and
#     kernel, and are the actual product this shell is a window onto
#
# So: on a machine that already has a BeeEye-gui backend reachable (built
# locally via ./start.sh, or reachable through a tunnel to a remote gateway),
# the installed app just works. On a machine with neither, it will report
# "cannot locate a BeeEye-gui(-cuda) binary" until BEEEYE_GUI_BIN is set or one
# is put on the machine — this is stated in the package description rather
# than hidden.
#
# No tauri-cli dependency: this hand-builds a standard Debian package tree and
# calls dpkg-deb directly, which is what was already on this machine, rather
# than pulling in another toolchain for one packaging step.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT=$(pwd)
DESKTOP_SRC="$ROOT/BeeEye-desktop/src-tauri"
BIN_SRC="$DESKTOP_SRC/target/release/BeeEye-desktop"
ICON_SRC="$DESKTOP_SRC/icons"

VERSION=$(python3 -c "import json;print(json.load(open('$DESKTOP_SRC/tauri.conf.json'))['version'])")
ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
PKG_NAME="beeeye-desktop"
OUT="$ROOT/${PKG_NAME}_${VERSION}_${ARCH}.deb"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

command -v dpkg-deb >/dev/null || die "dpkg-deb not found — apt install dpkg-dev"

if [[ ! -x "$BIN_SRC" ]]; then
  bold "building the release binary first…"
  (cd "$DESKTOP_SRC" && cargo build --release)
fi
[[ -x "$BIN_SRC" ]] || die "build finished but $BIN_SRC is still missing"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PKG_ROOT="$WORK/${PKG_NAME}_${VERSION}_${ARCH}"

mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/usr/share/applications"
mkdir -p "$PKG_ROOT/usr/share/doc/$PKG_NAME"
for size in 32 128 256 512; do
  mkdir -p "$PKG_ROOT/usr/share/icons/hicolor/${size}x${size}/apps"
done

# ---- binary ----
install -m 0755 "$BIN_SRC" "$PKG_ROOT/usr/bin/BeeEye-desktop"

# ---- icons ----
install -m 0644 "$ICON_SRC/32x32.png"       "$PKG_ROOT/usr/share/icons/hicolor/32x32/apps/beeeye-desktop.png"
install -m 0644 "$ICON_SRC/128x128.png"     "$PKG_ROOT/usr/share/icons/hicolor/128x128/apps/beeeye-desktop.png"
install -m 0644 "$ICON_SRC/128x128@2x.png"  "$PKG_ROOT/usr/share/icons/hicolor/256x256/apps/beeeye-desktop.png"
install -m 0644 "$ICON_SRC/icon.png"        "$PKG_ROOT/usr/share/icons/hicolor/512x512/apps/beeeye-desktop.png"

# ---- .desktop entry — Exec is the installed system path, not a repo path ----
cat > "$PKG_ROOT/usr/share/applications/io.beeeye.desktop.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Version=1.1
Name=BeeEye
Name[zh_CN]=蜂眼 BeeEye
GenericName=Live Traffic Analyzer
GenericName[zh_CN]=实时流量分析器
Comment=Live packet capture and protocol analysis for your home network
Comment[zh_CN]=家庭网络实时抓包与协议分析
Exec=/usr/bin/BeeEye-desktop
Icon=beeeye-desktop
Terminal=false
Categories=Network;Security;
StartupWMClass=BeeEye-desktop
StartupNotify=true
DESKTOP
chmod 0644 "$PKG_ROOT/usr/share/applications/io.beeeye.desktop.desktop"

# ---- copyright (Debian convention; lintian expects one) ----
cat > "$PKG_ROOT/usr/share/doc/$PKG_NAME/copyright" <<'COPYRIGHT'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: BeeEye
Upstream-Contact: BeeEye_Dev <root@beeeye.dev>
Source: https://github.com/cn0xroot/BeeEye

Files: *
Copyright: 2026 BeeEye_Dev
License: see the project repository
COPYRIGHT
# ---- control ----
INSTALLED_SIZE=$(du -sk "$PKG_ROOT" | cut -f1)
cat > "$PKG_ROOT/DEBIAN/control" <<CONTROL
Package: $PKG_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Installed-Size: $INSTALLED_SIZE
Depends: libwebkit2gtk-4.1-0, libjavascriptcoregtk-4.1-0, libsoup-3.0-0, libgtk-3-0t64 | libgtk-3-0, libc6
Maintainer: BeeEye_Dev <root@beeeye.dev>
Homepage: https://www.beeeye.dev/
Description: Native window shell for the BeeEye live traffic analyzer
 A thin Tauri wrapper (about 200 lines of Rust) around the BeeEye-gui web UI,
 giving the live analyzer a native window on an operator's own desktop
 instead of a browser tab. Connects to an already-running BeeEye-gui backend
 on 127.0.0.1:8081, or starts one itself and stops only that instance again
 on window close.
 .
 This package installs the shell only. It requires a BeeEye-gui(-cuda)
 backend to be reachable — either built and available on this same machine
 (see the main BeeEye repository's ./start.sh), or reachable through a tunnel
 to a remote gateway with BEEEYE_GUI_BIN or the backend already listening on
 the target port. Without either, the window reports that it cannot find one.
 .
 BeeEye is a home IoT gateway traffic analyzer built on eBPF — device
 fingerprinting, protocol dissection, HTTPS decryption, anomaly detection,
 GPU-accelerated visualization. See https://www.beeeye.dev/
CONTROL

# ---- postinst / postrm: refresh desktop & icon caches ----
cat > "$PKG_ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
POSTINST
chmod 0755 "$PKG_ROOT/DEBIAN/postinst"

cat > "$PKG_ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
POSTRM
chmod 0755 "$PKG_ROOT/DEBIAN/postrm"

# ---- build ----
bold "building $OUT"
dpkg-deb --root-owner-group --build "$PKG_ROOT" "$OUT" >/dev/null
dim "$(dpkg-deb --info "$OUT" | head -20)"

echo
bold "done: $OUT"
dim "install with:   sudo dpkg -i '$OUT' && sudo apt-get install -f   # the second step pulls in any missing Depends"
dim "or with apt:    sudo apt install ./'$(basename "$OUT")'"
dim "remove with:    sudo apt remove $PKG_NAME"
