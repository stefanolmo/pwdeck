#!/usr/bin/env bash
# Installs PW Deck for the current user on Ubuntu/Debian (venv in ~/.local/share/pwdeck).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="$HOME/.local/share/pwdeck"

echo "==> System dependencies (needs sudo)"
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip \
    libxcb-cursor0 libxkbcommon-x11-0 libegl1 libgl1 libdbus-1-3 libfontconfig1

echo "==> Virtual environment and package"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip
"$PREFIX/venv/bin/pip" install "$HERE"

echo "==> Launchers and icon"
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/scalable/apps"
ln -sf "$PREFIX/venv/bin/pwdeck" "$HOME/.local/bin/pwdeck"
ln -sf "$PREFIX/venv/bin/pwdeck-recover" "$HOME/.local/bin/pwdeck-recover"
cp "$HERE/packaging/pwdeck.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/pwdeck.svg"
sed -e "s|@EXEC@|$PREFIX/venv/bin/pwdeck|" -e "s|@ICON@|pwdeck|" "$HERE/packaging/pwdeck.desktop" \
    > "$HOME/.local/share/applications/pwdeck.desktop"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
gtk-update-icon-cache -q -t -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
echo "Done. Start 'pwdeck' from the applications menu or a terminal."
