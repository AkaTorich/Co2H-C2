#!/usr/bin/env bash
# Установка всех зависимостей для сборки Co2H на Linux (Debian/Ubuntu).
# Запускать: sudo bash scripts/install-deps.sh
set -euo pipefail

info()  { echo -e "\033[36m[*] $1\033[0m"; }
ok()    { echo -e "\033[32m[+] $1\033[0m"; }
warn()  { echo -e "\033[33m[!] $1\033[0m"; }
fatal() { echo -e "\033[31m[!] $1\033[0m"; exit 1; }

# Проверка root
if [ "$(id -u)" -ne 0 ]; then
    fatal "Run as root: sudo bash $0"
fi

# WSL workaround: systemd post-install скрипт падает из-за /etc/passwd lock.
# Подменяем postinst на пустышку, иначе dpkg блокирует ВСЕ установки.
if grep -qi microsoft /proc/version 2>/dev/null; then
    info "WSL detected - neutralizing systemd postinst..."
    POSTINST="/var/lib/dpkg/info/systemd.postinst"
    if [ -f "$POSTINST" ] && grep -q "passwd" "$POSTINST" 2>/dev/null; then
        cp "$POSTINST" "${POSTINST}.bak"
        echo '#!/bin/sh' > "$POSTINST"
        chmod 755 "$POSTINST"
    fi
    dpkg --configure -a 2>/dev/null || true
fi

# ============================================================================
# 1. Базовые инструменты сборки
# ============================================================================
info "Installing build essentials..."

apt-get update -qq

PACKAGES=(
    # Компилятор и базовые инструменты
    build-essential
    g++
    cmake
    git
    pkg-config
    nasm

    # Qt6
    qt6-base-dev
    qt6-base-private-dev
    qt6-svg-dev
    libqt6svg6-dev
    libqt6network6
    qt6-tools-dev

    # OpenSSL
    libssl-dev

    # SQLite (teamserver)
    libsqlite3-dev

    # OpenGL (Qt dependency)
    libgl1-mesa-dev
    libglu1-mesa-dev

    # X11 / XCB (Qt platform plugin)
    libxcb1-dev
    libxcb-xinerama0-dev
    libxcb-cursor-dev
    libxcb-keysyms1-dev
    libxcb-image0-dev
    libxcb-render-util0-dev
    libxcb-icccm4-dev
    libxkbcommon-dev
    libxkbcommon-x11-dev

    # Fontconfig / Freetype
    libfontconfig1-dev
    libfreetype6-dev

    # DBus (Qt dependency)
    libdbus-1-dev
)

apt-get install -y "${PACKAGES[@]}"
ok "All packages installed"

# ============================================================================
# 2. Проверка версий
# ============================================================================
echo ""
info "Checking installed versions..."

check_cmd() {
    if command -v "$1" &>/dev/null; then
        local ver
        ver=$("$1" --version 2>&1 | head -1)
        ok "$1: $ver"
        return 0
    else
        warn "$1: NOT FOUND"
        return 1
    fi
}

check_cmd g++
check_cmd cmake
check_cmd git
check_cmd nasm
check_cmd pkg-config

# Qt6 version
QT6_DIR=""
for d in /usr/lib/x86_64-linux-gnu/cmake/Qt6 /usr/lib/cmake/Qt6 /usr/lib64/cmake/Qt6; do
    if [ -d "$d" ]; then
        QT6_DIR="$d"
        break
    fi
done

if [ -n "$QT6_DIR" ]; then
    QT_VER=$(grep "set(Qt6_VERSION" "$QT6_DIR/Qt6ConfigVersion.cmake" 2>/dev/null | grep -oP '[\d.]+' | head -1)
    ok "Qt6: $QT_VER ($QT6_DIR)"
else
    warn "Qt6 cmake config not found"
fi

# OpenSSL
if [ -f /usr/include/openssl/ssl.h ]; then
    SSL_VER=$(openssl version 2>/dev/null || echo "unknown")
    ok "OpenSSL: $SSL_VER"
else
    warn "OpenSSL dev headers not found"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "\033[33m================================================\033[0m"
echo -e "\033[33m  Dependency installation complete\033[0m"
echo -e "\033[33m================================================\033[0m"
echo ""
echo "  To build the project:"
echo "    bash build-linux.sh"
echo ""
