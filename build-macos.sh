#!/usr/bin/env bash
# Кросс-сборка macOS бикона на Linux через osxcross.
# Результат:
#   bin/beacons/beacon-macos          — Mach-O universal binary (arm64 + x86_64)
#   bin/beacons/beacon-macos.dylib    — dynamic library universal binary
#
# Использование:
#   ./build-macos.sh              — собрать оба (arm64 + x86_64), создать universal
#   ./build-macos.sh arm64        — только Apple Silicon
#   ./build-macos.sh x64          — только Intel
#
# Зависимости (устанавливаются автоматически):
#   - clang, cmake, git, libssl-dev, libxml2-dev, patch, python3
#   - osxcross (клонируется в ./tools/osxcross)
#   - macOS SDK 14.0 (скачивается автоматически)

set -euo pipefail
cd "$(dirname "$0")"

info()  { echo -e "\033[36m[*] $1\033[0m"; }
ok()    { echo -e "\033[32m[+] $1\033[0m"; }
warn()  { echo -e "\033[33m[!] $1\033[0m"; }
fatal() { echo -e "\033[31m[!] $1\033[0m"; exit 1; }

# ---- Параметры ---------------------------------------------------------------

TARGET="${1:-all}"
OSXCROSS_DIR="$(pwd)/tools/osxcross"
SDK_VER="14.0"
SDK_URL="https://github.com/joseluisq/macosx-sdks/releases/download/${SDK_VER}/MacOSX${SDK_VER}.sdk.tar.xz"
SDK_TAR="/tmp/MacOSX${SDK_VER}.sdk.tar.xz"

OPENSSL_VER="3.3.0"
OPENSSL_SRC="/tmp/openssl-${OPENSSL_VER}"
OPENSSL_TAR="/tmp/openssl-${OPENSSL_VER}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"

SSL_PREFIX="$(pwd)/out/openssl"
BIN_DIR="bin/beacons"
mkdir -p "$BIN_DIR"

# ---- Установка системных зависимостей ----------------------------------------

install_deps() {
    local pkgs=""
    for cmd in clang cmake git patch python3 lzma; do
        command -v "$cmd" > /dev/null || pkgs="$pkgs $cmd"
    done
    # ninja-build — ускоряет сборку LLVM внутри libtapi (в 2-3 раза быстрее Make)
    dpkg -s ninja-build > /dev/null 2>&1  || pkgs="$pkgs ninja-build"
    # Дополнительные пакеты для osxcross (cctools + libtapi)
    dpkg -s libxml2-dev > /dev/null 2>&1  || pkgs="$pkgs libxml2-dev"
    dpkg -s libssl-dev > /dev/null 2>&1   || pkgs="$pkgs libssl-dev"
    dpkg -s zlib1g-dev > /dev/null 2>&1   || pkgs="$pkgs zlib1g-dev"
    dpkg -s libbz2-dev > /dev/null 2>&1   || pkgs="$pkgs libbz2-dev"
    dpkg -s xz-utils > /dev/null 2>&1     || pkgs="$pkgs xz-utils"
    dpkg -s uuid-dev > /dev/null 2>&1     || pkgs="$pkgs uuid-dev"
    dpkg -s clang > /dev/null 2>&1        || pkgs="$pkgs clang"
    dpkg -s llvm-dev > /dev/null 2>&1     || pkgs="$pkgs llvm-dev"

    if [ -n "$pkgs" ]; then
        info "Installing system dependencies:$pkgs"
        sudo apt-get update
        sudo apt-get install -y $pkgs
    fi
    ok "System dependencies OK"
}

# ---- osxcross ----------------------------------------------------------------

setup_osxcross() {
    if [ -f "$OSXCROSS_DIR/target/bin/o64-clang" ]; then
        ok "osxcross already built: $OSXCROSS_DIR"
        return
    fi

    info "Setting up osxcross..."

    # Пробуем несколько источников готовых сборок (без компиляции LLVM).
    local PREBUILT_URLS=(
        "https://github.com/nicoverbruggen/osxcross-binaries/releases/latest/download/osxcross-14.0-ubuntu-22.04.tar.xz"
        "https://github.com/nicoverbruggen/osxcross-binaries/releases/latest/download/osxcross-14.0-ubuntu-24.04.tar.xz"
        "https://github.com/nicoverbruggen/osxcross-binaries/releases/download/14.0/osxcross-14.0-ubuntu-22.04.tar.xz"
    )
    local PREBUILT_TAR="/tmp/osxcross-prebuilt.tar.xz"
    local got_prebuilt=0

    for url in "${PREBUILT_URLS[@]}"; do
        info "Trying prebuilt: $(basename "$url")..."
        if wget --timeout=30 --tries=2 --show-progress -O "$PREBUILT_TAR" "$url" 2>&1; then
            mkdir -p "$OSXCROSS_DIR"
            tar xf "$PREBUILT_TAR" -C "$OSXCROSS_DIR" --strip-components=1 2>/dev/null || true
            if [ -f "$OSXCROSS_DIR/target/bin/o64-clang" ]; then
                got_prebuilt=1
                ok "Prebuilt osxcross installed from $(basename "$url")"
                rm -f "$PREBUILT_TAR"
                break
            fi
            rm -rf "$OSXCROSS_DIR/target" 2>/dev/null || true
        fi
        rm -f "$PREBUILT_TAR"
    done

    # Если готовая сборка недоступна — собираем из исходников.
    if [ "$got_prebuilt" -eq 0 ]; then
        warn "Prebuilt not available, building from source (one-time)..."
        warn "libtapi компилирует встроенный LLVM — это занимает 10-25 мин."
        warn "После завершения tools/osxcross/ сохраняется и повторно не собирается."

        if [ ! -d "$OSXCROSS_DIR/.git" ]; then
            rm -rf "$OSXCROSS_DIR"
            git clone https://github.com/tpoechtrager/osxcross.git "$OSXCROSS_DIR"
        fi

        # Скачиваем SDK
        if [ ! -f "$SDK_TAR" ]; then
            info "Downloading macOS SDK ${SDK_VER}..."
            wget -q --show-progress -O "$SDK_TAR" "$SDK_URL"
        fi

        mkdir -p "$OSXCROSS_DIR/tarballs"
        cp "$SDK_TAR" "$OSXCROSS_DIR/tarballs/"

        info "Building osxcross (libtapi+LLVM, using $(nproc) CPU cores + ninja)..."
        pushd "$OSXCROSS_DIR" > /dev/null
        # JOBS — количество параллельных потоков сборки.
        # NINJA=1 — использовать ninja вместо make (быстрее для LLVM).
        UNATTENDED=1 \
        OSX_VERSION_MIN=11.0 \
        JOBS="$(nproc)" \
        NINJA=1 \
        ./build.sh 2>&1 | grep -E "^##|^\[|^-- Build|Building |built |installed|error:" || true
        popd > /dev/null
    fi

    [ -f "$OSXCROSS_DIR/target/bin/o64-clang" ] || fatal "osxcross build failed"
    ok "osxcross ready"
}

# ---- OpenSSL для darwin ------------------------------------------------------

download_openssl() {
    if [ ! -f "$OPENSSL_TAR" ]; then
        info "Downloading OpenSSL ${OPENSSL_VER}..."
        wget -q -O "$OPENSSL_TAR" "$OPENSSL_URL"
    fi
}

# build_openssl_darwin <target> <cc> <install_dir>
# target: darwin64-arm64-cc или darwin64-x86_64-cc
build_openssl_darwin() {
    local target="$1" cc="$2" dest="$3"

    if [ -f "$dest/lib/libssl.a" ]; then
        ok "OpenSSL already built: $dest"
        return
    fi

    info "Building OpenSSL ${OPENSSL_VER} for $target..."
    download_openssl
    rm -rf "$OPENSSL_SRC"
    tar xf "$OPENSSL_TAR" -C /tmp
    pushd "$OPENSSL_SRC" > /dev/null

    # Находим osxcross AR/RANLIB — нужны для правильного __.SYMDEF в архивах,
    # без которого ld64 не находит символы в .a файлах.
    local triple_prefix
    triple_prefix=$(basename "$cc" | sed 's/-clang$//')
    local cross_ar="${OSXCROSS_DIR}/target/bin/${triple_prefix}-ar"
    local cross_ranlib="${OSXCROSS_DIR}/target/bin/${triple_prefix}-ranlib"
    [ -f "$cross_ar" ] || cross_ar="ar"
    [ -f "$cross_ranlib" ] || cross_ranlib="ranlib"

    # no-module — не собирать .dylib провайдеры (ломается при кросс-компиляции).
    # no-legacy — отключить устаревшие шифры (бикону нужны только AES-GCM + RSA-OAEP).
    CC="$cc" AR="$cross_ar" RANLIB="$cross_ranlib" \
    ./Configure "$target" \
        no-shared no-tests no-module no-legacy no-quic no-apps \
        --prefix="$dest" \
        -mmacosx-version-min=11.0

    make -j"$(nproc)" CC="$cc" AR="$cross_ar" RANLIB="$cross_ranlib" 2>&1 | tail -3
    mkdir -p "$dest"
    make install_sw > /dev/null 2>&1
    popd > /dev/null
    ok "OpenSSL installed: $dest"
}

# ---- Сборка бикона -----------------------------------------------------------

# build_beacon_macos <arch> <triple> <openssl_dir> <output_name>
build_beacon_macos() {
    local arch="$1" triple="$2" ssl="$3" out="$4"
    local build_dir="out/build/beacon-macos-${arch}"
    local cc="${OSXCROSS_DIR}/target/bin/${triple}-clang"

    if [ ! -f "$cc" ]; then
        fatal "Cross-compiler not found: $cc"
    fi

    info "Building macOS beacon for ${arch}..."

    # CMAKE_SYSTEM_NAME=Darwin — кросс-компиляция для macOS.
    # Указываем пути к OpenSSL явно — find_package ненадёжен при кросс-компиляции.
    local ssl_lib="$ssl/lib"
    # OpenSSL 3.x иногда ставит в lib64
    [ -f "$ssl_lib/libssl.a" ] || ssl_lib="$ssl/lib64"

    cmake -B "$build_dir" -S beacon-linux \
        -DCMAKE_SYSTEM_NAME=Darwin \
        -DCMAKE_C_COMPILER="$cc" \
        -DCMAKE_OSX_ARCHITECTURES="$arch" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="11.0" \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR="$ssl" \
        -DOPENSSL_INCLUDE_DIR="$ssl/include" \
        -DOPENSSL_CRYPTO_LIBRARY="$ssl_lib/libcrypto.a" \
        -DOPENSSL_SSL_LIBRARY="$ssl_lib/libssl.a" \
        -DOPENSSL_USE_STATIC_LIBS=TRUE

    cmake --build "$build_dir" --parallel "$(nproc)" 2>&1 | grep -E "^\[|^Linking|^Built|^-- " || true

    # Mach-O executable
    if [ -f "$build_dir/beacon-macos" ]; then
        cp "$build_dir/beacon-macos" "$BIN_DIR/${out}"
        ok "$out -> $BIN_DIR/${out}"
    fi

    # Dynamic library (.dylib)
    if [ -f "$build_dir/beacon-macos.dylib" ]; then
        cp "$build_dir/beacon-macos.dylib" "$BIN_DIR/${out}.dylib"
        ok "${out}.dylib -> $BIN_DIR/${out}.dylib"
    fi
}

# ---- Создание Universal Binary (fat) ----------------------------------------

make_universal() {
    local lipo="${OSXCROSS_DIR}/target/bin/x86_64-apple-darwin23-lipo"
    # Ищем lipo в osxcross
    if [ ! -f "$lipo" ]; then
        lipo=$(find "$OSXCROSS_DIR/target/bin" -name "*-lipo" 2>/dev/null | head -1)
    fi
    if [ -z "$lipo" ] || [ ! -f "$lipo" ]; then
        warn "lipo not found in osxcross — skipping universal binary"
        return
    fi

    local arm64_bin="$BIN_DIR/beacon-macos-arm64"
    local x64_bin="$BIN_DIR/beacon-macos-x64"
    local universal="$BIN_DIR/beacon-macos"

    # Universal executable
    if [ -f "$arm64_bin" ] && [ -f "$x64_bin" ]; then
        "$lipo" -create "$arm64_bin" "$x64_bin" -output "$universal"
        ok "Universal binary: $universal"
    fi

    # Universal dylib
    if [ -f "${arm64_bin}.dylib" ] && [ -f "${x64_bin}.dylib" ]; then
        "$lipo" -create "${arm64_bin}.dylib" "${x64_bin}.dylib" -output "${universal}.dylib"
        ok "Universal dylib: ${universal}.dylib"
    fi
}

# ---- Основной поток ----------------------------------------------------------

install_deps
setup_osxcross

# Определяем triple (зависит от версии SDK — darwin23 для SDK 14.0)
DARWIN_VER="darwin23"
TRIPLE_ARM64="aarch64-apple-${DARWIN_VER}"
TRIPLE_X64="x86_64-apple-${DARWIN_VER}"

# Добавляем osxcross в PATH
export PATH="$OSXCROSS_DIR/target/bin:$PATH"

# ---- ARM64 (Apple Silicon) ---------------------------------------------------

if [ "$TARGET" = "all" ] || [ "$TARGET" = "arm64" ]; then
    CC_ARM64="${OSXCROSS_DIR}/target/bin/${TRIPLE_ARM64}-clang"
    if [ ! -f "$CC_ARM64" ]; then
        # Попробуем найти по маске
        CC_ARM64=$(find "$OSXCROSS_DIR/target/bin" -name "aarch64-apple-darwin*-clang" ! -name "*++" 2>/dev/null | head -1)
        TRIPLE_ARM64=$(basename "$CC_ARM64" | sed 's/-clang$//')
    fi
    [ -f "$CC_ARM64" ] || fatal "aarch64-apple-darwin*-clang not found in osxcross"

    SSL_MACOS_ARM64="$SSL_PREFIX/darwin-arm64"
    build_openssl_darwin "darwin64-arm64-cc" "$CC_ARM64" "$SSL_MACOS_ARM64"
    build_beacon_macos "arm64" "$TRIPLE_ARM64" "$SSL_MACOS_ARM64" "beacon-macos-arm64"
fi

# ---- x86_64 (Intel) ----------------------------------------------------------

if [ "$TARGET" = "all" ] || [ "$TARGET" = "x64" ]; then
    CC_X64="${OSXCROSS_DIR}/target/bin/${TRIPLE_X64}-clang"
    if [ ! -f "$CC_X64" ]; then
        CC_X64=$(find "$OSXCROSS_DIR/target/bin" -name "x86_64-apple-darwin*-clang" ! -name "*++" 2>/dev/null | head -1)
        TRIPLE_X64=$(basename "$CC_X64" | sed 's/-clang$//')
    fi
    [ -f "$CC_X64" ] || fatal "x86_64-apple-darwin*-clang not found in osxcross"

    SSL_MACOS_X64="$SSL_PREFIX/darwin-x64"
    build_openssl_darwin "darwin64-x86_64-cc" "$CC_X64" "$SSL_MACOS_X64"
    build_beacon_macos "x86_64" "$TRIPLE_X64" "$SSL_MACOS_X64" "beacon-macos-x64"
fi

# ---- Universal binary --------------------------------------------------------

if [ "$TARGET" = "all" ]; then
    make_universal
fi

# ---- Итог --------------------------------------------------------------------

echo ""
ok "macOS beacon build complete:"
ls -lh "$BIN_DIR"/beacon-macos* 2>/dev/null || warn "No macOS beacons found in $BIN_DIR"
echo ""
info "Ad-hoc signing (run on macOS or with osxcross ldid):"
echo "  ldid -S $BIN_DIR/beacon-macos"
echo "  # или на маке: codesign --force --sign - $BIN_DIR/beacon-macos"
