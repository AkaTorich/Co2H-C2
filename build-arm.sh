#!/usr/bin/env bash
# Кросс-сборка Linux beacon'а и teamserver'а для ARM64 (aarch64) и ARM32 (armhf).
# Запускать на x86_64 Linux-хосте.
#
# Результат:
#   bin/beacons/beacon-linux-arm64      — статический ELF aarch64
#   bin/beacons/beacon-linux-arm64.so   — разделяемая библиотека aarch64
#   bin/beacons/beacon-linux-arm32      — статический ELF armhf
#   bin/beacons/beacon-linux-arm32.so   — разделяемая библиотека armhf
#   bin/teamserver-arm64                — teamserver aarch64
#
# Использование:
#   ./build-arm.sh              — собрать всё (биконы + teamserver)
#   ./build-arm.sh arm64        — только биконы aarch64
#   ./build-arm.sh arm32        — только биконы armhf
#   ./build-arm.sh server       — только teamserver aarch64

set -euo pipefail
cd "$(dirname "$0")"

info()  { echo -e "\033[36m[*] $1\033[0m"; }
ok()    { echo -e "\033[32m[+] $1\033[0m"; }
warn()  { echo -e "\033[33m[!] $1\033[0m"; }
fatal() { echo -e "\033[31m[!] $1\033[0m"; exit 1; }

OPENSSL_VER="3.3.0"
OPENSSL_SRC="/tmp/openssl-${OPENSSL_VER}"
OPENSSL_TAR="/tmp/openssl-${OPENSSL_VER}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz"

BIN_DIR="bin/beacons"
mkdir -p "$BIN_DIR"

TARGET="${1:-all}"

# ---- Вспомогательные функции ------------------------------------------------

download_openssl() {
    if [ ! -f "$OPENSSL_TAR" ]; then
        info "Downloading OpenSSL ${OPENSSL_VER}..."
        wget -q -O "$OPENSSL_TAR" "$OPENSSL_URL"
    fi
}

# build_openssl <configure_target> <cross_prefix> <install_dir>
build_openssl() {
    local target="$1" prefix="$2" dest="$3"
    if [ -f "$dest/lib/libssl.a" ] || [ -f "$dest/lib64/libssl.a" ]; then
        ok "OpenSSL already built: $dest"
        return
    fi
    info "Building OpenSSL ${OPENSSL_VER} for $target..."
    download_openssl
    rm -rf "$OPENSSL_SRC"
    tar xf "$OPENSSL_TAR" -C /tmp
    pushd "$OPENSSL_SRC" > /dev/null
    # Бикону нужны только AES-256-GCM + RSA-OAEP + SHA-256 + RAND —
    # отключаем всё лишнее для минимального размера.
    ./Configure "$target" \
        no-shared no-tests no-module no-legacy no-quic no-apps \
        no-cms no-comp no-ct no-dgram no-dh no-dsa no-dtls no-ec2m \
        no-engine no-gost no-idea no-md2 no-md4 no-mdc2 no-ocsp \
        no-rc2 no-rc4 no-rc5 no-rmd160 no-seed no-siphash \
        no-sm2 no-sm3 no-sm4 no-srp no-srtp no-ts no-whirlpool \
        no-camellia no-aria no-bf no-blake2 no-cast no-chacha \
        no-cmac no-des no-poly1305 no-scrypt no-siv \
        no-ec no-ecdh no-ecdsa no-tls1 no-tls1_1 no-ssl3 no-dtls1 \
        --prefix="$dest" \
        --cross-compile-prefix="$prefix"
    make -j"$(nproc)" 2>&1 | tail -5
    mkdir -p "$dest"
    make install_sw
    popd > /dev/null
    ok "OpenSSL installed: $dest"
}

# build_beacon <arch_label> <compiler> <openssl_dir> <output_name>
build_beacon() {
    local arch="$1" cc="$2" ssl="$3" out="$4"
    local build_dir="out/build/beacon-linux-${arch}"

    info "Building beacon for ${arch}..."
    cmake -B "$build_dir" -S beacon-linux \
        -DCMAKE_C_COMPILER="$cc" \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR="$ssl" \
        -DOPENSSL_USE_STATIC_LIBS=TRUE \
        -DBEACON_STATIC=ON

    cmake --build "$build_dir" --parallel "$(nproc)" 2>&1 | grep -E "^\[|^Linking|^Built|^Scanning|^-- " || true

    # ELF-бинарник
    cp "$build_dir/beacon-linux64" "$BIN_DIR/$out"
    ok "$out -> $BIN_DIR/$out"

    # Разделяемая библиотека (.so)
    if [ -f "$build_dir/beacon-linux64.so" ]; then
        cp "$build_dir/beacon-linux64.so" "$BIN_DIR/${out}.so"
        ok "${out}.so -> $BIN_DIR/${out}.so"
    fi
}

# ---- Проверка кросс-компиляторов -------------------------------------------

install_cross_toolchain() {
    local pkgs=""
    if [ "$TARGET" = "all" ] || [ "$TARGET" = "arm64" ] || [ "$TARGET" = "server" ]; then
        command -v aarch64-linux-gnu-gcc > /dev/null || pkgs="$pkgs gcc-aarch64-linux-gnu"
        command -v aarch64-linux-gnu-g++ > /dev/null || pkgs="$pkgs g++-aarch64-linux-gnu"
    fi
    if [ "$TARGET" = "all" ] || [ "$TARGET" = "arm32" ]; then
        command -v arm-linux-gnueabihf-gcc > /dev/null || pkgs="$pkgs gcc-arm-linux-gnueabihf"
    fi
    if [ -n "$pkgs" ]; then
        info "Installing cross-compilers:$pkgs"
        sudo apt-get update
        sudo apt-get install -y $pkgs
    fi
}

install_cross_toolchain

# ---- ARM64 (aarch64) -------------------------------------------------------

SSL_PREFIX="$(pwd)/out/openssl"

if [ "$TARGET" = "all" ] || [ "$TARGET" = "arm64" ]; then
    command -v aarch64-linux-gnu-gcc > /dev/null || fatal "aarch64-linux-gnu-gcc not found"
    SSL_ARM64="$SSL_PREFIX/aarch64"
    build_openssl "linux-aarch64" "aarch64-linux-gnu-" "$SSL_ARM64"
    build_beacon "arm64" "aarch64-linux-gnu-gcc" "$SSL_ARM64" "beacon-linux-arm64"
fi

# ---- ARM32 (armhf) ---------------------------------------------------------

if [ "$TARGET" = "all" ] || [ "$TARGET" = "arm32" ]; then
    command -v arm-linux-gnueabihf-gcc > /dev/null || fatal "arm-linux-gnueabihf-gcc not found"
    SSL_ARM32="$SSL_PREFIX/armhf"
    build_openssl "linux-armv4" "arm-linux-gnueabihf-" "$SSL_ARM32"
    build_beacon "arm32" "arm-linux-gnueabihf-gcc" "$SSL_ARM32" "beacon-linux-arm32"
fi

# ---- Teamserver ARM64 (aarch64) --------------------------------------------

if [ "$TARGET" = "all" ] || [ "$TARGET" = "server" ]; then
    command -v aarch64-linux-gnu-g++ > /dev/null || fatal "aarch64-linux-gnu-g++ not found"

    SSL_ARM64="${SSL_PREFIX}/aarch64"
    # OpenSSL для teamserver'а нужен полный (TLS + крипто), пересобираем без урезания.
    SSL_SERVER="${SSL_PREFIX}/aarch64-server"
    if [ ! -f "$SSL_SERVER/lib/libssl.a" ] && [ ! -f "$SSL_SERVER/lib64/libssl.a" ]; then
        info "Building full OpenSSL ${OPENSSL_VER} for teamserver (aarch64)..."
        download_openssl
        rm -rf "$OPENSSL_SRC"
        tar xf "$OPENSSL_TAR" -C /tmp
        pushd "$OPENSSL_SRC" > /dev/null
        ./Configure linux-aarch64 \
            no-shared no-tests no-apps \
            --prefix="$SSL_SERVER" \
            --cross-compile-prefix="aarch64-linux-gnu-"
        make -j"$(nproc)" 2>&1 | tail -5
        mkdir -p "$SSL_SERVER"
        make install_sw
        popd > /dev/null
        ok "OpenSSL (full) installed: $SSL_SERVER"
    else
        ok "OpenSSL (full) already built: $SSL_SERVER"
    fi

    SERVER_BUILD="out/build/teamserver-arm64"
    info "Building teamserver for aarch64..."
    cmake -B "$SERVER_BUILD" -S . \
        -DCMAKE_C_COMPILER="aarch64-linux-gnu-gcc" \
        -DCMAKE_CXX_COMPILER="aarch64-linux-gnu-g++" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
        -DOPENSSL_ROOT_DIR="$SSL_SERVER" \
        -DOPENSSL_USE_STATIC_LIBS=TRUE \
        -DCO2H_BUILD_SERVER=ON \
        -DCO2H_BUILD_CLIENT=OFF \
        -DCO2H_BUILD_BEACON=OFF \
        -DCO2H_BUILD_TOOLS=OFF \
        -DCO2H_BUILD_TESTS=OFF

    cmake --build "$SERVER_BUILD" --target co2h_server --parallel "$(nproc)" 2>&1 | grep -E "^\[|^Linking|^Built" || true

    mkdir -p bin
    cp "$SERVER_BUILD/server/teamserver" "bin/teamserver-arm64"
    ok "teamserver-arm64 -> bin/teamserver-arm64"
fi

# ---- Итог -------------------------------------------------------------------

echo ""
ok "ARM build complete:"
ls -lh "$BIN_DIR"/beacon-linux-arm* 2>/dev/null || warn "No ARM beacons found in $BIN_DIR"
ls -lh bin/teamserver-arm* 2>/dev/null || true
