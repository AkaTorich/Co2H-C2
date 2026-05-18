#!/usr/bin/env bash
# Сборка сервера и клиента Co2H на Linux (запускать на Linux-машине).
# Результат: bin/ — полностью автономный дистрибутив.
set -euo pipefail
cd "$(dirname "$0")"

info()  { echo -e "\033[36m[*] $1\033[0m"; }
ok()    { echo -e "\033[32m[+] $1\033[0m"; }
fatal() { echo -e "\033[31m[!] $1\033[0m"; exit 1; }

# Автоустановка зависимостей (Debian/Ubuntu).
PACKAGES="build-essential cmake git pkg-config qt6-base-dev qt6-svg-dev qt6-base-private-dev libgl1-mesa-dev libssl-dev libsqlite3-dev"
MISSING=""
for pkg in $PACKAGES; do
    dpkg -s "$pkg" >/dev/null 2>&1 || MISSING="$MISSING $pkg"
done
if [ -n "$MISSING" ]; then
    info "Installing missing packages:$MISSING"
    sudo apt-get update
    sudo apt-get install -y $MISSING
fi

for cmd in cmake g++; do
    command -v "$cmd" >/dev/null || fatal "$cmd not found"
done

BUILD_DIR="out/build/linux"
BIN_DIR="bin"
LIB_DIR="$BIN_DIR/lib"
PLG_DIR="$BIN_DIR/plugins"

# Удаляем кеш предыдущей конфигурации если CMake нашёл не тот Qt6
# (например Windows Qt6 через /mnt/c вместо системного).
if [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
    if grep -q 'Qt6_DIR.*=/mnt/' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null; then
        info "Cached config points to Windows Qt — removing build cache..."
        rm -rf "$BUILD_DIR"
    fi
fi

# В WSL пути Windows (/mnt/c/...) попадают в $PATH, из-за чего CMake
# находит Windows-версию Qt6 вместо системной. Вырезаем /mnt/* из PATH.
CLEAN_PATH=$(echo "$PATH" | tr ':' '\n' | grep -v '^/mnt/' | tr '\n' ':' | sed 's/:$//')
export PATH="$CLEAN_PATH"
info "Cleaned PATH (removed /mnt/* entries)"

# Определяем системный Qt6 — /usr или /usr/lib/x86_64-linux-gnu/cmake
QT6_SYSTEM_DIR=""
for d in /usr/lib/x86_64-linux-gnu/cmake/Qt6 /usr/lib/cmake/Qt6 /usr/lib64/cmake/Qt6; do
    if [ -d "$d" ]; then
        QT6_SYSTEM_DIR="$d"
        break
    fi
done
[ -z "$QT6_SYSTEM_DIR" ] && fatal "System Qt6 cmake config not found"
ok "System Qt6: $QT6_SYSTEM_DIR"

# Конфигурация — пропускаем если CMakeCache.txt уже есть и валиден.
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    info "CMake configure..."
    cmake -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="/usr" \
        -DQt6_DIR="$QT6_SYSTEM_DIR" \
        -DCO2H_BUILD_CLIENT=ON \
        -DCO2H_BUILD_SERVER=ON \
        -DCO2H_BUILD_BEACON=OFF \
        -DCO2H_BUILD_TOOLS=ON \
        -DCO2H_BUILD_TESTS=OFF
    ok "Configure done"
else
    ok "CMake cache exists — skipping configure"
fi

info "Building..."
cmake --build "$BUILD_DIR" --parallel "$(nproc)" 2>&1 | grep -E "^\[|^Linking|^Built|^Scanning|^-- " || true
ok "Build done"

# ---- Собираем дистрибутив --------------------------------------------------
mkdir -p "$BIN_DIR" "$LIB_DIR"

cp "$BUILD_DIR/server/teamserver"              "$BIN_DIR/teamserver"
cp "$BUILD_DIR/client/co2h-client"             "$BIN_DIR/co2h-client"
cp "$BUILD_DIR/tools/artifact-gen/artifact-gen" "$BIN_DIR/artifact-gen"

# Зависимости через ldd (исключаем базовые системные).
collect_deps() {
    ldd "$1" 2>/dev/null \
        | awk '/=>/ && !/linux-vdso|ld-linux|libc\.so|libm\.so|libdl\.so|libpthread\.so|librt\.so|libresolv\.so|libnsl\.so|libgcc_s/ {print $3}' \
        | sort -u
}

info "Collecting shared libraries..."
ALL_DEPS=$(mktemp)
for bin in "$BIN_DIR/teamserver" "$BIN_DIR/co2h-client"; do
    collect_deps "$bin" >> "$ALL_DEPS"
done
sort -u "$ALL_DEPS" | while read -r so; do
    [ -f "$so" ] && cp -L "$so" "$LIB_DIR/" 2>/dev/null || true
done
rm -f "$ALL_DEPS"

# Рекурсивные зависимости.
for so in "$LIB_DIR"/*.so*; do
    collect_deps "$so" | while read -r dep; do
        base=$(basename "$dep")
        [ ! -f "$LIB_DIR/$base" ] && [ -f "$dep" ] && cp -L "$dep" "$LIB_DIR/" 2>/dev/null || true
    done
done

# Qt6 плагины.
QT6_PLUGIN_DIR=""
for d in /usr/lib/x86_64-linux-gnu/qt6/plugins /usr/lib/qt6/plugins /usr/lib64/qt6/plugins; do
    [ -d "$d" ] && QT6_PLUGIN_DIR="$d" && break
done

if [ -n "$QT6_PLUGIN_DIR" ]; then
    for sub in platforms xcbglintegrations iconengines imageformats tls; do
        if [ -d "$QT6_PLUGIN_DIR/$sub" ]; then
            mkdir -p "$PLG_DIR/$sub"
            cp -L "$QT6_PLUGIN_DIR/$sub"/*.so "$PLG_DIR/$sub/" 2>/dev/null || true
        fi
    done
    # Зависимости плагинов.
    for so in "$PLG_DIR"/*/*.so; do
        collect_deps "$so" | while read -r dep; do
            base=$(basename "$dep")
            [ ! -f "$LIB_DIR/$base" ] && [ -f "$dep" ] && cp -L "$dep" "$LIB_DIR/" 2>/dev/null || true
        done
    done
fi

echo "  $(ls "$LIB_DIR" | wc -l) shared libraries"
echo "  $(find "$PLG_DIR" -name '*.so' 2>/dev/null | wc -l) Qt plugins"

# Launcher-скрипты.
cat > "$BIN_DIR/run-client.sh" << 'LAUNCHER'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export LD_LIBRARY_PATH="$DIR/lib:$LD_LIBRARY_PATH"
export QT_PLUGIN_PATH="$DIR/plugins"
# Allow teamserver to bind ports below 1024 (e.g. 443) without root.
sudo setcap cap_net_bind_service=+ep "$DIR/teamserver" 2>/dev/null || true
"$DIR/co2h-client" "$@" &
disown
LAUNCHER

chmod +x "$BIN_DIR/teamserver" "$BIN_DIR/co2h-client" "$BIN_DIR/artifact-gen" \
         "$BIN_DIR/run-client.sh"

# Конфиги и сертификаты.
for sub in certs configs profiles; do
    if [ -d "$sub" ]; then
        mkdir -p "$BIN_DIR/$sub"
        cp -r "$sub"/* "$BIN_DIR/$sub/" 2>/dev/null || true
    fi
done

# ---- Каталог шаблонных биконов -----------------------------------------------
# Windows-биконы (beacon64.exe/dll, beacon32.exe/dll) собираются build.ps1,
# Linux-биконы собираются ниже. Все шаблоны лежат в bin/beacons/.
BEACONS_DST="$BIN_DIR/beacons"
mkdir -p "$BEACONS_DST"

if [ -d "$BEACONS_DST" ]; then
    WBC=$(find "$BEACONS_DST" -maxdepth 1 -name "beacon*.exe" -o -name "beacon*.dll" 2>/dev/null | wc -l)
    if [ "$WBC" -gt 0 ]; then
        ok "Found $WBC Windows beacon(s) in beacons/"
    else
        info "No Windows beacons in beacons/ (build on Windows first with build.ps1)"
    fi
fi

# ---- Linux beacon build ------------------------------------------------------
if [ -d "beacon-linux" ] && [ -f "beacon-linux/CMakeLists.txt" ]; then
    info "Building Linux beacon..."
    BEACON_LNX_BUILD="$BUILD_DIR/beacon-linux"
    if cmake -B "$BEACON_LNX_BUILD" -S beacon-linux \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_USE_STATIC_LIBS=TRUE 2>&1; then
        if cmake --build "$BEACON_LNX_BUILD" --parallel "$(nproc)" 2>&1 | grep -E "^\[|^Linking|^Built|^Scanning|^-- " || true; then
            cp "$BEACON_LNX_BUILD/beacon-linux64" "$BEACONS_DST/beacon-linux64" 2>/dev/null && \
                ok "beacon-linux64 (ELF) -> beacons/"
            cp "$BEACON_LNX_BUILD/beacon-linux64.so" "$BEACONS_DST/beacon-linux64.so" 2>/dev/null && \
                ok "beacon-linux64.so -> beacons/"
        else
            info "beacon-linux build failed"
        fi
    else
        info "beacon-linux cmake configure failed"
    fi
fi

# ---- Plugins build (all subdirectories of plugins/) -------------------------
# На Linux символы PluginContext доступны через -rdynamic (клиент экспортирует их).
# Import-библиотека не нужна.
PLUGINS_SRC="plugins"
if [ -d "$PLUGINS_SRC" ]; then
    for pdir in "$PLUGINS_SRC"/*/; do
        [ ! -f "${pdir}CMakeLists.txt" ] && continue
        pname=$(basename "$pdir")
        pbuild="out/build/plugin-${pname}-linux"
        info "Building plugin: $pname..."
        cmake -B "$pbuild" -S "$pdir" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_PREFIX_PATH="/usr" \
            -DQt6_DIR="$QT6_SYSTEM_DIR" \
            -DCO2H_CLIENT_LIB=""
        if cmake --build "$pbuild" --parallel "$(nproc)" 2>&1 | grep -E "^\[|^Linking|^Built|^Scanning|^-- " || true; then
            # Копируем все .so из plugins/ в дистрибутив.
            found=0
            for so in "$pbuild"/plugins/*.so "$pbuild"/plugins/lib*.so; do
                if [ -f "$so" ]; then
                    cp "$so" "$PLG_DIR/"
                    ok "plugins/$pname -> $PLG_DIR/$(basename "$so")"
                    found=1
                fi
            done
            if [ "$found" -eq 0 ]; then
                echo -e "\033[33m[!] Plugin '$pname': no .so found\033[0m"
            fi
        else
            echo -e "\033[33m[!] Plugin '$pname' build failed\033[0m"
        fi
    done
fi

# ---- Plugin SDK -------------------------------------------------------------
if [ -d "sdk" ]; then
    mkdir -p "$BIN_DIR/sdk"
    cp -r sdk/* "$BIN_DIR/sdk/"
    ok "sdk/ -> $BIN_DIR/sdk/"
fi

ok "bin/ ready"
echo ""
echo "  $BIN_DIR/run-client.sh   (launch client + server)"
echo "  $BIN_DIR/lib/            ($(ls "$LIB_DIR" | wc -l) .so)"
echo "  $BIN_DIR/beacons/        (beacon templates)"
echo "  $BIN_DIR/plugins/        (Qt6 plugins + co2h plugins)"
echo "  $BIN_DIR/sdk/            (plugin SDK)"
echo ""
