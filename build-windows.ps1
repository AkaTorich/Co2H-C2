#Requires -Version 5.1
param(
    [switch] $NoCerts,
    [switch] $NoBeacon,
    [switch] $Tests,
    [switch] $Clean
)

$Config = "Release"

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function info  { param($m) Write-Host "[*] $m" -ForegroundColor Cyan  }
function ok    { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function fatal { param($m) Write-Host "[!] $m" -ForegroundColor Red; exit 1 }

# ---- cmake (prefer 3.x, avoid 4.x which breaks msgpack-c) ------------------
$cmakeCandidates = @(
    "$env:USERPROFILE\cmake-3.31.6-windows-x86_64\bin\cmake.exe",
    "C:\Qt\Tools\CMake_64\bin\cmake.exe"
)
$cmake = $null
foreach ($c in $cmakeCandidates) {
    if (Test-Path $c) { $cmake = $c; break }
}
if (-not $cmake) {
    $found = Get-Command cmake -ErrorAction SilentlyContinue
    if ($found) { $cmake = $found.Source }
}
if (-not $cmake) { fatal "cmake not found" }
ok "cmake: $cmake"

# ---- Ninja (быстрее MSBuild в 2-3 раза) ------------------------------------
$useNinja = $false
$ninjaFound = Get-Command ninja -ErrorAction SilentlyContinue
# Встроенный Ninja из Visual Studio несовместим с cmake 3.31 на длинных путях —
# используем только отдельно установленный ninja.
if ($ninjaFound -and ($ninjaFound.Source -notlike '*Visual Studio*')) {
    # Ninja требует MSVC-окружение — ищем vcvars64.bat
    $vsSearchPaths = @(
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise',
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional',
        'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community',
        'C:\Program Files\Microsoft Visual Studio\2022\Community'
    )
    $vcvars64 = $null
    foreach ($p in $vsSearchPaths) {
        $vc = Join-Path $p 'VC\Auxiliary\Build\vcvars64.bat'
        if (Test-Path $vc) { $vcvars64 = $vc; break }
    }
    if ($vcvars64 -and (-not $env:VSCMD_ARG_TGT_ARCH)) {
        info "Importing MSVC x64 environment..."
        $tmpBat = [System.IO.Path]::GetTempFileName() + '.bat'
        $batBody = "@echo off`r`ncall `"$vcvars64`" >NUL 2>&1`r`nif errorlevel 1 exit /b 1`r`nset`r`n"
        [System.IO.File]::WriteAllText($tmpBat, $batBody, [System.Text.Encoding]::ASCII)
        $envDump = & cmd.exe /c $tmpBat
        $rc = $LASTEXITCODE
        Remove-Item $tmpBat -Force -ErrorAction SilentlyContinue
        if ($rc -eq 0) {
            foreach ($line in $envDump) {
                if ($line -match '^([^=]+)=(.*)$') {
                    Set-Item -Path ("Env:" + $Matches[1]) -Value $Matches[2]
                }
            }
            $useNinja = $true
        }
    } elseif ($env:VSCMD_ARG_TGT_ARCH) {
        # Уже в Developer Command Prompt
        $useNinja = $true
    }
}
if ($useNinja) { ok "Using Ninja" } else { ok "Using MSBuild" }

# Ninja — single-config, выходные файлы без подпапки Release/.
# VS generator — multi-config, бинарники в ...\Release\ и т.д.
if ($useNinja) { $cfgSub = "" } else { $cfgSub = "\$Config" }

# ---- Qt6 -------------------------------------------------------------------
$qt6Candidates = @(
    "C:\Qt\6.10.2\6.10.2\msvc2022_64\lib\cmake\Qt6",
    "C:\Qt\6.8.2\6.8.2\msvc2022_64\lib\cmake\Qt6",
    "C:\Qt\6.8.3\msvc2022_64\lib\cmake\Qt6",
    "C:\Qt\6.7.3\msvc2022_64\lib\cmake\Qt6"
)
$qt6 = $null
foreach ($q in $qt6Candidates) {
    if (Test-Path $q) { $qt6 = $q; break }
}
if (-not $qt6) { fatal "Qt6 not found (looked in C:\Qt\...)" }
ok "Qt6: $qt6"

# ---- OpenSSL ---------------------------------------------------------------
$ssl = "C:\Program Files\OpenSSL-Win64"
if (-not (Test-Path "$ssl\include\openssl\ssl.h")) { fatal "OpenSSL not found: $ssl" }
$sslCrypto = "$ssl\lib\VC\x64\MD\libcrypto.lib"
$sslSSL    = "$ssl\lib\VC\x64\MD\libssl.lib"
ok "OpenSSL: $ssl"

# ---- openssl.exe -----------------------------------------------------------
$opensslExe = $null
if (Test-Path "$ssl\bin\openssl.exe") {
    $opensslExe = "$ssl\bin\openssl.exe"
} else {
    $found = Get-Command openssl -ErrorAction SilentlyContinue
    if ($found) { $opensslExe = $found.Source }
}

# ---- certificates ----------------------------------------------------------
if (-not $NoCerts) {
    $certsDir = Join-Path $PSScriptRoot "certs"
    $needCerts = (-not (Test-Path "$certsDir\ca.crt")) -or
                 (-not (Test-Path "$certsDir\server.crt")) -or
                 (-not (Test-Path "$certsDir\operator.crt"))

    if ($needCerts) {
        if (-not $opensslExe) { fatal "openssl.exe not found - cannot generate certs" }
        info "Generating TLS certificates..."
        $env:PATH = "$ssl\bin;$env:PATH"
        $genCerts = Join-Path $PSScriptRoot "scripts\gen-certs.ps1"
        & $genCerts
        ok "Certificates ready: $certsDir"
    } else {
        ok "Certificates already exist, skipping"
    }
}

# ---- CMake configure -------------------------------------------------------
$buildDir = Join-Path $PSScriptRoot "out\build\full"

# При -Clean удаляем билд-папки целиком - гарантия пересборки
# (OneDrive ломает mtime, MSBuild .tlog может быть протухшим).
if ($Clean) {
    info "Clean build requested - removing out\build\..."
    $buildRoot = Join-Path $PSScriptRoot "out\build"
    if (Test-Path $buildRoot) {
        Remove-Item $buildRoot -Recurse -Force -ErrorAction SilentlyContinue
        ok "Build directory cleaned"
    }
}

info "CMake configure ($Config)..."

$buildBeacon = if ($NoBeacon) { "OFF" } else { "ON" }
$buildTests  = if ($Tests)    { "ON"  } else { "OFF" }

# Qt prefix dir (parent of bin/moc.exe) - ensures CMake picks correct moc
$qt6Prefix = Split-Path (Split-Path (Split-Path $qt6))

if ($useNinja) {
    # cmake выводит deprecation-предупреждения thirdparty в stderr;
    # $ErrorActionPreference='Stop' трактует их как ошибку — подавляем.
    $ErrorActionPreference = "Continue"
    & $cmake `
        -S $PSScriptRoot `
        -B $buildDir `
        -G Ninja `
        -Wno-dev `
        "-DCMAKE_BUILD_TYPE=$Config" `
        "-DCMAKE_PREFIX_PATH=$qt6Prefix" `
        "-DOPENSSL_ROOT_DIR=$ssl" `
        "-DOPENSSL_CRYPTO_LIBRARY=$sslCrypto" `
        "-DOPENSSL_SSL_LIBRARY=$sslSSL" `
        "-DQt6_DIR=$qt6" `
        -DCO2H_BUILD_SERVER=ON `
        -DCO2H_BUILD_CLIENT=ON `
        "-DCO2H_BUILD_BEACON=$buildBeacon" `
        "-DCO2H_BUILD_TOOLS=$buildBeacon" `
        "-DCO2H_BUILD_TESTS=$buildTests"
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) { fatal "cmake configure failed (exit $LASTEXITCODE)" }
} else {
    $ErrorActionPreference = "Continue"
    & $cmake `
        -S $PSScriptRoot `
        -B $buildDir `
        -G "Visual Studio 17 2022" -A x64 `
        -Wno-dev `
        "-DCMAKE_PREFIX_PATH=$qt6Prefix" `
        "-DOPENSSL_ROOT_DIR=$ssl" `
        "-DOPENSSL_CRYPTO_LIBRARY=$sslCrypto" `
        "-DOPENSSL_SSL_LIBRARY=$sslSSL" `
        "-DQt6_DIR=$qt6" `
        -DCO2H_BUILD_SERVER=ON `
        -DCO2H_BUILD_CLIENT=ON `
        "-DCO2H_BUILD_BEACON=$buildBeacon" `
        "-DCO2H_BUILD_TOOLS=$buildBeacon" `
        "-DCO2H_BUILD_TESTS=$buildTests"
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) { fatal "CMake configure failed" }
}
ok "Configure done"

# ---- build -----------------------------------------------------------------
info "Building ($Config)..."

$targets = [System.Collections.ArrayList]@("co2h_server", "co2h_client")
if (-not $NoBeacon) {
    [void]$targets.Add("co2h_beacon")
    [void]$targets.Add("co2h_beacon_exe")
    [void]$targets.Add("artifact_gen")
}
if ($Tests) { [void]$targets.Add("co2h_tests") }

foreach ($t in $targets) {
    info "  -> $t"
    $ErrorActionPreference = "Continue"
    & $cmake --build $buildDir --config $Config --target $t --parallel 2
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) { fatal "Build failed: $t" }
}
ok "All targets built"

# ---- tests -----------------------------------------------------------------
if ($Tests) {
    info "Running tests..."
    $testExe = "$buildDir\tests$cs\co2h_tests.exe"
    & $testExe --gtest_color=yes
    if ($LASTEXITCODE -ne 0) { fatal "Tests failed" }
    ok "All tests passed"
}

# ---- x86 beacon ------------------------------------------------------------
if (-not $NoBeacon) {
    $buildDir32 = Join-Path $PSScriptRoot "out\build\full-x86"
    info "CMake configure x86 beacon..."
    $ErrorActionPreference = "Continue"
    & $cmake `
        -S $PSScriptRoot `
        -B $buildDir32 `
        -G "Visual Studio 17 2022" -A Win32 `
        -Wno-dev `
        -DCO2H_BUILD_SERVER=OFF `
        -DCO2H_BUILD_CLIENT=OFF `
        -DCO2H_BUILD_BEACON=ON `
        -DCO2H_BUILD_TOOLS=OFF `
        -DCO2H_BUILD_TESTS=OFF
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) { fatal "CMake configure x86 failed" }
    ok "x86 configure done"

    foreach ($t in @("co2h_beacon", "co2h_beacon_exe")) {
        info "  -> $t (x86)"
        $ErrorActionPreference = "Continue"
        & $cmake --build $buildDir32 --config $Config --target $t --parallel 2
        $ErrorActionPreference = "Stop"
        if ($LASTEXITCODE -ne 0) { fatal "x86 build failed: $t" }
    }
    ok "x86 beacon built"
}

# ---- collect into bin\ -----------------------------------------------------
$binDir = Join-Path $PSScriptRoot "bin"
if (-not (Test-Path $binDir)) { New-Item -ItemType Directory $binDir | Out-Null }

info "Collecting binaries to bin\..."

# Ninja кладёт бинарники в корень целевой папки, VS — в подпапку Release/.
$cs = if ($useNinja) { "" } else { "\$Config" }

Copy-Item "$buildDir\server$cs\teamserver.exe"  "$binDir\teamserver.exe"  -Force
Copy-Item "$buildDir\client$cs\co2h-client.exe" "$binDir\co2h-client.exe" -Force

if (-not $NoBeacon) {
    Copy-Item "$buildDir\tools\artifact-gen$cs\artifact-gen.exe" "$binDir\artifact-gen.exe" -Force

    # Биконы → bin\beacons\
    $beaconsDir = Join-Path $binDir "beacons"
    if (-not (Test-Path $beaconsDir)) { New-Item -ItemType Directory -Path $beaconsDir | Out-Null }

    Copy-Item "$buildDir\beacon$cs\beacon64.dll" "$beaconsDir\beacon64.dll" -Force
    Copy-Item "$buildDir\beacon$cs\beacon64.exe" "$beaconsDir\beacon64.exe" -Force

    $buildDir32 = Join-Path $PSScriptRoot "out\build\full-x86"
    if (Test-Path "$buildDir32\beacon\$Config\beacon32.dll") {
        Copy-Item "$buildDir32\beacon\$Config\beacon32.dll" "$beaconsDir\beacon32.dll" -Force
        Copy-Item "$buildDir32\beacon\$Config\beacon32.exe" "$beaconsDir\beacon32.exe" -Force
        ok "x86 beacon: beacon32.dll, beacon32.exe"
    }

    # Linux-биконы (если есть — собираются build-linux.sh / build-arm.sh)
    $linuxBeacons = @(
        "beacon-linux64", "beacon-linux64.so",
        "beacon-linux-arm64", "beacon-linux-arm64.so",
        "beacon-linux-arm32", "beacon-linux-arm32.so"
    )
    foreach ($lb in $linuxBeacons) {
        $src = Join-Path $binDir $lb
        if (Test-Path $src) {
            Move-Item $src "$beaconsDir\$lb" -Force
            ok "linux beacon: $lb -> beacons\"
        }
    }
}

# Batch-launcher: добавляет lib\ в PATH, QT_PLUGIN_PATH и запускает co2h-client.exe
@"
@echo off
set "PATH=%~dp0lib;%PATH%"
set "QT_PLUGIN_PATH=%~dp0plugins"
start "" "%~dp0co2h-client.exe" %*
"@ | Set-Content "$binDir\run-client.bat" -Encoding ASCII

# ---- lib/ — Qt6 runtime DLLs + OpenSSL (delay-loaded из main.cpp) ----------
$libDir = Join-Path $binDir "lib"
if (-not (Test-Path $libDir)) { New-Item -ItemType Directory $libDir | Out-Null }

$qt6Bin = Join-Path (Split-Path (Split-Path (Split-Path $qt6))) "bin"
$qt6Dlls = @(
    "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll",
    "Qt6Svg.dll", "Qt6Network.dll", "Qt6OpenGL.dll"
)
foreach ($dll in $qt6Dlls) {
    $src = Join-Path $qt6Bin $dll
    if (Test-Path $src) { Copy-Item $src "$libDir\$dll" -Force }
}

$sslDlls = @("libcrypto-3-x64.dll", "libssl-3-x64.dll")
foreach ($dll in $sslDlls) {
    $src = "$ssl\bin\$dll"
    if (Test-Path $src) { Copy-Item $src "$libDir\$dll" -Force }
}

# ---- plugins/ — Qt6 platform, styles, iconengines, imageformats, tls -------
$plugDir = Join-Path $binDir "plugins"

$platformsDir = Join-Path $plugDir "platforms"
if (-not (Test-Path $platformsDir)) { New-Item -ItemType Directory $platformsDir -Force | Out-Null }
$qwindows = Join-Path $qt6Bin "..\plugins\platforms\qwindows.dll"
if (Test-Path $qwindows) { Copy-Item $qwindows "$platformsDir\qwindows.dll" -Force }

$stylesDir = Join-Path $plugDir "styles"
if (-not (Test-Path $stylesDir)) { New-Item -ItemType Directory $stylesDir -Force | Out-Null }
$qstyle = Join-Path $qt6Bin "..\plugins\styles\qwindowsvistastyle.dll"
if (Test-Path $qstyle) { Copy-Item $qstyle "$stylesDir\qwindowsvistastyle.dll" -Force }

$iconDir = Join-Path $plugDir "iconengines"
if (-not (Test-Path $iconDir)) { New-Item -ItemType Directory $iconDir -Force | Out-Null }
$qsvgicon = Join-Path $qt6Bin "..\plugins\iconengines\qsvgicon.dll"
if (Test-Path $qsvgicon) { Copy-Item $qsvgicon "$iconDir\qsvgicon.dll" -Force }

$imgDir = Join-Path $plugDir "imageformats"
if (-not (Test-Path $imgDir)) { New-Item -ItemType Directory $imgDir -Force | Out-Null }
$qsvgfmt = Join-Path $qt6Bin "..\plugins\imageformats\qsvg.dll"
if (Test-Path $qsvgfmt) { Copy-Item $qsvgfmt "$imgDir\qsvg.dll" -Force }

$tlsDir = Join-Path $plugDir "tls"
if (-not (Test-Path $tlsDir)) { New-Item -ItemType Directory $tlsDir -Force | Out-Null }
$qt6Tls = Join-Path $qt6Bin "..\plugins\tls"
foreach ($dll in @("qopensslbackend.dll", "qschannelbackend.dll")) {
    $src = Join-Path $qt6Tls $dll
    if (Test-Path $src) { Copy-Item $src "$tlsDir\$dll" -Force }
}

# certs, configs and profiles alongside the server
# Use \* to copy contents, not the directory itself (avoids nested duplication on re-runs)
foreach ($sub in @("certs", "configs", "profiles")) {
    $dst = Join-Path $binDir $sub
    if (-not (Test-Path $dst)) { New-Item -ItemType Directory $dst | Out-Null }
    if (Test-Path "$PSScriptRoot\$sub") {
        Copy-Item "$PSScriptRoot\$sub\*" $dst -Recurse -Force
    }
}

ok "bin\ ready"

# ---- stand (shellcodes + BOFs) ---------------------------------------------
info "Building stand (shellcodes + BOFs)..."
$standScript = Join-Path $PSScriptRoot "bof\build-stand.ps1"
& $standScript
if ($LASTEXITCODE -ne 0) { fatal "stand build failed" }

$standBin = Join-Path $PSScriptRoot "bof\build"
if (Test-Path $standBin) {
    # sc_*.bin/.o go to bin\shellcode\ (ready-to-load shellcodes),
    # everything else (.bin/.o) goes to bin\bof\Co2H-bof\
    $bofOut = Join-Path $binDir "bof\Co2H-bof"
    $scOut  = Join-Path $binDir "shellcode"
    if (-not (Test-Path $bofOut)) { New-Item -ItemType Directory $bofOut -Force | Out-Null }
    if (-not (Test-Path $scOut))  { New-Item -ItemType Directory $scOut  -Force | Out-Null }
    Get-ChildItem $standBin -File | Where-Object { $_.Extension -in ".bin",".o" } |
        ForEach-Object {
            if ($_.Name -like "sc_*") {
                Copy-Item $_.FullName $scOut -Force
            } else {
                Copy-Item $_.FullName $bofOut -Force
            }
        }
    ok "stand\build\sc_* -> bin\shellcode\"
    ok "stand\build\*    -> bin\bof\Co2h-bof\"
}

# Co2H-bof.zip — готовый архив с собранными BOF
$co2hBofZip = Join-Path $PSScriptRoot "bof\Co2H-bof\Co2H-bof.zip"
if (Test-Path $co2hBofZip) {
    $co2hBofDst = Join-Path $binDir "bof\Co2H-bof"
    if (-not (Test-Path $co2hBofDst)) { New-Item -ItemType Directory $co2hBofDst -Force | Out-Null }
    Copy-Item $co2hBofZip "$co2hBofDst\Co2H-bof.zip" -Force
    ok "bof\Co2H-bof\Co2H-bof.zip -> bin\bof\Co2H-bof\"
}

# ---- tools dir -------------------------------------------------------------
$toolsDir  = Join-Path $binDir "tools"
if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory $toolsDir | Out-Null }

$bofTpl = Join-Path $PSScriptRoot "bof\build\bof_stager_template.x64.o"
if (Test-Path $bofTpl) {
    Copy-Item $bofTpl (Join-Path $toolsDir "bof_stager_template.x64.o") -Force
    ok "bof\build\bof_stager_template.x64.o -> bin\tools\"
} else {
    info "bof_stager_template.x64.o not found, --bof option will fail at runtime"
}

# ---- stagers ---------------------------------------------------------------
$stagersSrc = Join-Path $PSScriptRoot "bof\stagers"
$stagersDst = Join-Path $binDir "stagers"
if (Test-Path $stagersSrc) {
    if (-not (Test-Path $stagersDst)) { New-Item -ItemType Directory $stagersDst | Out-Null }
    Copy-Item "$stagersSrc\*" $stagersDst -Recurse -Force
    ok "stand\stagers\ -> bin\stagers\"
}

# ---- CHM documentation -----------------------------------------------------
# Rebuild co2h.chm from current .html/.hhc/.hhk/.hhp sources.
# If HTML Help Workshop is not installed - skip, use existing CHM.
$chmBuild = Join-Path $PSScriptRoot "docs\chm\build-chm.ps1"
if (Test-Path $chmBuild) {
    info "Rebuilding co2h.chm..."
    & $chmBuild
    if ($LASTEXITCODE -eq 0) {
        ok "co2h.chm rebuilt"
    } else {
        info "CHM rebuild skipped or failed - using existing co2h.chm if any"
    }
}

$chmSrc = Join-Path $PSScriptRoot "docs\chm\co2h.chm"
if (Test-Path $chmSrc) {
    Copy-Item $chmSrc (Join-Path $binDir "co2h.chm") -Force
    ok "docs\chm\co2h.chm -> bin\co2h.chm"
} else {
    info "docs\chm\co2h.chm not found, skipping"
}

# ---- scelot (PE/.NET -> shellcode generator) from kit\utils\scelot ---------
$scelotDir = Join-Path $PSScriptRoot "kit\utils\scelot"
$scelotCML = Join-Path $scelotDir "CMakeLists.txt"
if (Test-Path $scelotCML) {
    info "Building scelot (PE/.NET -> shellcode)..."
    $scelotOk = $true

    # 1) loader stub x64
    info "  -> scelot: loader stub x64"
    $ErrorActionPreference = "Continue"
    & $cmake -S "$scelotDir\loader" -B "$scelotDir\build\stub_x64" `
        -G "Visual Studio 17 2022" -A x64 -Wno-dev
    if ($LASTEXITCODE -eq 0) {
        & $cmake --build "$scelotDir\build\stub_x64" --config Release
    }
    if ($LASTEXITCODE -ne 0) { $scelotOk = $false }

    # 2) loader stub x86
    if ($scelotOk) {
        info "  -> scelot: loader stub x86"
        & $cmake -S "$scelotDir\loader" -B "$scelotDir\build\stub_x86" `
            -G "Visual Studio 17 2022" -A Win32 -Wno-dev
        if ($LASTEXITCODE -eq 0) {
            & $cmake --build "$scelotDir\build\stub_x86" --config Release
        }
        if ($LASTEXITCODE -ne 0) { $scelotOk = $false }
    }

    # 3) generator (top-level)
    if ($scelotOk) {
        info "  -> scelot: generator"
        & $cmake -S $scelotDir -B "$scelotDir\build\main" `
            -G "Visual Studio 17 2022" -A x64 -Wno-dev
        if ($LASTEXITCODE -eq 0) {
            & $cmake --build "$scelotDir\build\main" --config Release
        }
        if ($LASTEXITCODE -ne 0) { $scelotOk = $false }
    }
    $ErrorActionPreference = "Stop"

    if ($scelotOk) {
        # scelot.exe outputs to project root
        $scelotExeBuilt = Join-Path $scelotDir "scelot.exe"
        if (Test-Path $scelotExeBuilt) {
            Copy-Item $scelotExeBuilt "$toolsDir\scelot.exe" -Force
            ok "kit\utils\scelot\scelot.exe -> bin\tools\scelot.exe"
        }
    } else {
        Write-Host "[!] scelot build failed" -ForegroundColor Yellow
    }
} else {
    info "kit\utils\scelot not found, skipping"
}

# ---- Kit Editor (.NET Framework 4.8, WPF) ---------------------------------
$kitEditorProj = Join-Path $PSScriptRoot "kit\kit-editor\KitEditor.csproj"
if (Test-Path $kitEditorProj) {
    info "Building Kit Editor..."
    # Find MSBuild
    $msbuild = $null
    $msbuildPaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe"
    )
    foreach ($mp in $msbuildPaths) {
        if (Test-Path $mp) { $msbuild = $mp; break }
    }
    if (-not $msbuild) {
        $found = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
        if ($found) { $msbuild = $found.Source }
    }

    if ($msbuild) {
        # NuGet restore (AvalonEdit)
        $nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue
        if ($nuget) {
            & $nuget.Source restore $kitEditorProj -PackagesDirectory (Join-Path $PSScriptRoot "kit\kit-editor\packages")
        } else {
            info "nuget.exe not found - assuming packages already restored"
        }

        $ErrorActionPreference = "Continue"
        & $msbuild $kitEditorProj /p:Configuration=Release /p:Platform=AnyCPU /v:minimal /nologo /m
        $ErrorActionPreference = "Stop"
        if ($LASTEXITCODE -eq 0) {
            ok "Kit Editor built -> kit\KitEditor.exe"
        } else {
            Write-Host "[!] Kit Editor build failed" -ForegroundColor Yellow
        }
    } else {
        info "MSBuild not found - skipping Kit Editor"
    }
} else {
    info "kit\kit-editor\KitEditor.csproj not found, skipping"
}

# ---- Plugin SDK ------------------------------------------------------------
$sdkSrc = Join-Path $PSScriptRoot "sdk"
if (Test-Path $sdkSrc) {
    $sdkDst = Join-Path $binDir "sdk"
    if (-not (Test-Path $sdkDst)) { New-Item -ItemType Directory $sdkDst | Out-Null }
    Copy-Item "$sdkSrc\*" $sdkDst -Recurse -Force

    # Import-библиотека клиента — нужна для линковки плагинов.
    $clientLib = "$buildDir\client$cs\co2h-client.lib"
    if (Test-Path $clientLib) {
        $sdkLibDir = Join-Path $sdkDst "lib"
        if (-not (Test-Path $sdkLibDir)) { New-Item -ItemType Directory $sdkLibDir | Out-Null }
        Copy-Item $clientLib "$sdkLibDir\co2h-client.lib" -Force
    }
    ok "sdk\ -> bin\sdk\  (plugin SDK: headers + lib + example)"
}

# ---- Plugins build (all subdirectories of plugins/) -------------------------
$pluginsDir = Join-Path $binDir "plugins"
if (-not (Test-Path $pluginsDir)) { New-Item -ItemType Directory $pluginsDir | Out-Null }

$clientLib = "$buildDir\client$cs\co2h-client.lib"
$pluginsSrcDir = Join-Path $PSScriptRoot "plugins"

if ((Test-Path $pluginsSrcDir) -and (Test-Path $clientLib)) {
    Get-ChildItem $pluginsSrcDir -Directory | ForEach-Object {
        $pDir = $_.FullName
        $pName = $_.Name
        if (-not (Test-Path "$pDir\CMakeLists.txt")) { return }

        $pBuild = Join-Path $PSScriptRoot "out\build\plugin-$pName"
        info "Building plugin: $pName..."
        $ErrorActionPreference = "Continue"
        if ($useNinja) {
            & $cmake `
                -S $pDir `
                -B $pBuild `
                -G Ninja `
                -Wno-dev `
                "-DCMAKE_BUILD_TYPE=$Config" `
                "-DCMAKE_PREFIX_PATH=$qt6Prefix" `
                "-DQt6_DIR=$qt6" `
                "-DCO2H_CLIENT_LIB=$clientLib"
        } else {
            & $cmake `
                -S $pDir `
                -B $pBuild `
                -G "Visual Studio 17 2022" -A x64 `
                -Wno-dev `
                "-DCMAKE_PREFIX_PATH=$qt6Prefix" `
                "-DQt6_DIR=$qt6" `
                "-DCO2H_CLIENT_LIB=$clientLib"
        }
        $ErrorActionPreference = "Stop"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Plugin '$pName' configure failed" -ForegroundColor Yellow
            return
        }
        $ErrorActionPreference = "Continue"
        & $cmake --build $pBuild --config $Config --parallel 2
        $ErrorActionPreference = "Stop"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Plugin '$pName' build failed" -ForegroundColor Yellow
            return
        }
        # Копируем все DLL из plugins/$Config/ в bin\plugins\.
        $pcsub = if ($useNinja) { "" } else { "\$Config" }
        $pOutDir = "$pBuild\plugins$pcsub"
        if (Test-Path $pOutDir) {
            Get-ChildItem $pOutDir -Filter "*.dll" | ForEach-Object {
                Copy-Item $_.FullName "$pluginsDir\$($_.Name)" -Force
                ok "plugins\$pName -> bin\plugins\$($_.Name)"
            }
        }
    }
} elseif (-not (Test-Path $clientLib)) {
    info "co2h-client.lib not found - skipping plugins build (rebuild client first)"
}

# ---- scripts/ — Lua scripts for the scripting engine ----------------------
$scriptsSrc = Join-Path $PSScriptRoot "client\scripts"
$scriptsDst = Join-Path $binDir "scripts"
if (Test-Path $scriptsSrc) {
    if (-not (Test-Path $scriptsDst)) { New-Item -ItemType Directory $scriptsDst | Out-Null }
    Copy-Item "$scriptsSrc\*" $scriptsDst -Recurse -Force
    ok "client\scripts\ -> bin\scripts\"
} else {
    if (-not (Test-Path $scriptsDst)) { New-Item -ItemType Directory $scriptsDst | Out-Null }
}

# ---- kit/ — Artifact Kit, Sleep Mask Kit, Process Inject Kit ---------------
$kitSrc = Join-Path $PSScriptRoot "kit"
$kitDst = Join-Path $binDir "kit"
if (Test-Path $kitSrc) {
    info "Copying kit\ -> bin\kit\..."
    if (-not (Test-Path $kitDst)) { New-Item -ItemType Directory $kitDst | Out-Null }
    Copy-Item "$kitSrc\*" $kitDst -Recurse -Force
    ok "kit\ -> bin\kit\"
}

# ---- summary ---------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Yellow
Write-Host "  Co2H build complete" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  bin\teamserver.exe"
Write-Host "  bin\co2h-client.exe"
if (-not $NoBeacon) {
    Write-Host "  bin\beacons\          (all beacon templates)"
    Write-Host "    beacon64.exe/dll    (Windows x64)"
    Write-Host "    beacon32.exe/dll    (Windows x86)"
    Write-Host "    beacon-linux64[.so] (Linux x64)"
    Write-Host "    beacon-linux-arm64  (Linux ARM64)"
    Write-Host "    beacon-linux-arm32  (Linux ARM32)"
    Write-Host "    beacon-macos[.dylib](macOS ARM64/x64)"
    Write-Host "  bin\artifact-gen.exe"
}
Write-Host "  bin\shellcode\        (sc_*.bin shellcodes)"
Write-Host "  bin\bof\co2h\         (Co2H BOFs)"
Write-Host "  bin\bof\              (third-party BOF collection)"
Write-Host "  bin\kit\              (Artifact Kit + KitEditor + scelot)"
Write-Host "  bin\tools\scelot.exe  (PE/.NET to shellcode generator)"
Write-Host "  bin\co2h.chm          (offline documentation)"
Write-Host "  bin\sdk\              (plugin SDK: headers + example)"
Write-Host "  bin\plugins\          (plugin DLLs go here)"
Write-Host "  bin\scripts\          (Lua scripts for scripting engine)"
Write-Host "  bin\stagers\          (stager scripts)"
Write-Host ""
