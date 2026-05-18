#Requires -Version 5.1
# Установка всех зависимостей для сборки Co2H на Windows.
# Запускать от имени администратора.

$ErrorActionPreference = "Stop"

function info  { param($m) Write-Host "[*] $m" -ForegroundColor Cyan  }
function ok    { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function fatal { param($m) Write-Host "[!] $m" -ForegroundColor Red; exit 1 }
function warn  { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }

# Проверка прав администратора.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    fatal "Run this script as Administrator"
}

# ============================================================================
# 1. Visual Studio Build Tools (MSVC C++ compiler)
# ============================================================================
info "Checking Visual Studio / Build Tools..."

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$hasVS = $false
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -property installationPath 2>$null
    if ($vsPath) { $hasVS = $true }
}

if ($hasVS) {
    ok "Visual Studio found: $vsPath"
} else {
    info "Installing Visual Studio Build Tools 2022..."
    $vsUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
    $vsInstaller = "$env:TEMP\vs_BuildTools.exe"
    Invoke-WebRequest -Uri $vsUrl -OutFile $vsInstaller
    $proc = Start-Process -Wait -PassThru -FilePath $vsInstaller -ArgumentList `
        "--quiet", "--wait", "--norestart", `
        "--add", "Microsoft.VisualStudio.Workload.VCTools", `
        "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", `
        "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621"
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        fatal "VS Build Tools installation failed (exit $($proc.ExitCode))"
    }
    ok "Visual Studio Build Tools 2022 installed"
}

# ============================================================================
# 2. CMake 3.x
# ============================================================================
info "Checking CMake..."

$cmakeVer = "3.31.6"
$cmakeDir = "$env:USERPROFILE\cmake-$cmakeVer-windows-x86_64"
$cmakeExe = "$cmakeDir\bin\cmake.exe"

if (Test-Path $cmakeExe) {
    ok "CMake $cmakeVer already installed: $cmakeExe"
} elseif (Get-Command cmake -ErrorAction SilentlyContinue) {
    ok "CMake found in PATH: $(cmake --version | Select-Object -First 1)"
} else {
    info "Downloading CMake $cmakeVer..."
    $cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v$cmakeVer/cmake-$cmakeVer-windows-x86_64.zip"
    $cmakeZip = "$env:TEMP\cmake-$cmakeVer.zip"
    Invoke-WebRequest -Uri $cmakeUrl -OutFile $cmakeZip
    Expand-Archive -Path $cmakeZip -DestinationPath $env:USERPROFILE -Force
    Remove-Item $cmakeZip
    ok "CMake $cmakeVer installed: $cmakeExe"
}

# ============================================================================
# 3. Qt6 (via aqtinstall)
# ============================================================================
info "Checking Qt6..."

$qt6Ver = "6.8.2"
$qt6Root = "C:\Qt"
$qt6Path = "$qt6Root\$qt6Ver\$qt6Ver\msvc2022_64"
$qt6Found = $false

foreach ($q in @("C:\Qt\6.10.2\6.10.2\msvc2022_64", "C:\Qt\6.8.2\6.8.2\msvc2022_64", "C:\Qt\6.7.3\msvc2022_64")) {
    if (Test-Path "$q\lib\cmake\Qt6") {
        $qt6Found = $true
        ok "Qt6 found: $q"
        break
    }
}

if (-not $qt6Found) {
    info "Downloading Qt Online Installer..."
    $qtInstallerUrl = "https://download.qt.io/official_releases/online_installers/qt-online-installer-windows-x64-online.exe"
    $qtInstaller = "$env:TEMP\qt-online-installer-windows-x64-online.exe"

    if (-not (Test-Path $qtInstaller)) {
        Invoke-WebRequest -Uri $qtInstallerUrl -OutFile $qtInstaller
    }

    info "Launching Qt Installer - select MSVC 2022 64-bit, install to C:\Qt"
    Write-Host ""
    Write-Host "  IMPORTANT: In the installer select:" -ForegroundColor Yellow
    Write-Host "    - Qt 6.8.x or 6.10.x" -ForegroundColor White
    Write-Host "    - MSVC 2022 64-bit" -ForegroundColor White
    Write-Host "    - Additional Libraries: Qt SVG" -ForegroundColor White
    Write-Host "    - Install path: C:\Qt" -ForegroundColor White
    Write-Host ""

    Start-Process -Wait -FilePath $qtInstaller

    # Повторная проверка после установки
    foreach ($q in @("C:\Qt\6.10.2\6.10.2\msvc2022_64", "C:\Qt\6.8.2\6.8.2\msvc2022_64",
                     "C:\Qt\6.10.2\msvc2022_64", "C:\Qt\6.8.2\msvc2022_64",
                     "C:\Qt\6.10.0\msvc2022_64", "C:\Qt\6.9.0\msvc2022_64")) {
        if (Test-Path "$q\lib\cmake\Qt6") {
            $qt6Found = $true
            ok "Qt6 found after install: $q"
            break
        }
    }

    if (-not $qt6Found) {
        warn "Qt6 not detected in C:\Qt after installer. Check installation path."
    }
}

# ============================================================================
# 4. OpenSSL
# ============================================================================
info "Checking OpenSSL..."

$sslDir = "C:\Program Files\OpenSSL-Win64"
if (Test-Path "$sslDir\include\openssl\ssl.h") {
    ok "OpenSSL found: $sslDir"
} else {
    # Способ 1: winget (наиболее надёжный)
    $installed = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        info "Installing OpenSSL via winget..."
        winget install --id ShiningLight.OpenSSL --accept-source-agreements --accept-package-agreements -s winget 2>$null
        if (Test-Path "$sslDir\include\openssl\ssl.h") {
            $installed = $true
        }
    }

    # Способ 2: прямая загрузка (slproweb, пробуем несколько версий)
    if (-not $installed) {
        info "Trying direct download from slproweb..."
        $sslInstaller = "$env:TEMP\OpenSSL-Win64.exe"
        $sslVersions = @("3_5_0", "3_4_1", "3_4_0", "3_3_2")
        foreach ($v in $sslVersions) {
            $sslUrl = "https://slproweb.com/download/Win64OpenSSL-$v.exe"
            try {
                Invoke-WebRequest -Uri $sslUrl -OutFile $sslInstaller -ErrorAction Stop
                info "Installing OpenSSL $v (silent)..."
                Start-Process -Wait -PassThru -FilePath $sslInstaller -ArgumentList "/VERYSILENT", "/DIR=C:\Program Files\OpenSSL-Win64" | Out-Null
                $installed = $true
                break
            } catch {
                # Версия не найдена, пробуем следующую
            }
        }
    }

    if (Test-Path "$sslDir\include\openssl\ssl.h") {
        ok "OpenSSL installed: $sslDir"
    } else {
        warn "OpenSSL installation failed. Install manually from https://slproweb.com/products/Win32OpenSSL.html"
    }
}

# ============================================================================
# 5. NASM (needed for some OpenSSL / beacon builds)
# ============================================================================
info "Checking NASM..."

if (Get-Command nasm -ErrorAction SilentlyContinue) {
    ok "NASM found in PATH"
} else {
    $nasmVer = "2.16.03"
    $nasmUrl = "https://www.nasm.us/pub/nasm/releasebuilds/$nasmVer/win64/nasm-$nasmVer-win64.zip"
    $nasmZip = "$env:TEMP\nasm.zip"
    $nasmDir = "C:\nasm"
    info "Downloading NASM $nasmVer..."
    Invoke-WebRequest -Uri $nasmUrl -OutFile $nasmZip
    Expand-Archive -Path $nasmZip -DestinationPath $env:TEMP -Force
    if (-not (Test-Path $nasmDir)) { New-Item -ItemType Directory $nasmDir | Out-Null }
    Copy-Item "$env:TEMP\nasm-$nasmVer\*" $nasmDir -Recurse -Force
    # Add to PATH for current session
    $env:PATH = "$nasmDir;$env:PATH"
    # Add to system PATH permanently
    $syspath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($syspath -notlike "*$nasmDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$syspath;$nasmDir", "Machine")
    }
    Remove-Item $nasmZip
    ok "NASM $nasmVer installed: $nasmDir"
}

# ============================================================================
# 6. Git
# ============================================================================
info "Checking Git..."

if (Get-Command git -ErrorAction SilentlyContinue) {
    ok "Git found: $(git --version)"
} else {
    info "Downloading Git..."
    $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/Git-2.47.1-64-bit.exe"
    $gitInstaller = "$env:TEMP\Git-installer.exe"
    Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller
    Start-Process -Wait -PassThru -FilePath $gitInstaller -ArgumentList "/VERYSILENT", "/NORESTART" | Out-Null
    ok "Git installed"
}

# ============================================================================
# 7. HTML Help Workshop (for CHM documentation)
# ============================================================================
info "Checking HTML Help Workshop..."

$hhcExe = "C:\Program Files (x86)\HTML Help Workshop\hhc.exe"
if (Test-Path $hhcExe) {
    ok "HTML Help Workshop found"
} else {
    warn "HTML Help Workshop not found"
    Write-Host "  Download from: https://web.archive.org/web/2015/http://download.microsoft.com/download/0/A/9/0A939EF6-E31C-430F-A3DF-DFAE7960D564/htmlhelp.exe" -ForegroundColor White
    Write-Host "  CHM build will be skipped without it." -ForegroundColor White
}

# ============================================================================
# Summary
# ============================================================================
Write-Host ""
Write-Host "================================================" -ForegroundColor Yellow
Write-Host "  Dependency check complete" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Required for build:" -ForegroundColor White
Write-Host "    [$(if ($hasVS) {'+'} else {'!'})] Visual Studio Build Tools 2022 (MSVC)" -ForegroundColor $(if ($hasVS) {'Green'} else {'Red'})
Write-Host "    [$(if (Test-Path $cmakeExe -or (Get-Command cmake -EA 0)) {'+'} else {'!'})] CMake 3.x" -ForegroundColor $(if (Test-Path $cmakeExe) {'Green'} else {'Red'})
Write-Host "    [$(if ($qt6Found) {'+'} else {'!'})] Qt6 (MSVC 2022 x64)" -ForegroundColor $(if ($qt6Found) {'Green'} else {'Red'})
Write-Host "    [$(if (Test-Path "$sslDir\include\openssl\ssl.h") {'+'} else {'!'})] OpenSSL 3.x" -ForegroundColor $(if (Test-Path "$sslDir\include\openssl\ssl.h") {'Green'} else {'Red'})
Write-Host ""
Write-Host "  After all dependencies are installed, run:" -ForegroundColor White
Write-Host "    .\build.ps1" -ForegroundColor Cyan
Write-Host ""
