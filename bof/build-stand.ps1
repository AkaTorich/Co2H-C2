# build-stand.ps1 -- assembles shellcodes and BOFs for the stand.
# ASCII-only by design (PowerShell 5.1 is fragile with non-ASCII bytes).
#
# Output goes to stand\build\:
#   sc_*.x64.bin  / sc_*.x86.bin   -- raw shellcode (.text section extract)
#   bof_*.x64.o   / bof_*.x86.o   -- COFF objects for the bof command
#
# Requires Visual Studio with C++ workload (cl.exe, ml64.exe, ml.exe).
# Auto-detects VS: BuildTools -> Enterprise -> Professional -> Community.

$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$src_sc  = Join-Path $root 'shellcode'
$src_bof = Join-Path $root 'Co2h'
$out     = Join-Path $root 'build'

if (-not (Test-Path $out)) { New-Item -ItemType Directory -Path $out | Out-Null }

# ---- Auto-detect Visual Studio (BuildTools first, then editions) -------------
$vsRoot = $null
$vsSearchPaths = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional',
    'C:\Program Files\Microsoft Visual Studio\2022\Community',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools',
    'C:\Program Files\Microsoft Visual Studio\2022\BuildTools',
    'C:\Program Files\Microsoft Visual Studio\18\Enterprise',
    'C:\Program Files\Microsoft Visual Studio\18\BuildTools'
)
foreach ($p in $vsSearchPaths) {
    $vc = Join-Path $p 'VC\Auxiliary\Build\vcvars64.bat'
    if (Test-Path $vc) { $vsRoot = $p; break }
}
if (-not $vsRoot) { throw "Visual Studio not found in any known location" }

$vcvars  = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
$msvcDir = Join-Path $vsRoot 'VC\Tools\MSVC'

if (-not (Test-Path $vcvars))  { throw "vcvars64.bat not found at $vcvars" }
if (-not (Test-Path $msvcDir)) { throw "VC\Tools\MSVC not found at $msvcDir" }
Write-Output "[*] Using VS: $vsRoot"

$msvcVer = (Get-ChildItem $msvcDir -Directory | Sort-Object Name -Descending | Select-Object -First 1)
if (-not $msvcVer) { throw "no MSVC version subfolder under $msvcDir" }

# x64 tools (Hostx64\x64)
$binX64 = Join-Path $msvcVer.FullName 'bin\Hostx64\x64'
$ml64   = Join-Path $binX64 'ml64.exe'
$clX64  = Join-Path $binX64 'cl.exe'
if (-not (Test-Path $ml64))  { throw "ml64.exe not found at $ml64" }
if (-not (Test-Path $clX64)) { throw "cl.exe (x64) not found at $clX64" }

# x86 tools (Hostx64\x86 -- x64-hosted cross-compiler targeting x86)
$binX86 = Join-Path $msvcVer.FullName 'bin\Hostx64\x86'
$ml32   = Join-Path $binX86 'ml.exe'
$clX86  = Join-Path $binX86 'cl.exe'
if (-not (Test-Path $ml32))  { throw "ml.exe (x86) not found at $ml32" }
if (-not (Test-Path $clX86)) { throw "cl.exe (x86) not found at $clX86" }

# Собираем INCLUDE напрямую из известных путей (vcvars64.bat через cmd.exe
# ненадёжен — cmd.exe падает "input line too long" при длинном PATH).
$msvcInc = Join-Path $msvcVer.FullName 'include'
if (-not (Test-Path $msvcInc)) { throw "MSVC include not found: $msvcInc" }

# Найти Windows SDK Include (последняя версия).
$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10\Include'
if (-not (Test-Path $sdkRoot)) {
    $sdkRoot = 'C:\Program Files\Windows Kits\10\Include'
}
$sdkVer = (Get-ChildItem $sdkRoot -Directory | Where-Object { $_.Name -match '^\d+\.\d+' } | Sort-Object Name -Descending | Select-Object -First 1)
if (-not $sdkVer) { throw "Windows SDK Include not found under $sdkRoot" }

$sdkUcrt   = Join-Path $sdkVer.FullName 'ucrt'
$sdkUm     = Join-Path $sdkVer.FullName 'um'
$sdkShared = Join-Path $sdkVer.FullName 'shared'

$env:INCLUDE = "$msvcInc;$sdkUcrt;$sdkUm;$sdkShared"
Write-Output "[*] INCLUDE: $env:INCLUDE"

Write-Output "ml64:  $ml64"
Write-Output "ml32:  $ml32"
Write-Output "cl64:  $clX64"
Write-Output "cl86:  $clX86"
Write-Output ''

# ---- helper: extract .text section bytes from COFF .obj ---------------------
# COFF layout: 20-byte file header, then NumberOfSections * 40-byte section
# headers. Each header: Name[8], VirtualSize[4], VirtualAddress[4],
# SizeOfRawData[4], PointerToRawData[4], ...
function Extract-TextSection($objPath, $binPath) {
    $bytes = [System.IO.File]::ReadAllBytes($objPath)
    if ($bytes.Length -lt 20) { throw "obj too small: $objPath" }
    $nsec = [BitConverter]::ToUInt16($bytes, 2)
    $optHdrSize = [BitConverter]::ToUInt16($bytes, 16)
    $secStart = 20 + $optHdrSize
    for ($i = 0; $i -lt $nsec; ++$i) {
        $h = $secStart + $i * 40
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $h, 8).TrimEnd([char]0)
        if ($name -eq '.text' -or $name -eq '.text$mn') {
            $size = [BitConverter]::ToUInt32($bytes, $h + 16)
            $ptr  = [BitConverter]::ToUInt32($bytes, $h + 20)
            $blob = New-Object byte[] $size
            [Array]::Copy($bytes, $ptr, $blob, 0, $size)
            [System.IO.File]::WriteAllBytes($binPath, $blob)
            Write-Output ("  -> {0} ({1} bytes)" -f $binPath, $size)
            return
        }
    }
    throw "no .text section in $objPath"
}

# ---- build ASM shellcodes ---------------------------------------------------
$asmFiles = Get-ChildItem -Path $src_sc -Filter '*.asm' -ErrorAction SilentlyContinue

foreach ($f in $asmFiles) {
    # x64 -- ml64.exe
    Write-Output ("ml64  {0}" -f $f.Name)
    $obj64 = Join-Path $out ($f.BaseName + '.x64.obj')
    & $ml64 /nologo /c /Fo$obj64 $f.FullName
    if ($LASTEXITCODE -ne 0) { throw "ml64 failed on $($f.Name)" }
    Extract-TextSection $obj64 (Join-Path $out ($f.BaseName + '.x64.bin'))

    # x86 -- ml.exe; skip gracefully if the file uses x64-only mnemonics
    Write-Output ("ml32  {0}" -f $f.Name)
    $obj86 = Join-Path $out ($f.BaseName + '.x86.obj')
    & $ml32 /nologo /c /Fo$obj86 $f.FullName
    if ($LASTEXITCODE -ne 0) {
        Write-Warning ("ml32 skipped {0} (x64-only syntax or unsupported mnemonic)" -f $f.Name)
    } else {
        Extract-TextSection $obj86 (Join-Path $out ($f.BaseName + '.x86.bin'))
    }
}

# ---- build BOFs (x64 + x86) -------------------------------------------------
# /c    -- compile only, produce COFF .obj
# /GS-  -- no stack cookies (BOF loader does not provide __security_*)
# /Os   -- favor small code
# /Zl   -- omit default-library refs
# /TC   -- treat as C
# /I    -- include path for beacon.h
$bofFiles = Get-ChildItem -Path $src_bof -Filter 'bof_*.c' -ErrorAction SilentlyContinue

foreach ($f in $bofFiles) {
    Write-Output ("cl x64  {0}" -f $f.Name)
    $o64 = Join-Path $out ($f.BaseName + '.x64.o')
    & $clX64 /nologo /c /GS- /Os /Zl /TC /I $src_bof /Fo$o64 $f.FullName
    if ($LASTEXITCODE -ne 0) { throw "cl x64 failed on $($f.Name)" }
    Write-Output ("  -> {0}" -f $o64)

    Write-Output ("cl x86  {0}" -f $f.Name)
    $o86 = Join-Path $out ($f.BaseName + '.x86.o')
    & $clX86 /nologo /c /GS- /Os /Zl /TC /I $src_bof /Fo$o86 $f.FullName
    if ($LASTEXITCODE -ne 0) { throw "cl x86 failed on $($f.Name)" }
    Write-Output ("  -> {0}" -f $o86)
}

# ---- build C shellcodes (x64 + x86) ----------------------------------------
# /Gs999999 -- disable stack probing (no __chkstk dependency)
# /O1       -- optimize for size
$cscFiles = Get-ChildItem -Path $src_sc -Filter 'sc_*.c' -ErrorAction SilentlyContinue

Write-Output ''
Write-Output 'stand build OK. Files in stand\build\:'
Get-ChildItem -Path $out | Format-Table Name, Length -AutoSize
