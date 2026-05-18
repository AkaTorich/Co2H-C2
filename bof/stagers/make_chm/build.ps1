# ---- Настройки ----
$OutFile = "C:\Temp\help.chm"   # куда сохранить готовый CHM
# --------------------

# Ищем hhc.exe в стандартных местах
$hhcPaths = @(
    "${env:ProgramFiles(x86)}\HTML Help Workshop\hhc.exe",
    "$env:ProgramFiles\HTML Help Workshop\hhc.exe",
    "$env:SystemRoot\hhc.exe"
)
$hhc = $hhcPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $hhc) {
    Write-Error "hhc.exe не найден. Установи HTML Help Workshop:
https://web.archive.org/web/2024/https://www.microsoft.com/en-us/download/details.aspx?id=21138"
    exit 1
}

$src = $PSScriptRoot
$hhp = Join-Path $src "project.hhp"

Write-Host "[*] Компилируем: $hhp"
& $hhc $hhp

$built = Join-Path $src "stager.chm"
if (Test-Path $built) {
    Copy-Item $built $OutFile -Force
    Remove-Item $built -Force
    Write-Host "[+] CHM: $OutFile  ($('{0:N0}' -f (Get-Item $OutFile).Length) bytes)"
} else {
    Write-Error "hhc.exe отработал, но stager.chm не создан."
    exit 1
}
