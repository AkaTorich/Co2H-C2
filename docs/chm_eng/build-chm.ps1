# build-chm.ps1 — собирает co2h.chm с правильной кириллицей.
#
# Проблема: HTML Help Workshop (hhc.exe) и старый hh.exe используют
# IE-trident с системной кодировкой (Windows-1251 на русской Windows)
# и игнорируют <meta charset="UTF-8">. Поэтому исходные UTF-8 файлы
# нужно перекодировать в cp1251 + поменять meta charset.
#
# Этот скрипт:
#   1. Создаёт подпапку build/
#   2. Конвертирует все *.html в Windows-1251 с правильным meta charset
#   3. Копирует .hhc/.hhk/.hhp/style.css (тоже в cp1251)
#   4. Запускает hhc.exe build/co2h.hhp
#   5. Кладёт co2h.chm рядом со скриптом

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root "build"

if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory -Path $build | Out-Null

$cp1251 = [System.Text.Encoding]::GetEncoding(1251)
$utf8   = [System.Text.Encoding]::UTF8

function ConvertHtml($srcPath, $dstPath) {
    $text = [System.IO.File]::ReadAllText($srcPath, $utf8)
    # Заменить charset=UTF-8 на charset=windows-1251 (case-insensitive).
    $text = [System.Text.RegularExpressions.Regex]::Replace(
        $text, 'charset\s*=\s*UTF-8', 'charset=windows-1251',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    [System.IO.File]::WriteAllText($dstPath, $text, $cp1251)
}

function ConvertText($srcPath, $dstPath) {
    $text = [System.IO.File]::ReadAllText($srcPath, $utf8)
    [System.IO.File]::WriteAllText($dstPath, $text, $cp1251)
}

# 1. HTML
Get-ChildItem -Path $root -Filter "*.html" -File | ForEach-Object {
    $dst = Join-Path $build $_.Name
    ConvertHtml $_.FullName $dst
    Write-Host "  [html ]  $($_.Name)"
}

# 2. CSS (latin-only, но всё равно положим)
Get-ChildItem -Path $root -Filter "*.css" -File | ForEach-Object {
    Copy-Item $_.FullName -Destination (Join-Path $build $_.Name)
    Write-Host "  [css  ]  $($_.Name)"
}

# 3. .hhc / .hhk — sitemap-файлы, кириллица в <param name="Name" value="..."> .
Get-ChildItem -Path $root -Filter "*.hh?" -File | Where-Object { $_.Extension -ne '.hhp' } | ForEach-Object {
    $dst = Join-Path $build $_.Name
    ConvertText $_.FullName $dst
    Write-Host "  [toc  ]  $($_.Name)"
}

# 4. .hhp — конфиг проекта (ASCII + Title в cp1251).
ConvertText (Join-Path $root "co2h.hhp") (Join-Path $build "co2h.hhp")
Write-Host "  [proj ]  co2h.hhp"

# 5. Поиск hhc.exe.
$hhcCandidates = @(
    "C:\Program Files (x86)\HTML Help Workshop\hhc.exe",
    "C:\Program Files\HTML Help Workshop\hhc.exe"
)
$hhc = $hhcCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $hhc) {
    Write-Host ""
    Write-Host "[build-chm] hhc.exe not found. Install HTML Help Workshop:" -ForegroundColor Red
    Write-Host "  https://learn.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-downloads"
    exit 1
}

Write-Host ""
Write-Host "[build-chm] running: $hhc build\co2h.hhp"
Push-Location $build
try {
    # hhc.exe возвращает 1 при УСПЕХЕ, 0 при ошибке (исторический quirk).
    & $hhc "co2h.hhp" | Out-Host
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($rc -eq 1) {
    $out = Join-Path $build "co2h-eng.chm"
    $final = Join-Path $root "co2h-eng.chm"
    if (Test-Path $out) {
        Move-Item -Force $out $final
        Write-Host ""
        Write-Host "[build-chm] OK -> $final" -ForegroundColor Green
        exit 0
    }
}

Write-Host ""
Write-Host "[build-chm] FAILED (hhc returned $rc)" -ForegroundColor Red
exit 1
