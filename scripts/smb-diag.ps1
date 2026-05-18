# SMB diagnostic / fixer for Co2H named-pipe listener.
#
# Usage:
#   On the SERVER box (where co2h_server.exe is running):
#       .\smb-diag.ps1 -Mode server [-ForcePrivate]
#
#   On the CLIENT box (where the beacon will run):
#       .\smb-diag.ps1 -Mode client -Server <ip|hostname> [-Pipe co2h]
#                                                          [-User DOMAIN\u -Pass p]
#                                                          [-AllowGuest]
#
#   Auto mode (no -Mode flag): the script guesses based on whether the local
#   pipe exists.
#       .\smb-diag.ps1
#
# Everything is auto-substituted (IPs, pipe name, user). All output is ASCII
# only because Windows PowerShell 5.1 reads .ps1 as ANSI/CP1251 and mangles
# UTF-8 Cyrillic into mojibake that breaks the parser.

[CmdletBinding()]
param(
    [ValidateSet('server','client','auto')]
    [string]$Mode  = 'auto',
    [string]$Server,
    [string]$Pipe  = 'co2h',
    [string]$User,
    [string]$Pass,
    [switch]$AllowGuest,        # client side: enable AllowInsecureGuestAuth
    [switch]$ForcePrivate,      # server side: silently switch Public -> Private
    [switch]$EnableNullSession  # server side: allow null/guest SMB to our pipe
)

$ErrorActionPreference = 'Continue'

function Section($t) { Write-Host "`n===== $t =====" -ForegroundColor Cyan }
function OK($t)      { Write-Host "[ OK ] $t" -ForegroundColor Green }
function Warn($t)    { Write-Host "[WARN] $t" -ForegroundColor Yellow }
function Bad($t)     { Write-Host "[FAIL] $t" -ForegroundColor Red }
function Info($t)    { Write-Host "[INFO] $t" -ForegroundColor Gray }

function Get-LocalIPv4 {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
            $_.PrefixOrigin -ne 'WellKnown'
        } | Select-Object -ExpandProperty IPAddress
}

function Resolve-Server {
    param([string]$S)
    if (-not $S) { return $null }
    try {
        $ip = ([System.Net.Dns]::GetHostAddresses($S) |
               Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
               Select-Object -First 1).IPAddressToString
        return $ip
    } catch { return $null }
}

# ============================================================ SERVER ===
function Run-Server {
    Section 'Server-side check'

    # 1. LanmanServer
    $svc = Get-Service LanmanServer -ErrorAction SilentlyContinue
    if (-not $svc) { Bad 'LanmanServer not registered.'; return }
    if ($svc.Status -ne 'Running') {
        Warn ("LanmanServer status: {0}. Trying to start..." -f $svc.Status)
        try {
            Start-Service SrvNet, Srv2, LanmanServer -ErrorAction Stop
            OK 'LanmanServer started.'
        } catch {
            Bad ("Start-Service failed: {0}" -f $_.Exception.Message)
            return
        }
    } else {
        OK 'LanmanServer Running.'
    }

    # 2. Listen 445
    $listen = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
    if ($listen) {
        OK ("Port 445 is listening ({0} sockets)." -f @($listen).Count)
    } else {
        Bad 'Nobody listens on 445 - SMB server did not come up.'
        return
    }

    # 2b. SMB protocol versions and AutoShareWks (controls IPC$ publication).
    try {
        $smbCfg = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smbCfg.EnableSMB2Protocol) { OK 'SMB2/3 protocol enabled.' }
        else                            { Bad 'SMB2 disabled - clients cannot speak modern SMB.' }
        if ($smbCfg.AutoShareWks) { OK 'AutoShareWks=ON (IPC$ and admin shares published).' }
        else {
            Bad 'AutoShareWks=OFF - IPC$ is NOT published. Remote clients will get error 67 on IPC$.'
            Info '  Run with -EnableNullSession to fix automatically (also turns on AutoShareWks).'
        }
        if ($smbCfg.ServerHidden) { Warn 'ServerHidden=ON (server does not announce, but pipes still work).' }
    } catch {
        Warn ("Get-SmbServerConfiguration failed: {0}" -f $_.Exception.Message)
    }

    # 2c. List published shares — IPC$ MUST appear here.
    try {
        $shares = Get-SmbShare -ErrorAction Stop
        $hasIpc = $shares | Where-Object Name -eq 'IPC$'
        if ($hasIpc) { OK 'IPC$ share is present.' }
        else         { Bad 'IPC$ share is MISSING. -EnableNullSession will recreate it.' }
    } catch {
        Warn ("Get-SmbShare failed: {0}" -f $_.Exception.Message)
    }

    # 3. Network category
    $profiles = Get-NetConnectionProfile
    foreach ($p in $profiles) {
        if ($p.NetworkCategory -eq 'Public') {
            Warn ("Adapter '{0}' is Public - SMB from outside will be blocked." -f $p.InterfaceAlias)
            if ($ForcePrivate) {
                try {
                    Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private
                    OK ("  Switched '{0}' -> Private." -f $p.InterfaceAlias)
                } catch {
                    Bad ("  Could not change profile: {0}" -f $_.Exception.Message)
                }
            } else {
                Info '  Re-run with -ForcePrivate to switch automatically.'
            }
        } else {
            OK ("Adapter '{0}' category: {1}." -f $p.InterfaceAlias, $p.NetworkCategory)
        }
    }

    # 4. Firewall
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
             Where-Object {
                ($_.DisplayGroup -like '*File and Printer Sharing*' -or
                 $_.DisplayGroup -like '*Common access to files*' -or
                 $_.DisplayGroup -like '*File*Print*Sharing*') -and
                 $_.Enabled -eq 'True' -and
                 $_.Direction -eq 'Inbound' -and
                 $_.Action -eq 'Allow'
             }
    if ($rules) {
        OK ("Firewall: {0} inbound-allow rules for File/Print Sharing." -f @($rules).Count)
    } else {
        Warn 'Firewall: no enabled inbound-allow rules for File/Print Sharing (may still be OK if other rules cover 445).'
    }

    # 5. Co2H pipe
    $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
             Where-Object Name -like "$Pipe*"
    if ($pipes) {
        OK ("Listener pipe present: {0}" -f ($pipes.Name -join ', '))
    } else {
        Warn ("Pipe '\\.\pipe\{0}' not found - co2h_server.exe is not running, or different pipe name." -f $Pipe)
    }

    # 6. Optional: open the pipe to anonymous/guest SMB sessions.
    if ($EnableNullSession) {
        Section 'Enabling NULL/Guest SMB session + IPC$ publication'
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        try {
            # IPC$ + admin shares publication. Без этого remote-клиент получит
            # error 67 (BAD_NET_NAME) — share IPC$ просто не существует.
            Set-ItemProperty -Path $key -Name AutoShareWks    -Type DWord -Value 1
            Set-ItemProperty -Path $key -Name AutoShareServer -Type DWord -Value 1
            OK 'AutoShareWks = 1, AutoShareServer = 1 (IPC$ will be published).'

            # NullSessionPipes: which pipes accept unauthenticated SMB callers.
            $cur = (Get-ItemProperty -Path $key -Name NullSessionPipes -ErrorAction SilentlyContinue).NullSessionPipes
            $list = @()
            if ($cur) { $list = @($cur) }
            if ($list -notcontains $Pipe) { $list += $Pipe }
            Set-ItemProperty -Path $key -Name NullSessionPipes -Type MultiString -Value $list
            OK ("NullSessionPipes now: {0}" -f ($list -join ', '))

            # Allow null session access globally.
            Set-ItemProperty -Path $key -Name RestrictNullSessAccess -Type DWord -Value 0
            OK 'RestrictNullSessAccess = 0'

            # LSA side: lower anonymous restrictions and allow anon SAM lookup.
            $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Set-ItemProperty -Path $lsa -Name RestrictAnonymous     -Type DWord -Value 0
            Set-ItemProperty -Path $lsa -Name RestrictAnonymousSAM  -Type DWord -Value 0
            Set-ItemProperty -Path $lsa -Name EveryoneIncludesAnonymous -Type DWord -Value 1
            OK 'LSA RestrictAnonymous/RestrictAnonymousSAM = 0, EveryoneIncludesAnonymous = 1'

            # Make the local Guest account usable for SMB (often disabled).
            $guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
            if ($guest) {
                if (-not $guest.Enabled) {
                    Enable-LocalUser -Name Guest
                    OK 'Local Guest account enabled.'
                } else { OK 'Local Guest account already enabled.' }
            } else { Warn 'No local Guest account on this box.' }

            try {
                Restart-Service LanmanServer -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 800
                OK 'LanmanServer restarted, settings applied.'
            } catch {
                Warn ("Could not restart LanmanServer: {0}" -f $_.Exception.Message)
                Info '  Reboot or restart it manually for changes to take effect.'
            }
            Warn 'These settings weaken SMB security globally - revert when no longer needed.'
        } catch {
            Bad ("EnableNullSession failed: {0}" -f $_.Exception.Message)
        }
    } else {
        Info 'Tip: if remote beacon gets error 64 / 1326 on IPC$, re-run with -EnableNullSession.'
    }

    # 7. Addresses for the client side
    $ips = Get-LocalIPv4
    Info ("Local IPv4: {0}" -f ($ips -join ', '))
    if ($ips) {
        Info ("From the beacon box run:  .\smb-diag.ps1 -Mode client -Server {0} -Pipe {1}" -f $ips[0], $Pipe)
    }
}

# ============================================================ CLIENT ===
function Run-Client {
    if (-not $Server) {
        Bad 'No -Server. Example: .\smb-diag.ps1 -Mode client -Server 10.100.102.2'
        return
    }

    Section ("Client-side check -> {0}\pipe\{1}" -f $Server, $Pipe)
    $ip = Resolve-Server $Server
    if (-not $ip) { Bad ("Cannot resolve '{0}'." -f $Server); return }
    OK ("Resolved: {0} -> {1}" -f $Server, $ip)

    # 1. TCP 445
    Info 'Test-NetConnection -Port 445'
    $tnc = Test-NetConnection $ip -Port 445 -WarningAction SilentlyContinue
    if ($tnc.TcpTestSucceeded) {
        OK 'TCP 445 reachable.'
    } else {
        Bad 'TCP 445 closed. Server firewall, or router between subnets.'
        return
    }

    # 2. Optional: enable insecure guest auth
    if ($AllowGuest) {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        try {
            New-Item -Path $key -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $key -Name AllowInsecureGuestAuth -Type DWord -Value 1
            OK 'AllowInsecureGuestAuth = 1.'

            # Restart-Service цепляет лишние зависимости (SessionEnv, RDP),
            # которые могут не подняться. net stop/start не трогает зависимостей.
            Info 'Restarting LanmanWorkstation via net stop/start...'
            $stop  = & cmd /c "net stop workstation /y 2>&1"
            $start = & cmd /c "net start workstation 2>&1"
            $stop  | ForEach-Object { Info ("  stop:  {0}" -f $_) }
            $start | ForEach-Object { Info ("  start: {0}" -f $_) }
            $svc = Get-Service LanmanWorkstation -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                OK 'LanmanWorkstation is Running.'
            } else {
                Warn 'LanmanWorkstation did not come back up - reboot may be required.'
                Info '  AllowInsecureGuestAuth value is saved; reboot will pick it up.'
            }
        } catch {
            Bad ("Could not write AllowInsecureGuestAuth: {0}" -f $_.Exception.Message)
        }
    }

    # 3. IPC$ session
    $unc = "\\$ip\IPC`$"
    Info ("net use {0}" -f $unc)
    & net use $unc /delete /y 2>$null | Out-Null
    if ($User) {
        & net use $unc $Pass /user:$User 2>&1 | ForEach-Object { Info ("  net use: {0}" -f $_) }
    } else {
        & net use $unc 2>&1 | ForEach-Object { Info ("  net use: {0}" -f $_) }
    }
    if ($LASTEXITCODE -eq 0) {
        OK 'IPC$ opened.'
    } else {
        Bad ("Could not open IPC`$ (exit={0})." -f $LASTEXITCODE)
        Info '  Error 5     -> need credentials: -User DOMAIN\u -Pass p'
        Info '  Error 53    -> SMB server not answering / server NIC is Public.'
        Info '  Error 64    -> SMB session was dropped (auth rejected). On the SERVER:'
        Info '                 .\smb-diag.ps1 -Mode server -EnableNullSession'
        Info '                 then on THIS box re-run with -AllowGuest'
        Info '  Error 67    -> IPC$ share missing on the server (AutoShareWks=0). On the SERVER:'
        Info '                 .\smb-diag.ps1 -Mode server -EnableNullSession'
        Info '                 (also republishes IPC$ + admin shares, restarts LanmanServer)'
        Info '  Error 1326  -> wrong username or password.'
        Info '  Try guest:  re-run with -AllowGuest'
    }

    # 4. Pipe visibility
    $pipePath = "\\$ip\pipe\$Pipe"
    Info ("Test-Path {0}" -f $pipePath)
    $exists = Test-Path -LiteralPath $pipePath
    if ($exists) {
        OK 'Pipe is visible over SMB - listener is ready to accept the beacon.'
    } else {
        Warn 'Pipe NOT visible over SMB. Wrong pipe name? Listener not running?'
    }

    # 5. Raw open/close - DACL check
    Info 'Direct pipe open (DACL check)'
    try {
        $h = [System.IO.File]::Open($pipePath, 'Open', 'ReadWrite')
        $h.Close()
        OK 'Pipe opened R/W - DACL OK.'
    } catch {
        Bad ("Open failed: {0}" -f $_.Exception.Message)
        Info '  UnauthorizedAccessException -> DACL/SMB-auth blocks (NULL DACL fix did not land - rebuild server).'
        Info '  FileNotFoundException       -> pipe does not exist.'
    }

    # 6. Drop the temp SMB session
    & net use $unc /delete /y 2>$null | Out-Null
}

# ============================================================== AUTO ===
switch ($Mode) {
    'server' { Run-Server }
    'client' { Run-Client }
    default {
        # Auto-detect: if our pipe is here, this is the server box.
        $isServer = (Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue |
                     Where-Object Name -like "$Pipe*").Count -gt 0
        if ($isServer) {
            Info 'Auto-detected: SERVER (co2h listener pipe present locally).'
            Run-Server
        } elseif ($Server) {
            Info 'Auto-detected: CLIENT (no local listener pipe, -Server given).'
            Run-Client
        } else {
            Warn 'Could not tell server from client.'
            Info '  Teamserver box:  .\smb-diag.ps1 -Mode server'
            Info '  Beacon box:      .\smb-diag.ps1 -Mode client -Server <ip>'
        }
    }
}
