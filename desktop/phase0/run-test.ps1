#requires -Version 5.1
<#
  MadShield desktop, phase 0 test (Windows).

  The question it answers: can a sing-box TUN carry the WHOLE system through Aether (WARP) WITHOUT a traffic loop,
  with working DNS and a usable speed?

  Needs an elevated (Administrator) PowerShell: the TUN adapter and its routes need it.
  The internet of this PC goes through the tunnel for about a minute. Everything is stopped at the end.

    .\phase0\run-test.ps1                  # HTTP/2 carrier (default)
    .\phase0\run-test.ps1 -Carrier h3      # HTTP/3 (QUIC) carrier
    .\phase0\run-test.ps1 -NoStrict        # TUN without strict_route
    .\phase0\run-test.ps1 -CheckOnly       # only writes and validates the sing-box config (no admin needed)
    .\phase0\run-test.ps1 -Cleanup         # if a run was interrupted and the internet stayed cut
#>
[CmdletBinding()]
param(
    [string]$Kit = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('h2', 'h3')][string]$Carrier = 'h2',
    [string]$WorkDir = (Join-Path $env:TEMP 'madshield-phase0'),
    [switch]$NoStrict,
    [ValidateSet('engine-first', 'tun-first')][string]$Order = 'tun-first',
    [ValidateSet('info', 'debug')][string]$LogLevel = 'info',
    [switch]$CheckOnly,
    [switch]$Cleanup
)

# Native programs write to stderr all the time; do not turn that into script errors.
$ErrorActionPreference = 'Continue'

$aetherExe = Join-Path $Kit 'aether.exe'
$singExe = Join-Path $Kit 'sing-box.exe'
$socksPort = 1819
$tunName = 'MadShieldTun'
# Programs of the engines themselves must never enter the tunnel (that is the loop), they go out directly.
$engines = @('aether.exe', 'psiphon-tunnel-core.exe', 'lyrebird.exe', 'madshield-fx.exe', 'sing-box.exe')

$results = New-Object System.Collections.ArrayList
function Add-Result([string]$Name, [bool]$Ok, [string]$Detail, [bool]$Required = $true) {
    $tag = if ($Ok) { 'PASS' } elseif ($Required) { 'FAIL' } else { 'INFO' }
    [void]$results.Add([pscustomobject]@{ Tag = $tag; Name = $Name; Detail = $Detail; Required = $Required })
    Write-Host ("[{0}] {1}: {2}" -f $tag, $Name, $Detail)
}

function Stop-Mine($Proc) {
    if ($Proc -and -not $Proc.HasExited) { try { $Proc.Kill() } catch { } }
}

function Invoke-Curl([string[]]$CurlArgs) {
    return (& curl.exe @CurlArgs 2>&1 | Out-String)
}

function Show-Tail([string]$Path, [int]$Lines = 40) {
    if (Test-Path $Path) {
        Write-Host "---- last $Lines lines of $Path"
        Get-Content $Path -Tail $Lines | ForEach-Object { Write-Host $_ }
    }
}

function Get-CpuPercent([string[]]$Names, [int]$Seconds) {
    $before = @{}
    foreach ($n in $Names) {
        foreach ($p in (Get-Process -Name $n -ErrorAction SilentlyContinue)) {
            $before[$p.Id] = @{ Name = $n; T = $p.TotalProcessorTime.TotalSeconds }
        }
    }
    Start-Sleep -Seconds $Seconds
    $out = @{}
    foreach ($id in @($before.Keys)) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p) {
            $out[$before[$id].Name] = [math]::Round((($p.TotalProcessorTime.TotalSeconds - $before[$id].T) / $Seconds) * 100, 1)
        }
    }
    return $out
}

if ($Cleanup) {
    foreach ($n in 'sing-box', 'aether') { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
    ipconfig /flushdns | Out-Null
    Write-Host 'Stopped sing-box and aether. If the internet is still cut, disconnect and reconnect the network once.'
    exit 0
}

if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$cfg = Join-Path $WorkDir 'tun.json'

# ---- 1. the sing-box configuration ---------------------------------------------------------------------------------
$strict = if ($NoStrict) { 'false' } else { 'true' }
$engineJson = ($engines | ForEach-Object { '"' + $_ + '"' }) -join ', '
$json = @"
{
  "log": { "level": "$LogLevel", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "tcp", "tag": "dns-remote", "server": "1.1.1.1", "detour": "warp" },
      { "type": "udp", "tag": "dns-direct", "server": "1.1.1.1" }
    ],
    "rules": [
      { "process_name": [ $engineJson ], "action": "route", "server": "dns-direct" }
    ],
    "final": "dns-remote",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "$tunName",
      "address": [ "198.18.0.1/30", "fdfe:dcba:9876::1/126" ],
      "mtu": 1400,
      "auto_route": true,
      "strict_route": $strict,
      "stack": "system",
      "route_exclude_address": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "168.63.129.16/32", "224.0.0.0/4" ]
    }
  ],
  "outbounds": [
    { "type": "socks", "tag": "warp", "server": "127.0.0.1", "server_port": $socksPort, "version": "5" },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-direct",
    "rules": [
      { "process_name": [ $engineJson ], "action": "route", "outbound": "direct" },
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" }
    ],
    "final": "warp"
  }
}
"@
# No byte order mark: sing-box's JSON reader would reject it.
[System.IO.File]::WriteAllText($cfg, $json, (New-Object System.Text.UTF8Encoding($false)))

if (-not (Test-Path $singExe)) { Write-Host "sing-box.exe not found in $Kit"; exit 2 }
$checkOut = (& $singExe check -c $cfg 2>&1 | Out-String)
$checkOk = ($LASTEXITCODE -eq 0)
Add-Result 'sing-box accepts the configuration' $checkOk ($(if ($checkOk) { 'sing-box check passed' } else { $checkOut.Trim() }))
if ($CheckOnly -or -not $checkOk) {
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content $env:GITHUB_STEP_SUMMARY ("- {0}: sing-box check" -f $(if ($checkOk) { 'PASS' } else { 'FAIL' })) }
    if ($checkOk) { exit 0 } else { exit 1 }
}

# ---- 2. preconditions -------------------------------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this in an elevated PowerShell (Run as administrator).'; exit 2 }
if (-not (Test-Path $aetherExe)) { Write-Host "aether.exe not found in $Kit"; exit 2 }

$aether = $null
$sing = $null
$watchdog = $null
try {
    # ---- 3. what the PC looks like before anything runs -----------------------------------------------------------------
    $directTrace = Invoke-Curl @('-s', '--max-time', '15', '--noproxy', '*', 'https://www.cloudflare.com/cdn-cgi/trace')
    $directIp = if ($directTrace -match '(?m)^ip=(.+)$') { $Matches[1].Trim() } else { '?' }
    $directWarp = if ($directTrace -match '(?m)^warp=(.+)$') { $Matches[1].Trim() } else { '?' }
    Add-Result 'before anything runs: direct traffic is NOT through WARP' ($directWarp -eq 'off') "ip=$directIp warp=$directWarp" $false

    # ---- 4. watchdog: kills sing-box whatever happens to this script --------------------------------------------------
    $wd = "Start-Sleep -Seconds 300; Get-Process -Name sing-box -ErrorAction SilentlyContinue | Stop-Process -Force"
    $watchdog = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-WindowStyle', 'Hidden', '-Command', $wd -PassThru -WindowStyle Hidden

    function Start-Tun {
        Write-Host 'Starting sing-box TUN ...'
        $p = Start-Process -FilePath $singExe -ArgumentList 'run', '-c', $cfg -WorkingDirectory $WorkDir -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $WorkDir 'singbox.out.log') -RedirectStandardError (Join-Path $WorkDir 'singbox.err.log')
        $up = $false
        for ($i = 0; $i -lt 30 -and -not $p.HasExited; $i++) {
            Start-Sleep -Seconds 1
            if (Get-NetAdapter -Name $tunName -ErrorAction SilentlyContinue) { $up = $true; break }
        }
        if ($up) { Start-Sleep -Seconds 4 }
        return @{ Proc = $p; Up = $up }
    }

    function Start-Aether {
        Get-ChildItem Env: | Where-Object { $_.Name -like 'AETHER_*' } | ForEach-Object { Remove-Item "Env:$($_.Name)" }
        $env:AETHER_PROTOCOL = 'masque'
        $env:AETHER_SCAN = 'turbo'
        $env:AETHER_IP = 'v4'
        $env:AETHER_NOIZE = 'balanced'
        $env:AETHER_LOG_LEVEL = 'info'
        $env:AETHER_SOCKS = "127.0.0.1:$socksPort"
        $env:AETHER_CONFIG = (Join-Path $WorkDir 'aether.toml')
        $env:AETHER_QUICK_RECONNECT = '1'
        $env:AETHER_MASQUE_HTTP2 = $(if ($Carrier -eq 'h2') { '1' } else { '0' })
        $env:AETHER_MASQUE_MTU = '1280'
        $emptyIn = Join-Path $WorkDir 'stdin.txt'
        New-Item -ItemType File -Force -Path $emptyIn | Out-Null
        Write-Host "Starting aether ($Carrier) ..."
        $p = Start-Process -FilePath $aetherExe -WorkingDirectory $Kit -PassThru -NoNewWindow `
            -RedirectStandardInput $emptyIn `
            -RedirectStandardOutput (Join-Path $WorkDir 'aether.out.log') -RedirectStandardError (Join-Path $WorkDir 'aether.err.log')
        $ok = $false
        $deadline = (Get-Date).AddSeconds(120)
        while ((Get-Date) -lt $deadline -and -not $p.HasExited) {
            $t = Invoke-Curl @('-s', '--max-time', '10', '--socks5-hostname', "127.0.0.1:$socksPort", 'https://www.cloudflare.com/cdn-cgi/trace')
            if ($t -match 'warp=(on|plus)') { $ok = $true; break }
            Start-Sleep -Seconds 3
        }
        return @{ Proc = $p; Ok = $ok }
    }

    # ---- 5. start in the chosen order ------------------------------------------------------------------------------------
    # engine-first: aether up, then the TUN (its open connection sees the routes change underneath it).
    # tun-first:    the TUN up (everything fails closed, aether's own process is routed direct), then aether.
    Write-Host "Order: $Order"
    if ($Order -eq 'engine-first') {
        $a = Start-Aether; $aether = $a.Proc
        Add-Result 'aether brings the tunnel up (SOCKS reaches WARP)' $a.Ok ($(if ($a.Ok) { 'warp=on through 127.0.0.1:' + $socksPort } else { 'no warp=on within 120 s' }))
        if (-not $a.Ok) { throw 'aether did not come up' }
        $t = Start-Tun; $sing = $t.Proc
        Add-Result 'the TUN adapter appears' $t.Up ($(if ($t.Up) { "adapter $tunName is up" } else { 'no adapter within 30 s (sing-box exited: ' + $sing.HasExited + ')' }))
        if (-not $t.Up) { throw 'the TUN did not start' }
    }
    else {
        $t = Start-Tun; $sing = $t.Proc
        Add-Result 'the TUN adapter appears' $t.Up ($(if ($t.Up) { "adapter $tunName is up" } else { 'no adapter within 30 s (sing-box exited: ' + $sing.HasExited + ')' }))
        if (-not $t.Up) { throw 'the TUN did not start' }
        $a = Start-Aether; $aether = $a.Proc
        Add-Result 'aether brings the tunnel up with the TUN already running' $a.Ok ($(if ($a.Ok) { 'warp=on through 127.0.0.1:' + $socksPort } else { 'no warp=on within 120 s' }))
        if (-not $a.Ok) { throw 'aether did not come up' }
    }

    # ---- 6. checks with the tunnel up -----------------------------------------------------------------------------------
    # Bringing the TUN up changes the routes under Aether's already open connection. A QUIC (h3) connection does not
    # survive that: Aether notices, reconnects directly (its process is routed to "direct") and is back within seconds.
    # So: poll until the system path works, and report how long it took (the app has to expect the same blip).
    $trace = ''
    $viaWarp = $false
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 45) {
        $trace = Invoke-Curl @('-s', '--max-time', '8', '--noproxy', '*', 'https://www.cloudflare.com/cdn-cgi/trace')
        if ($trace -match 'warp=(on|plus)') { $viaWarp = $true; break }
        Start-Sleep -Seconds 2
    }
    Add-Result 'time until the system path works after the TUN came up' $true ('{0:N0} s' -f $sw.Elapsed.TotalSeconds) $false
    $tunIp = if ($trace -match '(?m)^ip=(.+)$') { $Matches[1].Trim() } else { '?' }
    Add-Result 'a program that knows nothing about the tunnel goes through WARP' $viaWarp "ip=$tunIp (before: $directIp)"

    $http = (Invoke-Curl @('-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '25', '--noproxy', '*', 'https://example.com/')).Trim()
    Add-Result 'a name is resolved and a page loads' ($http -eq '200') "example.com -> HTTP $http"

    $dnsOk = $false
    try { $dnsOk = [bool](Resolve-DnsName -Name 'example.org' -Type A -ErrorAction Stop) } catch { }
    Add-Result 'system DNS answers (Resolve-DnsName)' $dnsOk ($(if ($dnsOk) { 'example.org resolved' } else { 'no answer' }))

    $cpu = Get-CpuPercent @('sing-box', 'aether') 8
    $loopFree = $true
    foreach ($k in $cpu.Keys) { if ($cpu[$k] -gt 30) { $loopFree = $false } }
    Add-Result 'no traffic loop: idle CPU of sing-box and aether stays low' $loopFree (($cpu.Keys | ForEach-Object { "$_=" + $cpu[$_] + '%' }) -join ' ')

    $speed = (Invoke-Curl @('-s', '-o', 'NUL', '-w', '%{speed_download}', '--max-time', '25', '--noproxy', '*', 'https://speed.cloudflare.com/__down?bytes=30000000')).Trim()
    $mbps = 0
    [void][double]::TryParse($speed, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$mbps)
    Add-Result 'download speed through the tunnel' ($mbps -gt 100000) ('{0:N2} MiB/s' -f ($mbps / 1MB)) $false

    $v6 = (Invoke-Curl @('-s', '-6', '--max-time', '8', '--noproxy', '*', 'https://[2606:4700:4700::1111]/cdn-cgi/trace')).Trim()
    Add-Result 'IPv6 (information only)' $true ($(if ($v6) { 'an IPv6 request got an answer: ' + (($v6 -split "`n")[0..2] -join ' ') } else { 'IPv6 does not get out (no leak either way)' })) $false

    $whoami = ''
    try { $whoami = (Resolve-DnsName -Name 'whoami.akamai.net' -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress } catch { }
    Add-Result 'DNS egress address (information only: should not be this PC''s ISP resolver)' $true "recursive resolver seen by the authoritative server: $whoami" $false

    Write-Host '---- UDP sockets of aether'
    Get-NetUDPEndpoint -OwningProcess $aether.Id -ErrorAction SilentlyContinue | Format-Table LocalAddress, LocalPort | Out-String | Write-Host
    Write-Host '---- IPv4 routes'
    route print -4 | Select-Object -First 45 | ForEach-Object { Write-Host $_ }

    $alive = (-not $aether.HasExited) -and (-not $sing.HasExited)
    Add-Result 'both processes are still running at the end' $alive ("aether exited=" + $aether.HasExited + ' sing-box exited=' + $sing.HasExited)
}
catch {
    Write-Host ("ERROR: " + $_.Exception.Message)
}
finally {
    Stop-Mine $sing
    Start-Sleep -Seconds 3
    Stop-Mine $aether
    Stop-Mine $watchdog
    Show-Tail (Join-Path $WorkDir 'singbox.err.log') 40
    $sbLog = Join-Path $WorkDir 'singbox.err.log'
    if (Test-Path $sbLog) {
        Write-Host '---- sing-box lines that mention an engine process (first 40)'
        Select-String -Path $sbLog -Pattern 'aether|psiphon|lyrebird|madshield-fx' | Select-Object -First 40 | ForEach-Object { Write-Host $_.Line }
    }
    Show-Tail (Join-Path $WorkDir 'singbox.out.log') 20
    Show-Tail (Join-Path $WorkDir 'aether.err.log') 40
    Show-Tail (Join-Path $WorkDir 'aether.out.log') 40
}

# ---- 7. summary -------------------------------------------------------------------------------------------------------
$failed = @($results | Where-Object { $_.Tag -eq 'FAIL' })
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("## MadShield desktop phase 0 ($Carrier, $Order, strict_route=$strict)")
foreach ($r in $results) { [void]$md.AppendLine(("- **{0}** {1}: {2}" -f $r.Tag, $r.Name, $r.Detail)) }
[void]$md.AppendLine(("Result: {0}" -f $(if ($failed.Count -eq 0) { 'ALL REQUIRED CHECKS PASSED' } else { "$($failed.Count) required check(s) failed" })))
[System.IO.File]::WriteAllText((Join-Path $WorkDir 'result.md'), $md.ToString(), (New-Object System.Text.UTF8Encoding($false)))
if ($env:GITHUB_STEP_SUMMARY) { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $md.ToString() }
Write-Host $md.ToString()
if ($failed.Count -eq 0) { exit 0 } else { exit 1 }
