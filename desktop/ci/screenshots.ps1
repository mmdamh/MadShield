# Starts the packaged program in a few states and saves a picture of its window for each (CI only; reviewed by eye).
param([string]$Exe, [string]$OutDir)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public class Win { 
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
"@
$settings = Join-Path $env:LOCALAPPDATA 'MadShield\settings.json'
New-Item -ItemType Directory -Force -Path (Split-Path $settings) | Out-Null

function Shot([string]$name, [string]$lang, [string]$page, [bool]$connect, [int]$wait) {
  $conn = if ($connect) { 'true' } else { 'false' }
  Set-Content -Path $settings -Encoding UTF8 -Value ('{"language":"' + $lang + '","engine":"warp","protocol":"MASQUE_H2","chain":"NONE","connectOnStart":' + $conn + '}')
  $p = Start-Process -FilePath $Exe -ArgumentList "--page=$page" -PassThru
  Start-Sleep -Seconds $wait
  $p.Refresh()
  if ($p.HasExited) { Write-Host "[$name] program exited with code $($p.ExitCode)"; return }
  [void][Win]::SetForegroundWindow($p.MainWindowHandle)
  Start-Sleep -Milliseconds 600
  $r = New-Object Win+RECT
  [void][Win]::GetWindowRect($p.MainWindowHandle, [ref]$r)
  $w = [Math]::Max(1, $r.R - $r.L); $h = [Math]::Max(1, $r.B - $r.T)
  $bmp = New-Object System.Drawing.Bitmap $w, $h
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
  $bmp.Save((Join-Path $OutDir "$name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
  Write-Host "[$name] ${w}x${h}"
  Stop-Process -Id $p.Id -Force
  Start-Sleep -Seconds 4
  Get-Process sing-box, aether, madshield-fx, psiphon-tunnel-core, lyrebird -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 3
}

Shot 'fa-home'     'fa' 'home'     $false 14
Shot 'en-home'     'en' 'home'     $false 12
Shot 'en-engine'   'en' 'engine'   $false 12
Shot 'fa-engine'   'fa' 'engine'   $false 12
Shot 'en-rules'    'en' 'rules'    $false 12
Shot 'en-settings' 'en' 'settings' $false 12
Shot 'en-connected' 'en' 'home'    $true  70
Remove-Item $settings -ErrorAction SilentlyContinue
