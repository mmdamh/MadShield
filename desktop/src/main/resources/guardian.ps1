# Started hidden by MadShield. When the app that started it is gone for any reason (crash, Task Manager), it stops every
# engine program of the kit, so the TUN cannot stay behind holding the internet. Exits by itself when the app ends normally.
param([int]$ParentPid, [string]$Kit)
$ErrorActionPreference = 'SilentlyContinue'
while (Get-Process -Id $ParentPid) { Start-Sleep -Seconds 2 }
Start-Sleep -Seconds 3   # a normal exit stops its own children first
$kitPrefix = ([IO.Path]::GetFullPath($Kit)).TrimEnd('\') + '\'
Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutablePath -and $_.ExecutablePath.StartsWith($kitPrefix, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
