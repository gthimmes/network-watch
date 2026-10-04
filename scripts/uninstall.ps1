<#
.SYNOPSIS
  Uninstalls Network Watch: stops and removes the service, removes any firewall blocks it created,
  the program files, Start menu shortcut and tray autostart. Keeps %ProgramData%\NetworkWatch
  (history, settings) unless -RemoveData is given.
#>
param([switch]$RemoveData, [switch]$Elevated)

$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:ProgramFiles 'NetworkWatch'

if (-not $Elevated) {
    Get-Process NetworkWatch.Tray -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name NetworkWatchTray -ErrorAction SilentlyContinue
    Remove-Item HKCU:\Software\NetworkWatch -Recurse -ErrorAction SilentlyContinue

    # Run the system part from a temp copy: this script may live in the folder being deleted.
    $temp = Join-Path $env:TEMP 'NetworkWatch-uninstall.ps1'
    Copy-Item $PSCommandPath $temp -Force
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$temp`"", '-Elevated')
    if ($RemoveData) { $arguments += '-RemoveData' }
    $proc = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList $arguments
    if ($proc.ExitCode -ne 0) { throw "Uninstall failed (exit code $($proc.ExitCode))." }
    Write-Host 'Network Watch has been removed.'
    return
}

$svc = Get-Service NetworkWatch -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') { Stop-Service NetworkWatch -Force; $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
    sc.exe delete NetworkWatch | Out-Null
}

# Firewall rules created by the Block action would otherwise keep blocking programs forever.
Get-NetFirewallRule -Group 'NetworkWatch' -ErrorAction SilentlyContinue | Remove-NetFirewallRule

Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Network Watch.lnk') -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
if ($RemoveData) { Remove-Item (Join-Path $env:ProgramData 'NetworkWatch') -Recurse -Force -ErrorAction SilentlyContinue }
exit 0
