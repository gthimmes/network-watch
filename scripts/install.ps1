<#
.SYNOPSIS
  Installs or upgrades Network Watch from an unzipped release folder (service\, cli\, tray\).

.DESCRIPTION
  Run as your normal user; it asks for administrator rights once (UAC) for the system part:
  copies files to %ProgramFiles%\NetworkWatch, installs/updates the NetworkWatch service (LocalSystem,
  automatic start, restart on failure), and adds a Start menu shortcut. Then it starts the tray app
  as you (not elevated). Data in %ProgramData%\NetworkWatch is kept across upgrades.
#>
param([switch]$Elevated, [string]$Source = $PSScriptRoot)

$ErrorActionPreference = 'Stop'
$source = $Source
$dest = Join-Path $env:ProgramFiles 'NetworkWatch'
$serviceName = 'NetworkWatch'
$trayExe = Join-Path $dest 'tray\NetworkWatch.Tray.exe'

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DesktopRuntime {
    $dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
    if (-not (Test-Path $dotnet)) { return $false }
    return [bool](& $dotnet --list-runtimes | Select-String '^Microsoft\.WindowsDesktop\.App 10\.')
}

if (-not $Elevated) {
    foreach ($part in 'service\NetworkWatch.Service.exe', 'cli\nwctl.exe', 'tray\NetworkWatch.Tray.exe') {
        if (-not (Test-Path (Join-Path $source $part))) { throw "Missing $part next to install.ps1. Run this from the unzipped release folder." }
    }

    if (-not (Test-DesktopRuntime)) {
        Write-Host 'Network Watch needs the .NET 10 Desktop Runtime, which is not installed.'
        $answer = Read-Host 'Install it now with winget (Microsoft.DotNet.DesktopRuntime.10)? [Y/n]'
        if ($answer -and $answer -notmatch '^[Yy]') { throw 'Cancelled. Install the .NET 10 Desktop Runtime from https://dot.net and run install.ps1 again.' }
        winget install --id Microsoft.DotNet.DesktopRuntime.10 --exact --accept-package-agreements --accept-source-agreements
        if (-not (Test-DesktopRuntime)) { throw '.NET 10 Desktop Runtime installation did not complete.' }
    }

    # Close a running tray so its files can be replaced.
    Get-Process NetworkWatch.Tray -ErrorAction SilentlyContinue | Stop-Process -Force

    Write-Host 'Requesting administrator rights to install the service...'
    $proc = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    if ($proc.ExitCode -ne 0) { throw "Installation failed (exit code $($proc.ExitCode)). See $env:TEMP\NetworkWatch-install.log" }

    # Start the tray as the current (non-elevated) user; it registers itself to start at sign-in.
    Start-Process $trayExe
    Write-Host ''
    Write-Host 'Network Watch is installed and running. Look for the shield icon in the system tray.'
    Write-Host "It spends the first 7 days learning what's normal on this PC; high-risk checks are active immediately."
    Write-Host "Command line: `"$dest\cli\nwctl.exe`" status"
    return
}

# ---- Elevated part ----
Start-Transcript -Path (Join-Path $env:TEMP 'NetworkWatch-install.log') -Force | Out-Null
try {
    if (-not (Test-Admin)) { throw 'The elevated part must run as administrator.' }

    $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Write-Host 'Stopping service...'
        Stop-Service $serviceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    foreach ($part in 'service', 'cli', 'tray') {
        robocopy (Join-Path $source $part) (Join-Path $dest $part) /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Copying $part failed (robocopy $LASTEXITCODE)." }
    }
    Copy-Item (Join-Path $source 'uninstall.ps1') $dest -Force -ErrorAction SilentlyContinue

    $exe = Join-Path $dest 'service\NetworkWatch.Service.exe'
    if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
        Write-Host 'Creating service...'
        New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName 'Network Watch' `
            -Description 'Monitors network connections and alerts on suspicious activity.' -StartupType Automatic | Out-Null
    }
    sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
    Start-Service $serviceName
    Write-Host 'Service started.'

    # Start menu shortcut for all users: opens the dashboard (or starts the tray).
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Network Watch.lnk'))
    $lnk.TargetPath = Join-Path $dest 'tray\NetworkWatch.Tray.exe'
    $lnk.Arguments = '--show'
    $lnk.Description = 'Network Watch dashboard'
    $lnk.Save()
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    Stop-Transcript | Out-Null
    exit 1
}
Stop-Transcript | Out-Null
exit 0
