<#
.SYNOPSIS
  Executed BY the elevated NetworkWatch-Dev-Service task. Do not run directly; use service.ps1.

.DESCRIPTION
  Reads .dev\service-request.json ({ "op": "install" | "restart" | "stop" | "uninstall" }),
  performs that operation on the NetworkWatch Windows service, and writes
  .dev\service.status and .dev\service-op.log.

  install  : stop if running, mirror artifacts\install -> %ProgramFiles%\NetworkWatch (service\, cli\, tray\),
             create the service if missing (auto start, restart on failure), start it.
  restart  : restart the installed service.
  stop     : stop the service.
  uninstall: stop, delete the service, remove the program files (keeps %ProgramData% data).
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dev = Join-Path $repo '.dev'
$status = Join-Path $dev 'service.status'
$log = Join-Path $dev 'service-op.log'
New-Item -ItemType Directory -Force -Path $dev | Out-Null

$serviceName = 'NetworkWatch'
$source = Join-Path $repo 'artifacts\install'
$dest = Join-Path $env:ProgramFiles 'NetworkWatch'
$exe = Join-Path $dest 'service\NetworkWatch.Service.exe'

function Log([string]$msg) { Add-Content -Path $log -Value "$(Get-Date -Format HH:mm:ss) $msg" -Encoding ascii }

function Stop-NwService {
    $svc = Get-Service $serviceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Log 'stopping service'
        Stop-Service $serviceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

try {
    Set-Content -Path $status -Value 'running' -Encoding ascii
    Set-Content -Path $log -Value '' -Encoding ascii

    $op = 'install'
    $requestPath = Join-Path $dev 'service-request.json'
    if (Test-Path $requestPath) { $op = [string](Get-Content $requestPath -Raw | ConvertFrom-Json).op }
    if ($op -notin 'install', 'restart', 'stop', 'uninstall') { throw "Unknown op '$op'" }
    Log "op=$op"

    switch ($op) {
        'install' {
            if (-not (Test-Path (Join-Path $source 'service\NetworkWatch.Service.exe'))) { throw "Not published: $source (run service.ps1, which publishes first)" }
            # Same code path as a real install, so dev deploys exercise the installer.
            & (Join-Path $repo 'scripts\install.ps1') -Elevated -Source $source
            if ($LASTEXITCODE -ne 0) { throw "install.ps1 failed ($LASTEXITCODE); see $env:TEMP\NetworkWatch-install.log" }
            Log 'installed via scripts\install.ps1 and started'
        }
        'restart' { Stop-NwService; Start-Service $serviceName; Log 'restarted' }
        'stop' { Stop-NwService; Log 'stopped' }
        'uninstall' {
            # Same code path as a real uninstall (keeps %ProgramData% data).
            & (Join-Path $repo 'scripts\uninstall.ps1') -Elevated
            if ($LASTEXITCODE -ne 0) { throw "uninstall.ps1 failed ($LASTEXITCODE)" }
            Log 'uninstalled via scripts\uninstall.ps1'
        }
    }

    $state = (Get-Service $serviceName -ErrorAction SilentlyContinue).Status
    Set-Content -Path $status -Value "done op=$op service=$state" -Encoding ascii
}
catch {
    Log "ERROR: $($_.Exception.Message)"
    Set-Content -Path $status -Value "failed: $($_.Exception.Message)" -Encoding ascii
    exit 1
}
