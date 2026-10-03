<#
.SYNOPSIS
  Install/update/restart/stop/uninstall the NetworkWatch service via the elevated dev task -- no UAC prompt.

.DESCRIPTION
  install (default): publishes service, CLI and tray to artifacts\install\{service,cli,tray} as the normal
  user, closes the installed tray app (it locks its files), then the elevated task mirrors that folder to
  %ProgramFiles%\NetworkWatch and (re)starts the service. Afterwards the installed tray app is relaunched.

.EXAMPLE
  .\scripts\dev\service.ps1              # build + install/update + start
  .\scripts\dev\service.ps1 -Op restart
  .\scripts\dev\service.ps1 -Op uninstall
#>
param(
    [ValidateSet('install', 'restart', 'stop', 'uninstall')][string]$Op = 'install',
    [switch]$NoTray
)

$ErrorActionPreference = 'Stop'
# Fresh SDK installs may not be on PATH in already-open shells.
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { $env:Path = "$env:ProgramFiles\dotnet;$env:Path" }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dev = Join-Path $repo '.dev'
$status = Join-Path $dev 'service.status'
$log = Join-Path $dev 'service-op.log'
$install = Join-Path $repo 'artifacts\install'
$installedTray = Join-Path $env:ProgramFiles 'NetworkWatch\tray\NetworkWatch.Tray.exe'
New-Item -ItemType Directory -Force -Path $dev | Out-Null

if (-not (Get-ScheduledTask -TaskPath '\NetworkWatch\' -TaskName 'NetworkWatch-Dev-Service' -ErrorAction SilentlyContinue)) {
    throw 'Dev task not registered. Run scripts\dev\register-dev-tasks.ps1 once (one UAC prompt).'
}

if ($Op -eq 'install') {
    $projects = @{
        service = 'src\NetworkWatch.Service'
        cli     = 'src\NetworkWatch.Cli'
        tray    = 'src\NetworkWatch.Tray'
    }
    foreach ($name in $projects.Keys) {
        $project = Join-Path $repo $projects[$name]
        if (-not (Test-Path $project)) { continue }
        $out = Join-Path $install $name
        if (Test-Path $out) { Remove-Item $out -Recurse -Force }
        Write-Host "Publishing $name..."
        dotnet publish $project -c Release -o $out -nologo -v quiet
        if ($LASTEXITCODE -ne 0) { throw "Publish of $name failed." }
    }
}

if ($Op -in 'install', 'uninstall') {
    Get-Process NetworkWatch.Tray -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like (Join-Path $env:ProgramFiles 'NetworkWatch\*') } |
        Stop-Process -Force
}

@{ op = $Op } | ConvertTo-Json | Set-Content (Join-Path $dev 'service-request.json') -Encoding ascii
Set-Content -Path $status -Value 'queued' -Encoding ascii
Start-ScheduledTask -TaskPath '\NetworkWatch\' -TaskName 'NetworkWatch-Dev-Service'

$deadline = (Get-Date).AddMinutes(3)
do {
    Start-Sleep -Seconds 1
    $state = (Get-Content $status -Raw -ErrorAction SilentlyContinue).Trim()
} while ($state -in 'queued', 'running' -and (Get-Date) -lt $deadline)

if (Test-Path $log) { Get-Content $log }
Write-Host "Status: $state"
if ($state -notlike 'done*') { exit 1 }

if ($Op -eq 'install' -and -not $NoTray -and (Test-Path $installedTray)) {
    Start-Process $installedTray
    Write-Host 'Tray app started.'
}
