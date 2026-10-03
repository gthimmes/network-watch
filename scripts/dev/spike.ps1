<#
.SYNOPSIS
  Runs the ETW spike elevated via the dev scheduled task -- no UAC prompt.
  Builds first (as the normal user), then waits and prints the log.

.EXAMPLE
  .\scripts\dev\spike.ps1 -Duration 60 -Dns
#>
param(
    [ValidateRange(5, 600)][int]$Duration = 60,
    [switch]$All,
    [switch]$Dns,
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dev = Join-Path $repo '.dev'
$status = Join-Path $dev 'spike.status'
$log = Join-Path $dev 'spike.log'
New-Item -ItemType Directory -Force -Path $dev | Out-Null

if (-not (Get-ScheduledTask -TaskPath '\NetworkWatch\' -TaskName 'NetworkWatch-Dev-Spike' -ErrorAction SilentlyContinue)) {
    throw 'Dev task not registered. Run scripts\dev\register-dev-tasks.ps1 once (one UAC prompt).'
}

if (-not $NoBuild) {
    dotnet build (Join-Path $repo 'src\NetworkWatch.Spike') -nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
}

@{ duration = $Duration; all = [bool]$All; dns = [bool]$Dns } | ConvertTo-Json | Set-Content (Join-Path $dev 'spike-request.json') -Encoding ascii
Set-Content -Path $status -Value 'queued' -Encoding ascii

Start-ScheduledTask -TaskPath '\NetworkWatch\' -TaskName 'NetworkWatch-Dev-Spike'
Write-Host "Spike running elevated for $Duration s..."

$deadline = (Get-Date).AddSeconds($Duration + 60)
do {
    Start-Sleep -Seconds 2
    $state = (Get-Content $status -Raw -ErrorAction SilentlyContinue).Trim()
} while ($state -in 'queued', 'running' -and (Get-Date) -lt $deadline)

Write-Host "Status: $state"
if (Test-Path $log) { Get-Content $log -Encoding utf8 }
if ($state -notlike 'done exit=0') { exit 1 }
