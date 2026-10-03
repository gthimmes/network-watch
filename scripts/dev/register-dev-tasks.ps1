<#
.SYNOPSIS
  One-time setup: registers the NetworkWatch-Dev-Spike scheduled task so the spike
  can run elevated later without a UAC prompt (start it with scripts\dev\spike.ps1).

.DESCRIPTION
  Requires admin once. If not elevated, the script relaunches itself through UAC.
  The task runs as the current user with highest privileges, only while that user
  is logged on (no stored password). It executes scripts\dev\run-spike.ps1 from
  this repo, so re-run this script if the repo moves.

  Security note: the task runs the spike binary built in this repo with admin
  rights, and anything running as your account can rebuild that binary. Remove
  the task with scripts\dev\unregister-dev-tasks.ps1 when you don't need it.
#>
param([string]$ForUser = "$env:USERDOMAIN\$env:USERNAME")

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting administrator rights (one-time)..."
    $proc = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-ForUser', "`"$ForUser`"")
    exit $proc.ExitCode
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$principal = New-ScheduledTaskPrincipal -UserId $ForUser -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew

function Register-DevTask([string]$name, [string]$runnerScript, [string]$description) {
    $runner = Join-Path $repo "scripts\dev\$runnerScript"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`"" `
        -WorkingDirectory $repo
    Register-ScheduledTask -TaskName $name -TaskPath '\NetworkWatch\' -Description "$description Repo: $repo" `
        -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Registered \NetworkWatch\$name for $ForUser"
}

Register-DevTask 'NetworkWatch-Dev-Spike' 'run-spike.ps1' 'Dev only: runs the network-watch ETW spike elevated.'
Register-DevTask 'NetworkWatch-Dev-Service' 'run-service-op.ps1' 'Dev only: installs/restarts/uninstalls the NetworkWatch service from the latest publish.'
exit 0
