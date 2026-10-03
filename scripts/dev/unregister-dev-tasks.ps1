<#
.SYNOPSIS
  Removes the dev scheduled tasks created by register-dev-tasks.ps1 (needs admin once).
#>
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $proc = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    exit $proc.ExitCode
}

Get-ScheduledTask -TaskPath '\NetworkWatch\' -ErrorAction SilentlyContinue |
    Where-Object TaskName -like 'NetworkWatch-Dev-*' |
    ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false
        Write-Host "Removed $($_.TaskPath)$($_.TaskName)"
    }
