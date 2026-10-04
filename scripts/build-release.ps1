<#
.SYNOPSIS
  Builds a release zip: artifacts\release\NetworkWatch-<version>-win-x64.zip
  containing service\, cli\, tray\, install.ps1, uninstall.ps1 and README.txt.

.DESCRIPTION
  Framework-dependent publish (needs the .NET 10 Desktop Runtime on the target; install.ps1 offers to
  install it with winget). Run tests first unless -SkipTests.
#>
param([switch]$SkipTests)

$ErrorActionPreference = 'Stop'
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { $env:Path = "$env:ProgramFiles\dotnet;$env:Path" }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = ([xml](Get-Content (Join-Path $repo 'src\NetworkWatch.Service\NetworkWatch.Service.csproj'))).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
$stage = Join-Path $repo "artifacts\release\NetworkWatch-$version"
$zip = "$stage-win-x64.zip"

if (-not $SkipTests) {
    dotnet test (Join-Path $repo 'NetworkWatch.slnx') -nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
}

if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
foreach ($p in @(@('service', 'src\NetworkWatch.Service'), @('cli', 'src\NetworkWatch.Cli'), @('tray', 'src\NetworkWatch.Tray'))) {
    Write-Host "Publishing $($p[0])..."
    dotnet publish (Join-Path $repo $p[1]) -c Release -r win-x64 --self-contained false -o (Join-Path $stage $p[0]) -nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw "Publish of $($p[0]) failed." }
}
Copy-Item (Join-Path $PSScriptRoot 'install.ps1'), (Join-Path $PSScriptRoot 'uninstall.ps1') $stage
@"
Network Watch $version

Install:   right-click install.ps1 > Run with PowerShell  (or: powershell -ExecutionPolicy Bypass -File install.ps1)
Uninstall: powershell -ExecutionPolicy Bypass -File "C:\Program Files\NetworkWatch\uninstall.ps1"

Requires Windows 10/11 x64 and the .NET 10 Desktop Runtime (the installer offers to install it).
Data and logs: C:\ProgramData\NetworkWatch.  Command line: C:\Program Files\NetworkWatch\cli\nwctl.exe help
Threat intel: abuse.ch (ThreatFox, URLhaus, Feodo), Spamhaus DROP, Tor Project. $("IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0.")
"@ | Set-Content (Join-Path $stage 'README.txt') -Encoding ascii

if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Write-Host "Built $zip ($([int]((Get-Item $zip).Length / 1MB)) MB)"
