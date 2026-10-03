<#
.SYNOPSIS
  Executed BY the elevated scheduled task. Do not run directly; use spike.ps1.

.DESCRIPTION
  Reads .dev\spike-request.json (validated: duration 5-600s, booleans all/dns only),
  runs the already-built spike exe, and writes .dev\spike.log and .dev\spike.status.
  It never builds code and never executes anything other than the spike exe.
#>
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dev = Join-Path $repo '.dev'
$status = Join-Path $dev 'spike.status'
$log = Join-Path $dev 'spike.log'
New-Item -ItemType Directory -Force -Path $dev | Out-Null

try {
    Set-Content -Path $status -Value 'running' -Encoding ascii

    $duration = 60; $all = $false; $dns = $false
    $requestPath = Join-Path $dev 'spike-request.json'
    if (Test-Path $requestPath) {
        $req = Get-Content $requestPath -Raw | ConvertFrom-Json
        if ($null -ne $req.duration) { $duration = [Math]::Min(600, [Math]::Max(5, [int]$req.duration)) }
        if ($null -ne $req.all) { $all = [bool]$req.all }
        if ($null -ne $req.dns) { $dns = [bool]$req.dns }
    }

    $exe = Join-Path $repo 'src\NetworkWatch.Spike\bin\Debug\net10.0-windows\NetworkWatch.Spike.exe'
    if (-not (Test-Path $exe)) { throw "Spike not built: $exe (run dotnet build first)" }

    $spikeArgs = @('--log', $log, '--duration', "$duration")
    if ($all) { $spikeArgs += '--all' }
    if ($dns) { $spikeArgs += '--dns' }

    Remove-Item $log -ErrorAction SilentlyContinue
    & $exe @spikeArgs | Out-Null
    Set-Content -Path $status -Value "done exit=$LASTEXITCODE" -Encoding ascii
}
catch {
    Set-Content -Path $status -Value "failed: $($_.Exception.Message)" -Encoding ascii
    exit 1
}
