# network-watch — context for Claude / contributors

Local network-monitoring tool: a Windows service watches every connection (per process, with DNS names), runs detections, and a tray app shows alerts. **Read [PLAN.md](PLAN.md) first.** It holds the product reasoning, the detection list, the architecture, and the decisions made so far.

## Current status

- **Phase:** Phase 0 spike (console app printing live `process → domain → IP:port` from ETW). See "Next steps" below.
- **Owner context:** personal use on the owner's own Windows 11 machine for now. Other OSes and headless servers come later, so keep the core portable (rules below).

## Architecture rules (don't break these)

1. **`NetworkWatch.Core` targets plain `net10.0`** and must not reference Windows APIs, ETW, the registry, WinForms, or `System.Management`. Models, flow aggregation, DNS↔IP correlation, detections, and SQLite storage live here.
2. **OS-specific code lives only in `NetworkWatch.Collectors.<OS>`** (and the future `IEnforcer` implementations for blocking). Collectors produce normalized events through `ICollector`.
3. **The service is the product, and the tray is just one client.** The service must run headless (that's the server deployment story). UI talks to it over a local API (named pipe for now). Alerts go out through pluggable `IAlertSink`s.
4. **Avoid alert fatigue.** Only High severity produces a toast. New detections need a severity tier and a plain-English explanation ("what happened / why it matters / what to do").
5. **Everything stays local.** No telemetry. Any outbound lookup (VirusTotal, AbuseIPDB) is opt-in.

## Tech

- C# / **.NET 10 (LTS)**. ETW via `Microsoft.Diagnostics.Tracing.TraceEvent`. Storage via `Microsoft.Data.Sqlite`. The service host uses `Microsoft.Extensions.Hosting.WindowsServices`.
- ETW kernel network/process sessions **require admin**. The service runs as LocalSystem. The spike/console must be run from an elevated terminal.

## Setting up on a new machine

```powershell
winget install --id Microsoft.DotNet.SDK.10 --exact
git clone https://github.com/gthimmes/network-watch.git
cd network-watch
dotnet build
```

## Gotchas

- Windows PowerShell 5.1 `Get-Content`/`Set-Content` default to the ANSI codepage. They will mangle the UTF-8 in these docs (em dashes, arrows, box-drawing). Use `-Encoding utf8` or edit files with a proper editor.

## Next steps

1. Scaffold the solution layout from PLAN.md §10 (`src/…`, `tests/…`).
2. Phase 0 spike: real-time ETW session (kernel NetworkTCPIP + `Microsoft-Windows-DNS-Client`), print per-process connections with resolved domain names. Validate the data quality (short-lived connections, UDP, IPv6, PID → path resolution after the process exits).
3. Then Phase 1 MVP per PLAN.md §7.
