# network-watch — context for Claude / contributors

Local network-monitoring tool: a Windows service watches every connection (per process, with DNS names), runs detections, and a tray app shows alerts. **Read [PLAN.md](PLAN.md) first.** It holds the product reasoning, the detection list, the architecture, and the decisions made so far.

## Current status

- **Phase 0 spike: code complete and builds, but not yet run against live traffic.**
  - `src/NetworkWatch.Spike` prints live `process → domain → IP:port` and a data-quality summary.
  - `NetworkWatch.Core` has `DnsCorrelator`, `FlowTracker`, `IpClassifier`, and the `ICollector` interface. These are portable and unit-tested.
  - `NetworkWatch.Collectors.Windows` has `EtwNetworkCollector`: a kernel TCP/IP + process session plus a `Microsoft-Windows-DNS-Client` session, using TraceEvent 3.2.8.
  - `dotnet test` reports 36 passing tests.
- Service, tray, detections, and storage aren't started yet.
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

## Running the spike

The exe's manifest requests admin, so launching it triggers UAC. From an **elevated** terminal:

```powershell
dotnet build NetworkWatch.slnx
.\src\NetworkWatch.Spike\bin\Debug\net10.0-windows\NetworkWatch.Spike.exe --dns --log spike.log --duration 120
```

Flags: `--all` includes LAN/loopback traffic, `--dns` prints each lookup, `--log <file>` mirrors output to a file, and `--duration <s>` auto-stops. The summary's **"Public outbound w/ domain %"** is the key number. Yellow lines are public connections with no DNS lookup seen.

## Next steps

1. **Run the spike elevated and validate the data.** Things to check:
   - Do the DNS-Client 3008 events arrive and map IPs to domains? The target is >80% for public outbound.
   - Is `saddr`/`daddr` correct for inbound accepts?
   - Are process names and paths resolved, including for short-lived processes?
   - Is IPv6 handled?
   - Are browsers using their own DNS-over-HTTPS (bypassing DNS-Client), which would show up as lots of yellow lines?
   - Is the volume of UDP events acceptable?
2. Fix whatever the spike reveals. Then start Phase 1 (PLAN.md §7):
   - `NetworkWatch.Service` (Worker Service + `UseWindowsService`)
   - SQLite storage
   - threat-intel feeds
   - detections #1–8
   - the named-pipe API
   - the tray client
