# network-watch — context for Claude / contributors

Local network-monitoring tool: a Windows service watches every connection (per process, with DNS names), runs detections, and a tray app shows alerts. **Read [PLAN.md](PLAN.md) first.** It holds the product reasoning, the detection list, the architecture, and the decisions made so far.

## Current status

- **Phase 0 spike: working and validated on live traffic** (2026-10-03).
  - `src/NetworkWatch.Spike` prints live `process → domain → IP:port` and a data-quality summary.
  - `NetworkWatch.Core` has `DnsCorrelator`, `FlowTracker`, `IpClassifier`, `ReorderBuffer`, and `ICollector`. These are portable and unit-tested.
  - `NetworkWatch.Collectors.Windows` has `EtwNetworkCollector`: a kernel TCP/IP + process session plus a `Microsoft-Windows-DNS-Client` session, using TraceEvent 3.2.8.
  - `dotnet test` reports 39 passing tests.
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
- ETW kernel network/process sessions **require admin**. The service runs as LocalSystem. Elevated dev runs go through the dev task (below).

## Setting up on a new machine

```powershell
winget install --id Microsoft.DotNet.SDK.10 --exact
git clone https://github.com/gthimmes/network-watch.git
cd network-watch
dotnet build NetworkWatch.slnx
.\scripts\dev\register-dev-tasks.ps1   # one-time UAC prompt; enables prompt-free elevated runs
```

## Elevated dev runs without UAC (for Claude and humans)

`scripts/dev/register-dev-tasks.ps1` (run once, with one UAC prompt) registers the scheduled task `\NetworkWatch\NetworkWatch-Dev-Spike`. The task runs as the owner with highest privileges and only while they're logged on. After that, **no prompt is needed**:

```powershell
.\scripts\dev\spike.ps1 -Duration 60 -Dns        # builds, runs spike elevated, prints .dev\spike.log
```

- `spike.ps1` builds as the normal user, writes a validated request to `.dev\spike-request.json`, starts the task, and waits for `.dev\spike.status`.
- `run-spike.ps1` is what the task executes. It only runs the already-built spike exe, with duration clamped to 5–600 s.
- To generate traffic during a run, start `spike.ps1` in the background and make requests (e.g. `curl.exe`) meanwhile.
- **Security tradeoff (accepted by the owner):** anything running as the owner can rebuild the exe the task runs elevated. Remove the task with `scripts\dev\unregister-dev-tasks.ps1`.
- The task stores an absolute repo path. Re-run the register script if the repo moves. Each machine needs its own registration.
- Plan: add a similar `NetworkWatch-Dev-Service` task (install/restart the service from the latest build) when Phase 1 starts.

Spike flags (when run directly from an elevated terminal): `--all` includes LAN/loopback traffic, `--dns` prints each lookup with its delivery latency, `--log <file>` mirrors output, and `--duration <s>` auto-stops.

## Spike findings (2026-10-03)

- **DNS events arrive late.** DNS-Client events are delivered up to ~3 s after the event, versus ~0–2 s for kernel connection events. That's because they come from separate ETW sessions with independent buffering. Connections therefore pass through a 5 s `ReorderBuffer` before DNS correlation. Without it, the correlation rate was 0%. Keep this in the service pipeline.
- **Correlation works.** Every `curl` request to github/example/wikipedia/reddit/nuget mapped to its domain, including short-lived processes (the process name was resolved correctly).
- **Legitimate traffic with no DNS lookup is common.** On the owner's machine this comes from qBittorrent (P2P DHT/trackers by IP) and the WireGuard/Windscribe VPN endpoint. Detection #4 ("direct-to-IP") needs per-app baselining or allowances for P2P/VPN apps, or it will be noisy.
- The owner runs the **Windscribe VPN**, which sinkholes some domains to `0.0.0.0` (e.g. `mobile.events.data.microsoft.com`). DNS answers of `0.0.0.0` are a usable signal ("blocked by DNS filter").
- **Not yet validated:**
  - inbound TCP accepts (none observed, so `saddr`/`daddr` orientation for accepts is unconfirmed)
  - browser traffic and DNS-over-HTTPS (no browser was active)
  - IPv6 connections
  - UDP event volume over long runs

## Gotchas

- Windows PowerShell 5.1 `Get-Content`/`Set-Content` default to the ANSI codepage. They will mangle the UTF-8 in these docs (em dashes, arrows, box-drawing). Use `-Encoding utf8` or edit files with a proper editor. Keep `.ps1` files ASCII-only.
- `dotnet test` only builds test projects and their dependencies, not the Spike. Use `dotnet build NetworkWatch.slnx` to catch Spike compile errors.

## Next steps

1. Finish the open validation items above. Use a browser with secure DNS on and off, and add a local listener to check inbound accepts.
2. Start Phase 1 (PLAN.md §7):
   - `NetworkWatch.Service` (Worker Service + `UseWindowsService`) with the Core pipeline (reorder buffer → DNS correlation → flow tracking)
   - an install script plus a `NetworkWatch-Dev-Service` dev task
   - SQLite storage
   - threat-intel feeds
   - detections #1–8
   - the named-pipe API
   - the tray client
