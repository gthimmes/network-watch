# network-watch — context for Claude / contributors

Local network-monitoring tool: a Windows service watches every connection (per process, with DNS names), runs detections, and a tray app shows alerts. **Read [PLAN.md](PLAN.md) first.** It holds the product reasoning, the detection list, the architecture, and the decisions made so far.

## Current status (2026-10-03)

**Phase 1 MVP is functional and installed on the owner's machine.** The service is running and has been verified on live traffic.

| Area | State |
|---|---|
| Windows service (`NetworkWatch`, LocalSystem, auto-start, restart-on-failure) | Running |
| Collectors: ETW connections + DNS (with command line and parent process), TCP listeners, network config | Verified live |
| Threat intel: ThreatFox IP/domain, URLhaus, Feodo, Spamhaus DROP v4/v6, Tor exits, custom list (~8.9k indicators) | Verified live |
| Detections #1 threat intel (DNS lookup and connection merge into one alert) | Verified live |
| #2 untrusted program (unsigned + Temp/Downloads/AppData…) | Verified live |
| #3 living-off-the-land binaries (+ High if parent is Office/browser/PDF) | Verified live (powershell); certutil is blocked by policy on this PC |
| #4 direct-to-IP | Unit tests; live check pending |
| #5 beaconing | Verified live (fires on the 9th regular connection, 5-min span) |
| #6 exposure (new listener) | Verified live |
| #6 exposure (inbound from internet), #7 remote-access tools, #8 network tampering | Unit tests only |
| #9 new app (Info) | Verified live |
| Firewall block/unblock (rules grouped "NetworkWatch") | Verified live |
| Trusted-client gate for mutating API commands | Verified live |
| Local API (named pipe) + `nwctl` CLI | Working |
| Tray app (icon states, toasts with Block/Trust/Details, dashboard) | Built; first deploy in progress |

Tests: `dotnet test NetworkWatch.slnx` → 65 passing.

**Owner context:** personal use on the owner's own Windows 11 machine. Other OSes and headless servers come later, so keep the core portable (rules below). The owner runs the Windscribe VPN (WireGuard) and qBittorrent, which shape what "normal" looks like.

## Layout

```
src/NetworkWatch.Core                portable engine (net10.0): events, pipeline, detectors, intel, SQLite storage, API handler + client
src/NetworkWatch.Collectors.Windows  ETW, listener table, environment, Authenticode/catalog verifier, firewall enforcer, process resolver
src/NetworkWatch.Service             Windows service host: Engine (composition), workers, pipe server, file logger
src/NetworkWatch.Cli                 nwctl: CLI client (also the future headless/server UI)
src/NetworkWatch.Tray                WinForms tray + toasts + dashboard (net10.0-windows10.0.19041.0)
src/NetworkWatch.Spike               Phase 0 console (kept for ad-hoc ETW debugging)
tools/NetworkWatch.TrafficGen        nwtraffic: benign test traffic (get / beacon / rawip / listen). Unsigned on purpose.
tests/…                              Core tests (pipeline scenarios on real SQLite) + Windows real-OS tests (no admin needed)
scripts/dev                          elevated dev harness (see below)
```

## Architecture rules (don't break these)

1. **`NetworkWatch.Core` targets plain `net10.0`** and must not reference Windows APIs, ETW, the registry, WinForms, or `System.Management`. Models, flow aggregation, DNS↔IP correlation, detections, and SQLite storage live here.
2. **OS-specific code lives only in `NetworkWatch.Collectors.<OS>`**, including `IEnforcer` and `ISignatureVerifier` implementations. Collectors produce normalized events through `ICollector`.
3. **The service is the product, and the tray and `nwctl` are just clients.** The service must run headless. Clients talk to it over the local API (`\\.\pipe\NetworkWatch`, newline-delimited JSON, see `Core/Api`). Alerts go out through `IAlertSink`s.
4. **Avoid alert fatigue.**
   - Only High severity produces a toast; Medium turns the tray yellow; Info is timeline-only.
   - New detections need a severity tier and a plain-English explanation (what happened / why it matters / what to do).
   - Alerts dedup on `DedupKey` for 24 h, incrementing the count instead.
   - Baseline-dependent detectors stay quiet during the 7-day learning period.
5. **Everything stays local.** No telemetry. Any outbound lookup (VirusTotal, AbuseIPDB) is opt-in.
6. **Mutating API commands** (trust, untrust, block, unblock, end/restart learning) are only accepted from executables under `%ProgramFiles%\NetworkWatch` (admin-writable only). Malware running as the user must not be able to trust or unblock itself.

## Runtime locations

- Program files: `%ProgramFiles%\NetworkWatch\{service,cli,tray}`
- Data: `%ProgramData%\NetworkWatch\`
  - `networkwatch.db` (SQLite, WAL)
  - `logs\service-yyyyMMdd.log`
  - `feeds\` (cached feeds)
  - `custom-indicators.txt` (one IP, CIDR or domain per line; run `nwctl refresh-feeds` after editing)
- Logs and the DB are readable without admin. Use `nwctl` from Program Files for anything that changes state.

## Elevated dev runs without UAC (for Claude and humans)

`scripts/dev/register-dev-tasks.ps1` (run once, one UAC prompt) registers two scheduled tasks under `\NetworkWatch\`. Both run as the owner with highest privileges, only while the owner is logged on. Both are registered on the owner's main machine.

- **`NetworkWatch-Dev-Service`:** `.\scripts\dev\service.ps1 [-Op install|restart|stop|uninstall] [-NoTray]`
  - `install` publishes service, cli and tray to `artifacts\install\`.
  - It then mirrors that folder to `%ProgramFiles%\NetworkWatch`, creates or starts the service, and relaunches the tray.
- **`NetworkWatch-Dev-Spike`:** `.\scripts\dev\spike.ps1 -Duration 60 -Dns` runs the Phase 0 ETW console elevated.

**Security tradeoff (accepted by the owner):** anything running as the owner can rebuild what these tasks run elevated. Remove them with `scripts\dev\unregister-dev-tasks.ps1`. The tasks store absolute repo paths, so re-register if the repo moves. Each machine needs its own registration.

## Live testing recipe

```powershell
$nw = "$env:ProgramFiles\NetworkWatch\cli\nwctl.exe"
dotnet publish tools\NetworkWatch.TrafficGen -c Release -o $env:TEMP\nwtest
& $env:TEMP\nwtest\nwtraffic.exe get https://example.com     # → High "untrusted program" (unsigned, in Temp)
& $nw end-learning                                           # enables baseline detectors (#4, #6, #9)
& $env:TEMP\nwtest\nwtraffic.exe listen 47123 45             # → Medium "started accepting connections"
& $env:TEMP\nwtest\nwtraffic.exe beacon https://example.com/ 40 10   # → beacon alert after ~5 min
& $env:TEMP\nwtest\nwtraffic.exe rawip 1.1.1.1 443           # → direct-ip (only >10 min after service start)
& $nw alerts; & $nw alert <id>
& $nw restart-learning                                       # IMPORTANT: restore the owner's 7-day learning afterwards
```

## Findings so far

- **DNS events arrive late.** DNS-Client events arrive up to ~3 s after the connection. The pipeline holds connections for 5 s (`ReorderBuffer`).
- **Exited processes must stay cached.** Short-lived processes exit before their DNS event is processed, so `ProcessResolver` keeps exited processes for 60 s.
- **Many Windows binaries are catalog-signed.** In-box binaries (cmd, ping…) have no embedded signature. `WindowsSignatureVerifier` falls back to the catalog database. `curl.exe` and `dotnet.exe` are embedded-signed. The signer shown is the certificate's O= field.
- **Legitimate direct-to-IP traffic exists on the owner's PC.** qBittorrent (P2P) and the Windscribe VPN endpoint connect straight to IPs. The direct-IP detector learns these during the learning period.
- **The VPN sinkholes some domains.** Windscribe answers `0.0.0.0` for some domains. A malicious-domain lookup answered with 0.0.0.0 is downgraded to Medium ("your DNS filter blocked it").
- **`certutil.exe` is blocked from running** on this PC (Defender ASR / policy).

## Gotchas

- Windows PowerShell 5.1 `Get-Content`/`Set-Content` default to the ANSI codepage and mangle UTF-8. Use `-Encoding utf8` or the Edit tool. Keep `.ps1` files ASCII-only.
- `dotnet test` only builds test projects and their deps. Use `dotnet build NetworkWatch.slnx` to catch errors elsewhere.
- Shells opened before the SDK install don't have `dotnet` on PATH. The dev scripts add `%ProgramFiles%\dotnet` themselves.
- Redeploying restarts the service and loses in-memory detector state (beacon history, DNS map, warm-up timer).

## Known gaps / next steps

1. Live-verify direct-IP and beaconing. Exercise the tray toasts and buttons.
2. Hardening:
   - `%ProgramData%\NetworkWatch` inherits "Users: create files". The service should set a restrictive ACL on its data dir (custom list editing then moves to an API command).
   - The service binary is framework-dependent; consider self-contained publishing for distribution.
3. Phase 2 (PLAN.md §7):
   - upload-volume anomaly
   - DNS-abuse heuristics (DGA/tunneling)
   - suspicious ports
   - daily digest
   - GeoIP/ASN enrichment (DB-IP lite, CC BY)
   - VirusTotal/AbuseIPDB opt-in
   - a real installer (MSI/MSIX) for non-dev installs
4. Server story: `nwctl` already works headless. A Linux collector (eBPF or `/proc` + `ss`) would implement `ICollector`, plus a Unix-socket transport for the API.
