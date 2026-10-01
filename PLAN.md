# network-watch — Product Plan

A local-only Windows tray app that watches every network connection on the machine, ties each one to the program that made it, and alerts only when something is actually worth your attention.

---

## 1. What already exists, and the gap

| Tool | What it does well | What's missing for us |
|---|---|---|
| **GlassWire** | Nice per-app traffic graphs, "first time app went online" alerts | Mostly shows bandwidth. Little threat detection. Paid. |
| **Little Snitch / Portmaster / simplewall** | Per-app allow/deny firewall | Prompt-heavy, so people end up clicking "allow" on everything. Doesn't explain *why* something is suspicious. |
| **Sysmon + SIEM / EDR (Defender, CrowdStrike)** | Very good detection | Built for SOC analysts. Defender is quiet about network behavior unless it's blocking known malware. |
| **Wireshark / TCPView** | Full visibility | No judgment. You have to know what you're looking at. |

**Our gap:** a "security-savvy friend" sitting on your network connection. It sees everything, stays quiet about normal traffic, and when it does speak up it tells you in plain English what happened, why it matters, and what to do about it.

## 2. Product principles

1. **Alert fatigue kills this kind of tool.** If it cries wolf you'll turn it off within a week. So:
   - Start with a **7-day learning period** that builds a baseline of which apps talk to which places.
   - Use **severity tiers**. Only *High* shows a toast. *Medium* goes into a daily digest. *Info* only goes on the timeline.
   - Make every alert actionable with one click: **Trust**, **Block**, **Snooze**, or **Details**.
2. **Every alert explains itself:** what happened, which program did it (path, signer, parent process), why it's flagged, how confident we are, and the recommended action.
3. **Local and private.** No cloud, no telemetry. Data lives in a local SQLite DB. Outbound lookups (e.g. VirusTotal) are opt-in and send only hashes or IPs.
4. **Light on resources:** under 1% CPU and under 100 MB RAM at steady state. No packet capture by default.
5. **Built to go cross-platform later.** The detection engine stays OS-independent, and only the data "collectors" are Windows-specific. Mac and Linux become new collectors, not a rewrite.

## 3. What it watches (data collection)

All of this is available on Windows **without a kernel driver or packet capture**, using built-in ETW (Event Tracing for Windows) providers:

| Signal | Source | Why it matters |
|---|---|---|
| TCP/UDP connections, with PID, remote IP and port, bytes sent and received | `Microsoft-Windows-Kernel-Network` / kernel NetworkTCPIP ETW | Tells us *who* talks to *where* and how much |
| DNS queries and answers, with PID | `Microsoft-Windows-DNS-Client` ETW | Gives domain names, and lets us match an IP back to the domain that was looked up |
| Listening ports and inbound connections | ETW plus `GetExtendedTcpTable` polling | Tells us what's exposed |
| Process details: path, SHA-256, Authenticode signer, parent, command line | Process ETW and WinVerifyTrust | Separates "signed Microsoft binary" from "unsigned exe in %TEMP%" |
| Network environment: DNS servers, proxy, hosts file, gateway MAC, Wi-Fi SSID | Registry, file watchers, `GetIpNetTable` | Catches hijacking and spoofing |

## 4. What it flags (detections)

The list is ordered by how strong a signal each one gives you compared with how much noise it makes. The MVP covers rows 1–9.

| # | Detection | Example | Default severity |
|---|---|---|---|
| 1 | **Threat-intel match**: the IP or domain is on a known-bad list | Connection to a Feodo/Emotet C2 server, a URLhaus malware host, or a Spamhaus DROP range | High |
| 2 | **Untrusted program goes online**: unsigned, or running from `%TEMP%`, `%APPDATA%`, `Downloads`, or `ProgramData` | `C:\Users\you\AppData\Local\Temp\x7f.exe` → 185.x.x.x:443 | High |
| 3 | **Living-off-the-land binaries reaching the internet** | `powershell`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wscript` connecting to non-Microsoft hosts | High |
| 4 | **Direct-to-IP connection with no prior DNS lookup** (excluding LAN and well-known CDNs) | Malware often hardcodes IPs. Normal apps almost always resolve names first. | Medium |
| 5 | **Beaconing**: regular, low-jitter callbacks to the same destination | Something phoning home every 60s ± 2s for hours | Medium → High |
| 6 | **New listener or inbound exposure** | New process listening on 0.0.0.0, inbound connections from public IPs, RDP or SMB reachable | High (public) / Medium |
| 7 | **Remote-access tool session** | AnyDesk, TeamViewer, ScreenConnect, or RustDesk connection starts. This is the #1 tech-support-scam signal. | High (if not trusted) |
| 8 | **Network tampering** | DNS server changed, system proxy set, hosts file edited, gateway MAC changed (ARP spoofing) | High |
| 9 | **First-seen behavior after baseline**: a known app suddenly contacts a new country or ASN, or a new app goes online | Info, rolled up into the daily digest | Info / Medium |
| 10 | **Unusual upload volume**: a process sends far more than its own baseline | 2 GB uploaded by something that normally sends KB | Medium (v2) |
| 11 | **DNS abuse**: DGA-looking random domains, very long or high-entropy subdomains (tunneling), apps skipping the system resolver (custom DoH or :53 to an unknown server) | `a8f3kq0z...example.top` | Medium (v2) |
| 12 | **Suspicious ports and protocols**: 4444, 1337, 6667 (IRC), Tor ports, connections to Tor relays | Medium (v2) |

**Free threat-intel feeds** (downloaded locally and refreshed every few hours): abuse.ch Feodo Tracker, URLhaus, ThreatFox, and SSLBL (some need a free auth key); Spamhaus DROP/EDROP; the Tor exit/relay list; and an optional custom blocklist.

**Optional enrichment** (opt-in, user supplies the key): VirusTotal file-hash lookup and AbuseIPDB IP reputation. GeoIP and ASN data come from a local MaxMind GeoLite2 or DB-IP database.

## 5. User experience

- **Tray icon** shows the current state: 🟢 all quiet / 🟡 items to review / 🔴 high-severity alert. Hovering shows a summary like "42 apps online, 0 alerts today."
- **Toast notification** (High severity only), for example: *"Unsigned program `x7f.exe` in your Temp folder connected to a known malware server in RU."* with buttons **[Block] [Details] [Trust]**.
- **Dashboard window** with four views:
  - **Now:** live list of apps and their connections, with domain, country, bytes, and signer.
  - **Alerts:** a triage queue with explanations.
  - **Timeline:** searchable history of "what talked to what, when."
  - **Apps:** per-app profile (every destination ever contacted, trust state).
- **Daily digest** (optional toast or window): "3 new apps went online, 1 new listening port, nothing suspicious."
- **Block** creates a Windows Firewall rule for that program or IP via the `INetFwPolicy2` API. Rules are tagged so we can list them and undo them. Cheap to build, and gives the user real control.

## 6. Architecture

```
┌──────────────────────────── Windows Service (LocalSystem) ───────────────────────────┐
│  Collectors (Windows-specific)          Engine (OS-independent)                       │
│  ├─ ETW: Kernel-Network ─┐              ├─ Correlator (PID→process, IP→DNS name)       │
│  ├─ ETW: DNS-Client ─────┼─► events ──► ├─ Enrichment (GeoIP/ASN, signer, threat intel)│
│  ├─ ETW: Process ────────┤              ├─ Baseline store                              │
│  └─ Env watchers ────────┘              ├─ Detection rules → Alerts                    │
│                                         └─ SQLite (connections, alerts, baseline)      │
└──────────────────────────────────────────────┬────────────────────────────────────────┘
                                               │ named pipe (local only, ACL'd)
                         ┌─────────────────────▼─────────────────────┐
                         │  Tray App (user session): icon, toasts,    │
                         │  dashboard, Trust/Block actions            │
                         └────────────────────────────────────────────┘
```

**Why a service plus a separate tray app:** kernel ETW sessions need admin rights. Running collection as a service means it starts at boot, sees everything, and never asks for UAC. The tray app runs without elevation in the user's session.

**Recommended stack: C# / .NET 10 (current LTS; .NET 8 support ends Nov 2026)**
- `Microsoft.Diagnostics.Tracing.TraceEvent` is the most mature ETW library available.
- WinForms `NotifyIcon` and Windows App SDK toasts are first-class.
- `Microsoft.Data.Sqlite` for storage.
- .NET runs on macOS and Linux, so the engine can be reused when we add those collectors (eBPF / Endpoint Security).
- Ships as a single self-contained `.exe` plus an MSI or MSIX installer.

**Alternatives considered:**
- **Rust:** smaller footprint, but ETW and tray tooling is rougher, and it's slower to build.
- **Python + psutil:** polling-only, so it misses short-lived connections, has no DNS-per-process, and is heavier to ship.
- **Electron UI:** memory hog for a tray app.

## 7. Roadmap

**Phase 0: spike (1–2 days).** A console app that prints live `process → domain → IP:port` using ETW. This proves the data quality before we build anything else.

**Phase 1: MVP (≈2–3 weeks).**
- Service and tray app, with SQLite storage
- Collectors for connections, DNS, processes, and listeners
- Threat-intel feed downloader and matcher
- Detections #1–8, plus the learning period and first-seen (#9)
- Toasts with Trust / Block / Details, tray states, and a basic dashboard (Now / Alerts / Apps)
- Firewall block and unblock

**Phase 2: smarter.**
- Beaconing tuning
- Upload-volume anomaly detection (#10)
- DNS-abuse heuristics (#11)
- Suspicious ports and Tor (#12)
- Daily digest
- Timeline search
- VirusTotal and AbuseIPDB opt-in lookups
- Rule configuration UI, export to CSV/JSON

**Phase 3: beyond one PC.**
- macOS and Linux collectors
- Optional LAN device discovery (who's on my Wi-Fi?)
- Optional "home hub" mode that aggregates several machines (still self-hosted)

## 8. Explicit non-goals (for now)

- **Full packet capture and TLS decryption.** Too invasive, too heavy, and needs a driver or Npcap.
- **Replacing antivirus or EDR.** We complement Defender. We don't scan files.
- **Prompt-on-every-connection firewall mode.** This trains users to click "allow" on everything.

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| False positives from updaters, browsers, and Microsoft telemetry | Learning period, a signer-based trust list (Microsoft, Google, etc.), per-app Trust button |
| ETW event volume from browsers | Aggregate in memory per (pid, remote, port) flow and write summaries, not individual packets |
| Malware kills or tampers with the service | Run as a protected service with restart on failure, and alert from the tray if the service goes silent |
| Threat-feed licensing | Use only free-for-personal-use feeds and show attribution in the About screen |

## 10. Decisions (2026-10-01)

1. **Audience:** personal use on my own machine for now. Keep the installer and onboarding minimal. A dev-friendly `install.ps1` is enough.
2. **Service:** yes. Collection and detection run in a Windows service, and the tray app is a thin client.
3. **Platforms:** Windows first. Other machine types later, **including headless servers**. That leads to these structural rules from day one:
   - **`NetworkWatch.Core`** (models, correlator, detections, storage) has **no Windows references**. It targets plain `net10.0`.
   - **`NetworkWatch.Collectors.Windows`** is the only project that touches ETW, Win32, or the registry. A future `Collectors.Linux` (eBPF / `/proc` + `ss` fallback) or `Collectors.MacOS` (Endpoint Security / NetworkExtension) plugs in through the same `ICollector` interface.
   - **The service is the product, and the tray is just one client.** The service exposes a local API that any client can use. A server install runs the service with no tray, and later gets a web UI or log/syslog/webhook alert sinks.
   - **Alert delivery uses pluggable `IAlertSink`s:** tray toast now, then file/JSON log, Windows Event Log, webhook, and syslog for servers.
4. **Block action:** still planned for the MVP, implemented behind the Windows-only `IEnforcer` interface so servers can use iptables/nftables later.

### Solution layout

```
src/
  NetworkWatch.Core/                 net10.0   — events, flow aggregation, DNS↔IP correlation, detections, SQLite
  NetworkWatch.Collectors.Windows/   net10.0-windows — ETW (TraceEvent), process info, signer, env watchers
  NetworkWatch.Service/              net10.0-windows — Worker Service host (UseWindowsService), local API
  NetworkWatch.Tray/                 net10.0-windows — NotifyIcon, toasts, dashboard
  NetworkWatch.Spike/                net10.0-windows — Phase 0 console: live process → domain → IP:port
tests/
  NetworkWatch.Core.Tests/
```

