# network-watch

A local, private network monitor for Windows. A background service watches every inbound and outbound connection, ties each one to the program that made it (including the domain it looked up), and alerts you only when something looks genuinely suspicious: known-malware servers, untrusted programs going online, beaconing, new exposed ports, remote-access sessions, DNS/proxy tampering, and more.

- **Status:** early development (Phase 0 spike). See [PLAN.md](PLAN.md) for the product plan and roadmap, and [CLAUDE.md](CLAUDE.md) for current status and contributor notes.
- **Platform:** Windows 10/11 first. The core engine is OS-independent, so Linux, macOS, and headless servers can come later.

## Build

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```powershell
dotnet build
```

ETW-based collection needs administrator rights. Run the spike from an elevated terminal. The service runs as LocalSystem.
