// nwctl — command-line client for the Network Watch service. Run "nwctl help" for commands.

using System.Text.Json;
using NetworkWatch.Core;
using NetworkWatch.Core.Api;
using NetworkWatch.Core.Storage;

var json = args.Contains("--json");
var positional = args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
if (positional.Count == 0 || positional[0] is "help" or "-h" or "/?")
{
    PrintHelp();
    return 0;
}

string? Option(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
int? IntOption(string name) => int.TryParse(Option(name), out var v) ? v : null;
long? Arg(int index) => positional.Count > index && long.TryParse(positional[index], out var v) ? v : null;
string? StrArg(int index) => positional.Count > index ? positional[index] : null;

var command = positional[0];
// --path/--app/--search/--min/--limit values are not commands' positional args
foreach (var opt in new[] { "--path", "--app", "--search", "--min", "--limit", "--hours" })
    if (Option(opt) is { } value) positional.Remove(value);

try
{
    if (command == "watch")
    {
        Console.WriteLine("Watching for new alerts (Ctrl+C to stop)...");
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        await foreach (var alert in NetworkWatchClient.SubscribeAsync(TimeSpan.FromSeconds(5), cts.Token))
            PrintAlertLine(alert);
        return 0;
    }

    var request = command switch
    {
        "status" => new ApiRequest { Cmd = ApiCommands.Status },
        "alerts" => new ApiRequest { Cmd = ApiCommands.Alerts, Limit = IntOption("--limit") ?? 30, MinSeverity = ParseSeverity(Option("--min")) },
        "alert" => new ApiRequest { Cmd = ApiCommands.Alert, AlertId = Arg(1) },
        "ack" when StrArg(1) == "all" => new ApiRequest { Cmd = ApiCommands.AckAll },
        "ack" => new ApiRequest { Cmd = ApiCommands.Ack, AlertId = Arg(1) },
        "connections" => new ApiRequest { Cmd = ApiCommands.Connections, Limit = IntOption("--limit") ?? 40, Search = Option("--search") },
        "apps" => new ApiRequest { Cmd = ApiCommands.Apps },
        "trust" => new ApiRequest { Cmd = ApiCommands.Trust, AlertId = Arg(1), AppKey = Option("--app") },
        "untrust" => new ApiRequest { Cmd = ApiCommands.Untrust, AppKey = StrArg(1) },
        "block" => new ApiRequest { Cmd = ApiCommands.Block, AlertId = Arg(1), ProcessPath = Option("--path") },
        "unblock" => new ApiRequest { Cmd = ApiCommands.Unblock, ProcessPath = StrArg(1) },
        "blocks" => new ApiRequest { Cmd = ApiCommands.Blocks },
        "end-learning" => new ApiRequest { Cmd = ApiCommands.EndLearning },
        "restart-learning" => new ApiRequest { Cmd = ApiCommands.RestartLearning },
        "refresh-feeds" => new ApiRequest { Cmd = ApiCommands.RefreshFeeds },
        "indicators" when StrArg(1) == "add" => new ApiRequest { Cmd = ApiCommands.AddIndicator, Value = StrArg(2) },
        "indicators" when StrArg(1) == "remove" => new ApiRequest { Cmd = ApiCommands.RemoveIndicator, Value = StrArg(2) },
        "indicators" => new ApiRequest { Cmd = ApiCommands.Indicators },
        "usage" => new ApiRequest { Cmd = ApiCommands.Usage, Hours = IntOption("--hours") ?? 24, Limit = IntOption("--limit") ?? 20 },
        "digest" => new ApiRequest { Cmd = ApiCommands.Digest, Hours = IntOption("--hours") ?? 24 },
        "virustotal" when StrArg(1) == "off" => new ApiRequest { Cmd = ApiCommands.SetVirusTotalKey, Value = null },
        "virustotal" when StrArg(1) is { Length: > 10 } key => new ApiRequest { Cmd = ApiCommands.SetVirusTotalKey, Value = key },
        _ => null,
    };
    if (request is null)
    {
        Console.Error.WriteLine($"Unknown command '{command}'. Run 'nwctl help'.");
        return 2;
    }

    await using var client = await NetworkWatchClient.ConnectAsync(TimeSpan.FromSeconds(5));
    if (command == "trust" && args.Contains("--detector") && request.AlertId is { } alertId)
    {
        // Trust only for the detector that raised this alert.
        var alert = await client.CallAsync<Alert>(new ApiRequest { Cmd = ApiCommands.Alert, AlertId = alertId });
        request = request with { DetectorId = alert?.DetectorId };
    }
    var data = await client.CallRawAsync(request);

    if (json || data is null)
    {
        Console.WriteLine(data is null ? "ok" : JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    switch (command)
    {
        case "status" or "end-learning" or "restart-learning" or "refresh-feeds" or "virustotal":
            PrintStatus(data.Value.Deserialize<StatusDto>(ApiJson.Options)!);
            break;
        case "alerts":
            var alerts = data.Value.Deserialize<List<Alert>>(ApiJson.Options)!;
            if (alerts.Count == 0) Console.WriteLine("No alerts.");
            foreach (var a in alerts) PrintAlertLine(a);
            break;
        case "alert":
            PrintAlert(data.Value.Deserialize<Alert>(ApiJson.Options)!);
            break;
        case "connections":
            foreach (var c in data.Value.Deserialize<List<ConnectionRecord>>(ApiJson.Options)!.AsEnumerable().Reverse())
                Console.WriteLine($"{c.Time:MM-dd HH:mm:ss}  {(c.Direction == "Outbound" ? "OUT" : "IN "),-3} {c.Protocol,-3}  {Trunc($"{c.ProcessName} ({c.Pid})", 28),-28}  {c.RemoteIp + ":" + c.RemotePort,-26} {Trunc(c.Domain ?? $"({c.Scope})", 34),-34} {Trunc(string.Join(", ", new[] { c.Country, c.Network }.Where(s => !string.IsNullOrEmpty(s))), 40)}{(c.Threat is null ? "" : $"  !! {c.Threat}")}");
            break;
        case "indicators":
            var indicators = data.Value.Deserialize<List<string>>(ApiJson.Options)!;
            Console.WriteLine(indicators.Count == 0 ? "Your custom blocklist is empty." : string.Join(Environment.NewLine, indicators));
            break;
        case "usage":
            Console.WriteLine($"{"Program",-32} {"Sent",10} {"Received",10}");
            foreach (var u in data.Value.Deserialize<List<AppUsage>>(ApiJson.Options)!)
                Console.WriteLine($"{Trunc(u.ProcessName, 32),-32} {Bytes(u.BytesSent),10} {Bytes(u.BytesReceived),10}");
            break;
        case "digest":
            var d = data.Value.Deserialize<DigestDto>(ApiJson.Options)!;
            Console.WriteLine($"Since {d.Since:g}: {d.Summary}");
            Console.WriteLine($"Connections recorded: {d.Connections:N0}. Blocked programs: {d.BlockedPrograms}. {(d.IsLearning ? $"Learning until {d.LearningEndsAt:g}." : "")}");
            foreach (var a in d.NotableAlerts) Console.WriteLine($"  {a}");
            if (d.IsLearning && d.NewPrograms.Count > 0)
                Console.WriteLine($"  {d.NewPrograms.Count} programs seen for the first time (normal while learning).");
            else
                foreach (var p in d.NewPrograms) Console.WriteLine($"  New program: {p.ProcessName} ({p.Signer ?? "unsigned/unknown"})");
            foreach (var t in d.TopTalkers) Console.WriteLine($"  Traffic: {t.ProcessName} sent {Bytes(t.BytesSent)}, received {Bytes(t.BytesReceived)}");
            break;
        case "apps":
            foreach (var a in data.Value.Deserialize<List<AppRecord>>(ApiJson.Options)!)
                Console.WriteLine($"{a.LastSeen:MM-dd HH:mm}  {(a.Trusted ? "trusted " : ""),-8} {Trunc(a.ProcessName, 28),-28} {Trunc(a.Signer ?? "-", 30),-30} {a.ProcessPath}");
            break;
        default:
            Console.WriteLine(JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
            break;
    }
    return 0;
}
catch (ApiException ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}
catch (TimeoutException)
{
    Console.Error.WriteLine("Couldn't reach the Network Watch service. Is it installed and running? (sc query NetworkWatch)");
    return 3;
}

static Severity? ParseSeverity(string? s) => Enum.TryParse<Severity>(s, ignoreCase: true, out var v) ? v : null;

static string Trunc(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

static string Bytes(long b) => UploadVolumeDetector.FormatBytes(b);

static void PrintStatus(StatusDto s)
{
    Console.WriteLine($"Network Watch {s.Version}, running since {s.StartedAt:g}");
    Console.WriteLine(s.IsLearning
        ? $"Learning what's normal until {s.LearningEndsAt:g} (baseline alerts are quiet until then)"
        : "Learning period complete: watching for anything unusual");
    Console.WriteLine($"Events: {s.EventsProcessed:N0}  connections: {s.ConnectionsSeen:N0}  flows stored: {s.FlowsStored:N0}  DNS answers: {s.DnsResolutions:N0}  remote sign-ins: {s.RemoteLogons:N0}");
    Console.WriteLine($"Last event: {s.LastEvent?.ToString("T") ?? "none yet"}  apps known: {s.AppsKnown}");
    Console.WriteLine($"Threat indicators loaded: {s.ThreatIndicators:N0}  (feeds refreshed {s.FeedsRefreshed?.ToString("g") ?? "never"})");
    Console.WriteLine($"Unacknowledged alerts: {s.UnacknowledgedHigh} high, {s.UnacknowledgedMedium} medium");
    Console.WriteLine($"VirusTotal lookups: {(s.VirusTotalEnabled ? "on (hashes only)" : "off (nwctl virustotal <api-key> to enable)")}");
    foreach (var e in s.CollectorErrors) Console.WriteLine($"Collector error: {e}");
}

static void PrintAlertLine(Alert a)
{
    Console.ForegroundColor = a.Severity switch { Severity.High => ConsoleColor.Red, Severity.Medium => ConsoleColor.Yellow, _ => ConsoleColor.Gray };
    Console.WriteLine($"#{a.Id,-5} {a.LastSeen:MM-dd HH:mm}  {a.Severity,-6} {(a.Count > 1 ? $"x{a.Count} " : "")}{a.Title}{(a.Status == AlertStatus.Acknowledged ? "  (ack)" : "")}");
    Console.ResetColor();
}

static void PrintAlert(Alert a)
{
    PrintAlertLine(a);
    Console.WriteLine($"  Detector:     {a.DetectorId}");
    if (a.ProcessPath is not null || a.ProcessName is not null) Console.WriteLine($"  Program:      {a.ProcessPath ?? a.ProcessName}");
    if (a.Remote is not null) Console.WriteLine($"  Remote:       {a.Remote}{(a.Domain is null ? "" : $" ({a.Domain})")}");
    Console.WriteLine($"  First/last:   {a.FirstSeen:g} / {a.LastSeen:g} ({a.Count}x)");
    Console.WriteLine();
    Console.WriteLine($"  What happened: {a.WhatHappened}");
    Console.WriteLine($"  Why it matters: {a.WhyItMatters}");
    Console.WriteLine($"  What to do: {a.WhatToDo}");
}

static void PrintHelp()
{
    Console.WriteLine("""
        nwctl — Network Watch command line

          status                              service health, learning period, counts
          alerts [--min high|medium|info] [--limit N]
          alert <id>                          full explanation of one alert
          ack <id>|all
          connections [--search text] [--limit N]
          apps
          trust <alertId> [--detector]        trust the alert's program
          trust --app <appKey>
          untrust <appKey>
          block <alertId> | --path <exe>      block a program in Windows Firewall
          unblock <exe>
          blocks
          usage [--hours N]                   data sent/received per program
          digest [--hours N]                  summary of the last day
          indicators [add|remove <ip|cidr|domain>]   your custom blocklist
          virustotal <api-key>|off             opt-in VirusTotal hash lookups for suspicious programs
          end-learning | restart-learning | refresh-feeds
          watch                               stream new alerts
          --json                              raw JSON output

        Changing commands (trust, block, learning) only work when nwctl runs from Program Files\NetworkWatch.
        """);
}
