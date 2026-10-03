// Phase 0 spike: print live "process → domain → IP:port" and measure data quality.
//
// Usage (elevated): NetworkWatch.Spike [--all] [--dns] [--log <file>] [--duration <seconds>]
//   --all       also show loopback/LAN/multicast traffic (default: public addresses only)
//   --dns       also print each DNS resolution as it happens
//   --log       also append every printed line (and the summary) to a file
//   --duration  stop automatically after N seconds

using System.Threading.Channels;
using NetworkWatch.Collectors.Windows;
using NetworkWatch.Core;

var showAll = args.Contains("--all");
var showDns = args.Contains("--dns");
var logPath = OptionValue("--log");
using var log = logPath is not null ? new StreamWriter(logPath, append: true) { AutoFlush = true } : null;

if (!EtwNetworkCollector.IsElevated)
{
    Console.Error.WriteLine("This needs administrator rights (ETW kernel tracing). Re-run from an elevated terminal.");
    return 1;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
if (int.TryParse(OptionValue("--duration"), out var seconds))
    cts.CancelAfter(TimeSpan.FromSeconds(seconds));

var channel = Channel.CreateUnbounded<NetEvent>(new UnboundedChannelOptions { SingleReader = true });
var collector = new EtwNetworkCollector();
var dnsMap = new DnsCorrelator();
var flows = new FlowTracker(TimeSpan.FromMinutes(2));
var stats = new Stats();

Console.WriteLine($"network-watch spike — collecting via {collector.Name}. Ctrl+C to stop and print a summary.");
Console.WriteLine(showAll ? "Showing all traffic." : "Showing public-internet traffic only (--all for everything).");
Console.WriteLine();

var collecting = collector.RunAsync(channel.Writer, cts.Token)
    .ContinueWith(t => { if (t.Exception is not null) Write(ConsoleColor.Red, $"Collector failed: {t.Exception.GetBaseException()}"); channel.Writer.TryComplete(); });

// DNS events come from a separate ETW session and can arrive after the connection they
// explain (measured: up to ~3s late vs ~0-2s for kernel events), so connections wait
// briefly before being matched. Ticks flush the buffer when idle.
var pending = new ReorderBuffer<(ConnectionEvent Conn, AddressScope Scope)>(TimeSpan.FromSeconds(5));
_ = Task.Run(async () =>
{
    using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
    try
    {
        while (await timer.WaitForNextTickAsync(cts.Token))
            channel.Writer.TryWrite(new Tick(DateTimeOffset.Now));
    }
    catch (OperationCanceledException) { }
});

var lastPrune = DateTimeOffset.Now;
try
{
    await foreach (var ev in channel.Reader.ReadAllAsync(cts.Token))
    {
        switch (ev)
        {
            case DnsResolution dns:
                dnsMap.Record(dns);
                stats.DnsResolutions++;
                if (showDns)
                    Write(ConsoleColor.DarkGray, $"{dns.Time:HH:mm:ss}  DNS          pid {dns.Pid,-6} {dns.QueryName} → {string.Join(", ", dns.Addresses)}  (delivered +{(DateTimeOffset.Now - dns.Time).TotalSeconds:F1}s)");
                break;

            case ConnectionEvent c:
                var scope = IpClassifier.Classify(c.Remote.Address);
                if (showAll || scope == AddressScope.Public)
                    if (flows.IsNew(c))
                        pending.Add((c, scope), DateTimeOffset.Now);

                break;
        }

        foreach (var (c, scope) in pending.DrainReady(DateTimeOffset.Now))
            PrintConnection(c, scope);

        if (DateTimeOffset.Now - lastPrune > TimeSpan.FromMinutes(1))
        {
            lastPrune = DateTimeOffset.Now;
            flows.Prune(lastPrune);
            dnsMap.Prune(lastPrune - TimeSpan.FromHours(6));
        }
    }
}
catch (OperationCanceledException) { }

await collecting;
// Drain whatever arrived after cancellation (including late DNS answers) before flushing.
while (channel.Reader.TryRead(out var late))
    if (late is DnsResolution dns) { dnsMap.Record(dns); stats.DnsResolutions++; }
foreach (var (c, scope) in pending.DrainAll())
    PrintConnection(c, scope);
stats.Print(dnsMap, line => Write(ConsoleColor.White, line));
return 0;

void PrintConnection(ConnectionEvent c, AddressScope scope)
{
    var domain = dnsMap.Lookup(c.Remote.Address);
    stats.Count(c, scope, domain is not null);

    var arrow = c.Direction == Direction.Outbound ? "→" : "←";
    var dir = c.Direction == Direction.Outbound ? "OUT" : "IN ";
    var name = domain?.Name ?? (scope == AddressScope.Public ? "(no DNS lookup seen)" : $"({scope})");
    var color = c.Direction == Direction.Inbound && c.Protocol == Protocol.Tcp ? ConsoleColor.Magenta
              : domain is null && scope == AddressScope.Public ? ConsoleColor.Yellow
              : ConsoleColor.Gray;
    Write(color, $"{c.Time:HH:mm:ss}  {dir} {c.Protocol.ToString().ToUpperInvariant(),-4} {Trunc($"{c.ProcessName} ({c.Pid})", 32),-32} {arrow} {c.Remote,-40} {name}");
}

void Write(ConsoleColor color, string line)
{
    Console.ForegroundColor = color;
    Console.WriteLine(line);
    Console.ResetColor();
    log?.WriteLine(line);
}

string? OptionValue(string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static string Trunc(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

/// <summary>Wakes the reader loop so held connections are flushed even when traffic is idle.</summary>
sealed record Tick(DateTimeOffset At) : NetEvent(At, 0);

sealed class Stats
{
    public int DnsResolutions;
    private int _publicOutbound, _publicOutboundWithDns, _inboundTcp, _flows;
    private readonly Dictionary<string, int> _byProcess = [];

    public void Count(ConnectionEvent c, AddressScope scope, bool hasDns)
    {
        _flows++;
        _byProcess[c.ProcessName] = _byProcess.GetValueOrDefault(c.ProcessName) + 1;
        if (c.Direction == Direction.Inbound && c.Protocol == Protocol.Tcp) _inboundTcp++;
        if (c.Direction == Direction.Outbound && scope == AddressScope.Public)
        {
            _publicOutbound++;
            if (hasDns) _publicOutboundWithDns++;
        }
    }

    public void Print(DnsCorrelator dns, Action<string> write)
    {
        write("");
        write("── Summary ─────────────────────────────────────────");
        write($"Flows shown:               {_flows}");
        write($"DNS resolutions seen:      {DnsResolutions} ({dns.Count} IPs mapped)");
        write($"Inbound TCP accepts:       {_inboundTcp}");
        var pct = _publicOutbound == 0 ? 0 : 100.0 * _publicOutboundWithDns / _publicOutbound;
        write($"Public outbound w/ domain: {_publicOutboundWithDns}/{_publicOutbound} ({pct:F0}%)  ← key data-quality metric");
        write("Top processes:");
        foreach (var (name, count) in _byProcess.OrderByDescending(p => p.Value).Take(10))
            write($"  {count,5}  {name}");
    }
}
