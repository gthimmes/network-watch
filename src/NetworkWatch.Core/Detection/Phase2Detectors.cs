namespace NetworkWatch.Core;

/// <summary>A traffic sample after app identification and signature check.</summary>
public sealed record EnrichedTraffic(TrafficSample Sample, string AppKey, SignatureInfo Signature);

/// <summary>
/// #11: DNS abuse.
/// DGA: malware generating many random domain names to find its controller produces bursts of
/// failed lookups (NXDOMAIN) for random-looking names.
/// Tunneling: data smuggled out inside DNS queries shows up as many unique, long subdomains of one domain.
/// </summary>
public sealed class DnsAbuseDetector : Detector
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    internal const int DgaThreshold = 12;
    internal const int TunnelUniqueThreshold = 60;
    private const double TunnelMinAverageLength = 20;

    private readonly Dictionary<string, List<(DateTimeOffset Time, string Name)>> _failures = [];
    private readonly Dictionary<(string Process, string Parent), Dictionary<string, DateTimeOffset>> _subdomains = [];

    public override string Id => "dns-abuse";

    public override IEnumerable<Alert> OnDns(DnsResolution d, DetectionContext ctx)
    {
        var name = d.QueryName.TrimEnd('.').ToLowerInvariant();
        if (!name.Contains('.') || name.EndsWith(".local", StringComparison.Ordinal) || name.EndsWith(".arpa", StringComparison.Ordinal))
            yield break; // single-label names (browser intranet probes), mDNS, reverse lookups
        var process = d.ProcessName ?? $"PID {d.Pid}";
        var (registrable, subdomain) = SplitDomain(name);

        // DGA: failed lookups of random-looking registrable domains.
        if (d.NameNotFound && IsRandomLooking(registrable.Split('.')[0]))
        {
            if (!_failures.TryGetValue(process, out var list)) _failures[process] = list = [];
            list.RemoveAll(f => ctx.Now - f.Time > Window);
            if (!list.Any(f => f.Name == registrable)) list.Add((ctx.Now, registrable));
            if (list.Count >= DgaThreshold)
            {
                var examples = string.Join(", ", list.TakeLast(5).Select(f => f.Name));
                yield return new Alert
                {
                    DetectorId = Id,
                    Severity = Severity.High,
                    DedupKey = $"dga:{process.ToLowerInvariant()}",
                    Title = $"{process} is trying many random-looking domains",
                    WhatHappened = $"{process} (PID {d.Pid}) looked up {list.Count} different random-looking domains in the last {Window.TotalMinutes:0} minutes and none of them exist. Examples: {examples}.",
                    WhyItMatters = "Some malware generates hundreds of random domain names a day (a \"domain generation algorithm\") and tries them until it finds the one its operators registered. Normal software doesn't do this.",
                    WhatToDo = $"Unless {process} is a security or network-testing tool you run, block it and run a Microsoft Defender full scan.",
                    ProcessName = d.ProcessName,
                    ProcessPath = d.ProcessPath,
                    Pid = d.Pid,
                    Domain = registrable,
                    FirstSeen = ctx.Now,
                    LastSeen = ctx.Now,
                };
            }
        }

        // Tunneling: many unique long subdomains under one parent from one process.
        if (subdomain.Length >= 12)
        {
            var key = (process, registrable);
            if (!_subdomains.TryGetValue(key, out var seen)) _subdomains[key] = seen = [];
            seen[subdomain] = ctx.Now;
            if (seen.Count >= TunnelUniqueThreshold)
            {
                foreach (var (sub, time) in seen)
                    if (ctx.Now - time > Window) seen.Remove(sub);
                if (seen.Count >= TunnelUniqueThreshold && seen.Keys.Average(s => s.Length) >= TunnelMinAverageLength)
                    yield return new Alert
                    {
                        DetectorId = Id,
                        Severity = Severity.High,
                        DedupKey = $"dns-tunnel:{process.ToLowerInvariant()}:{registrable}",
                        Title = $"{process} may be sending data hidden in DNS lookups",
                        WhatHappened = $"{process} (PID {d.Pid}) made {seen.Count} lookups of unique, long names under {registrable} in the last {Window.TotalMinutes:0} minutes, for example {Truncate(name, 120)}.",
                        WhyItMatters = "Encoding data into DNS names (\"DNS tunneling\") lets malware sneak data out or receive commands even through strict firewalls. Some antivirus and reputation services also use long DNS lookups legitimately.",
                        WhatToDo = $"If you don't recognize {registrable} as a security product you use, block {process} and investigate.",
                        ProcessName = d.ProcessName,
                        ProcessPath = d.ProcessPath,
                        Pid = d.Pid,
                        Domain = registrable,
                        FirstSeen = ctx.Now,
                        LastSeen = ctx.Now,
                    };
            }
        }
    }

    public override void OnTick(DetectionContext ctx)
    {
        foreach (var (process, list) in _failures)
        {
            list.RemoveAll(f => ctx.Now - f.Time > Window);
            if (list.Count == 0) _failures.Remove(process);
        }
        foreach (var (key, seen) in _subdomains)
        {
            foreach (var (sub, time) in seen)
                if (ctx.Now - time > Window) seen.Remove(sub);
            if (seen.Count == 0) _subdomains.Remove(key);
        }
    }

    private static readonly HashSet<string> SecondLevelSuffixes = ["co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go"];

    /// <summary>Splits "a.b.example.co.uk" into ("example.co.uk", "a.b"). Approximate public-suffix handling.</summary>
    internal static (string Registrable, string Subdomain) SplitDomain(string name)
    {
        var labels = name.Split('.');
        var take = labels.Length >= 3 && labels[^1].Length == 2 && SecondLevelSuffixes.Contains(labels[^2]) ? 3 : 2;
        take = Math.Min(take, labels.Length);
        return (string.Join('.', labels[^take..]), string.Join('.', labels[..^take]));
    }

    /// <summary>Heuristic for machine-generated labels: long, high character entropy, few vowels or long consonant runs.</summary>
    internal static bool IsRandomLooking(string label)
    {
        if (label.Length < 10 || label.Contains('-')) return false;
        var entropy = label.GroupBy(c => c).Sum(g => { var p = (double)g.Count() / label.Length; return -p * Math.Log2(p); });
        var vowels = label.Count(c => "aeiou".Contains(c)) / (double)label.Length;
        var digits = label.Count(char.IsDigit) / (double)label.Length;
        int run = 0, maxRun = 0;
        foreach (var c in label)
        {
            run = char.IsLetter(c) && !"aeiouy".Contains(c) ? run + 1 : 0;
            maxRun = Math.Max(maxRun, run);
        }
        // Entropy alone doesn't separate words from noise ("stackoverflow" scores 3.55); vowel ratio and consonant runs do.
        return entropy >= 2.5 && (vowels < 0.25 || maxRun >= 5 || digits is > 0.2 and < 0.8);
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

/// <summary>#12: outbound TCP to ports strongly associated with malware, IRC botnets, Tor or remote control.</summary>
public sealed class SuspiciousPortDetector : Detector
{
    internal static readonly IReadOnlyDictionary<int, string> Ports = new Dictionary<int, string>
    {
        [4444] = "the default port of Metasploit/Meterpreter reverse shells",
        [1337] = "a port popular with hacking tools and backdoors",
        [31337] = "a classic backdoor port (\"eleet\")",
        [5555] = "a port used by Android debug bridges and several remote-access trojans",
        [6666] = "an IRC port; IRC is used by old-school botnets for command-and-control",
        [6667] = "the standard IRC port; IRC is used by old-school botnets for command-and-control",
        [6668] = "an IRC port; IRC is used by old-school botnets for command-and-control",
        [6669] = "an IRC port; IRC is used by old-school botnets for command-and-control",
        [9001] = "the default Tor relay port",
        [9030] = "the default Tor directory port",
        [9050] = "the default Tor SOCKS proxy port",
        [9150] = "the Tor Browser SOCKS proxy port",
        [1080] = "the SOCKS proxy port, used to tunnel traffic through another machine",
        [23] = "Telnet, an unencrypted remote-login protocol (also used by IoT botnets)",
        [2323] = "an alternate Telnet port targeted by IoT botnets",
        [3389] = "Remote Desktop (RDP) — this computer is controlling another computer on the internet",
        [5900] = "VNC remote control — this computer is controlling another computer on the internet",
    };

    public override string Id => "suspicious-port";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Conn.Protocol != Protocol.Tcp || c.Conn.Direction != Direction.Outbound || c.Scope != AddressScope.Public)
            yield break;
        if (c.Threat is not null || !Ports.TryGetValue(c.Conn.Remote.Port, out var meaning)) yield break;

        var key = $"port:{c.AppKey}|{c.Conn.Remote.Port}";
        // Learn which apps legitimately use these ports (e.g. a BitTorrent client talking to trackers on 1337).
        if (!ctx.Baseline.AddListener(key, ctx.Now) || ctx.IsLearning) yield break;

        var severity = c.Signature.IsSigned ? Severity.Medium : Severity.High;
        yield return ForConnection(c, ctx, severity, key,
            $"{c.Conn.ProcessName} connected out on suspicious port {c.Conn.Remote.Port}",
            $"{Describe(c)}, {SignerText(c.Signature)}, connected to {c.DestinationWithPort}.",
            $"Port {c.Conn.Remote.Port} is {meaning}. Ordinary apps rarely use it.",
            $"If you know why {c.Conn.ProcessName} uses this port (gaming, BitTorrent, remote administration you do), choose Trust. Otherwise block it.");
    }
}

/// <summary>#10: a program uploads far more than it normally does (possible data theft).</summary>
public sealed class UploadVolumeDetector : Detector
{
    internal const long MinimumThreshold = 250L * 1024 * 1024;
    internal const int Multiplier = 5;

    private readonly Dictionary<string, (long Hour, long Sent, Dictionary<string, long> ByRemote)> _current = [];

    public override string Id => "upload-volume";

    public override IEnumerable<Alert> OnTraffic(EnrichedTraffic t, DetectionContext ctx)
    {
        if (t.Sample.BytesSent <= 0 || !IpClassifier.IsPublic(t.Sample.Remote)) yield break;
        var hour = Storage.UsageStore.HourOf(t.Sample.Time);
        if (!_current.TryGetValue(t.AppKey, out var state) || state.Hour != hour)
            state = (hour, 0, []);
        var remote = t.Sample.Remote.ToString();
        state.ByRemote[remote] = state.ByRemote.GetValueOrDefault(remote) + t.Sample.BytesSent;
        state = (hour, state.Sent + t.Sample.BytesSent, state.ByRemote);
        _current[t.AppKey] = state;

        if (ctx.IsLearning)
        {
            ctx.Baseline.RecordHourlyUpload(t.AppKey, t.Sample.ProcessName, t.Sample.ProcessPath, state.Sent, ctx.Now);
            yield break;
        }

        var learned = ctx.Baseline.MaxHourlyUpload(t.AppKey);
        var threshold = Math.Max(MinimumThreshold, learned * Multiplier);
        if (state.Sent < threshold) yield break;

        var top = state.ByRemote.OrderByDescending(kv => kv.Value).First();
        var severity = t.Signature.IsSigned ? Severity.Medium : Severity.High;
        yield return new Alert
        {
            DetectorId = Id,
            Severity = severity,
            DedupKey = $"upload:{t.AppKey}:{t.Sample.Time:yyyy-MM-dd}",
            Title = $"{t.Sample.ProcessName} is uploading an unusual amount of data",
            WhatHappened = $"{t.Sample.ProcessName} (PID {t.Sample.Pid}{(t.Sample.ProcessPath is null ? "" : $", {t.Sample.ProcessPath}")}), {SignerText(t.Signature)}, " +
                $"has uploaded {FormatBytes(state.Sent)} this hour; its usual maximum is {FormatBytes(learned)}. Most went to {top.Key} ({FormatBytes(top.Value)}).",
            WhyItMatters = "Stealing files means uploading them. A program suddenly sending far more than usual can be exfiltrating data — or simply backing up, syncing or sharing something big you started.",
            WhatToDo = $"If you're not uploading, syncing or sharing something large with {t.Sample.ProcessName} right now, block it and investigate.",
            ProcessName = t.Sample.ProcessName,
            ProcessPath = t.Sample.ProcessPath,
            Pid = t.Sample.Pid,
            Remote = top.Key,
            FirstSeen = ctx.Now,
            LastSeen = ctx.Now,
        };
    }

    public override void OnTick(DetectionContext ctx)
    {
        var hour = Storage.UsageStore.HourOf(ctx.Now);
        foreach (var (app, state) in _current)
            if (state.Hour < hour - 1) _current.Remove(app);
    }

    public static string FormatBytes(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / 1024.0:0} KB",
        _ => $"{bytes} bytes",
    };
}
