using NetworkWatch.Core.Intel;

namespace NetworkWatch.Core;

/// <summary>#1: connection to, or DNS lookup of, a known-bad IP/network/domain.</summary>
public sealed class ThreatIntelDetector : Detector
{
    public override string Id => "threat-intel";
    public override bool RespectsTrust => false;

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Threat is not { } t || c.Scope != AddressScope.Public) yield break;

        var inbound = c.Conn.Direction == Direction.Inbound;
        var key = $"ti:{c.AppKey}:{c.Conn.Remote.Address}";

        if (t.Category == ThreatCategory.Tor)
        {
            if (inbound && c.Conn.Protocol == Protocol.Tcp)
                yield return ForConnection(c, ctx, Severity.Medium, key,
                    $"Connection from the Tor network into {c.Conn.ProcessName}",
                    $"{Describe(c)} accepted a connection from {c.Conn.Remote}, which is a Tor exit relay, on local port {c.Conn.Local.Port}.",
                    "Tor hides who is really connecting. Unexpected inbound connections from Tor are often scanning or attack attempts against exposed services.",
                    "If you don't run a server that should be reachable from the internet, close the port or block the program in the firewall.");
            else
                yield return ForConnection(c, ctx, Severity.Info, key,
                    $"{c.Conn.ProcessName} talked to a Tor exit relay",
                    $"{Describe(c)} exchanged traffic with {c.Conn.Remote}, a Tor exit relay.",
                    "Usually harmless (Tor Browser, or a relay operator's other services), but malware sometimes uses Tor to hide its controllers.",
                    "If you don't use Tor, check what this program is.");
            yield break;
        }

        // When the match came from the domain (not the IP), the DNS lookup already raised an alert
        // for the same program+domain; share its key so the connection merges into it.
        if (c.Domain is not null && ctx.Intel.Lookup(c.Conn.Remote.Address) is null)
            key = DnsKey(c.Conn.ProcessName, t.Value ?? c.Domain);

        var severity = t.Compromised ? Severity.Medium : Severity.High;
        var direction = inbound ? "received a connection from" : "connected to";
        yield return ForConnection(c, ctx, severity, key,
            t.Category == ThreatCategory.BadNetwork
                ? $"{c.Conn.ProcessName} {direction} a criminal network"
                : $"{c.Conn.ProcessName} {direction} a known malicious server",
            $"{Describe(c)} {direction} {c.DestinationWithPort}. That address is listed by {t.Description}." +
                (t.Compromised ? " The listing says it is a legitimate site that has been hacked." : ""),
            t.Category switch
            {
                ThreatCategory.Malware => "Security researchers have seen malware use this server for command-and-control or to deliver payloads. A connection from your computer can mean the program is infected or is being used to download something malicious.",
                ThreatCategory.BadNetwork => "Spamhaus lists this whole network as run by criminals (hijacked or 'bulletproof' hosting). Legitimate software almost never needs to talk to it.",
                _ => "This address is on your own custom blocklist.",
            },
            $"Unless you know exactly why {c.Conn.ProcessName} did this: block it, run a full Microsoft Defender scan (Windows Security → Virus & threat protection → Scan options → Full scan), and consider an offline scan.");
    }

    public override IEnumerable<Alert> OnDns(DnsResolution d, DetectionContext ctx)
    {
        if (ctx.Intel.LookupDomain(d.QueryName) is not { } t || t.Category == ThreatCategory.Tor) yield break;

        var name = d.ProcessName ?? $"PID {d.Pid}";
        var blocked = d.Addresses.Count > 0 && d.Addresses.All(a => IpClassifier.Classify(a) is AddressScope.Unspecified or AddressScope.Loopback);
        yield return new Alert
        {
            DetectorId = Id,
            Severity = t.Compromised || blocked ? Severity.Medium : Severity.High,
            DedupKey = DnsKey(name, t.Value ?? d.QueryName),
            Title = $"{name} looked up a known malicious domain",
            WhatHappened = $"{name} (PID {d.Pid}) asked DNS for {d.QueryName}, which is listed by {t.Description}." +
                (blocked ? " Your DNS filter answered with a blocked address, so the connection probably did not happen." : ""),
            WhyItMatters = "Looking up a malware domain usually means something on this computer is trying to reach it: an infected program, a malicious document or script, or a compromised web page.",
            WhatToDo = $"Check what {name} was doing at that moment. If it isn't a browser visiting a page you chose, run a full Microsoft Defender scan.",
            ProcessName = d.ProcessName,
            ProcessPath = d.ProcessPath,
            Pid = d.Pid,
            Domain = d.QueryName,
            FirstSeen = ctx.Now,
            LastSeen = ctx.Now,
        };
    }

    private static string DnsKey(string processName, string domain) =>
        $"ti-dns:{processName.ToLowerInvariant()}:{domain.TrimEnd('.').ToLowerInvariant()}";
}

/// <summary>#2: unsigned / invalidly signed program, especially from Temp/Downloads/AppData, using the internet.</summary>
public sealed class UntrustedProgramDetector : Detector
{
    public override string Id => "untrusted-program";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Scope != AddressScope.Public) yield break;

        var suspiciousPlace = KnownLists.IsSuspiciousLocation(c.Conn.ProcessPath);
        Severity severity;
        string why;
        switch (c.Signature.Status)
        {
            case SignatureStatus.Invalid:
                severity = Severity.High;
                why = "Its digital signature is broken, which happens when a signed file has been modified after signing — a classic sign of tampering — or when it was signed with a revoked or untrusted certificate.";
                break;
            case SignatureStatus.Unsigned when suspiciousPlace:
                severity = Severity.High;
                why = "It isn't digitally signed and runs from a folder (Temp, Downloads, AppData, ProgramData...) where malware is usually dropped. Legitimate installed software normally lives in Program Files and is signed.";
                break;
            case SignatureStatus.Unsigned when c.IsNewApp && !ctx.IsLearning:
                severity = Severity.Medium;
                why = "It isn't digitally signed, so there's no way to confirm who made it, and it has never used the network on this computer before.";
                break;
            default:
                yield break;
        }

        yield return ForConnection(c, ctx, severity, $"untrusted:{c.AppKey}",
            $"Untrusted program {c.Conn.ProcessName} is using the internet",
            $"{Describe(c)}, which is {SignerText(c.Signature)}, connected to {c.DestinationWithPort}.",
            why,
            "If you didn't just download or build this program yourself, block it, then delete it and run a Microsoft Defender scan. If you trust it, choose Trust.");
    }
}

/// <summary>#3: built-in Windows tools commonly abused by attackers reaching out to the internet.</summary>
public sealed class LivingOffTheLandDetector : Detector
{
    public override string Id => "lolbin";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Conn.Direction != Direction.Outbound || c.Scope != AddressScope.Public) yield break;
        var file = KnownLists.FileName(c.Conn.ProcessName, c.Conn.ProcessPath);
        if (!KnownLists.LivingOffTheLand.TryGetValue(file, out var highSuspicion)) yield break;
        if (KnownLists.IsRoutineDomain(c.Domain)) yield break;

        var suspiciousParent = c.Conn.ParentProcessName is { } parent && KnownLists.SuspiciousParents.Contains(parent);
        var severity = highSuspicion || suspiciousParent ? Severity.High : Severity.Medium;
        var commandLine = c.Conn.CommandLine is { Length: > 0 } cmd ? $" Command line: {Truncate(cmd, 400)}" : "";
        yield return ForConnection(c, ctx, severity, $"lolbin:{file}:{c.Destination}",
            $"{c.Conn.ProcessName} reached out to {c.Destination}",
            $"{Describe(c)} connected to {c.DestinationWithPort}{(c.Domain is null ? " (no DNS name)" : "")}.{commandLine}",
            $"{file} is a built-in Windows tool that attackers abuse to download and run malicious code without dropping obvious malware files (\"living off the land\"). " +
                (suspiciousParent ? $"It was started by {c.Conn.ParentProcessName}, which is exactly how malicious documents, emails and web exploits launch their payloads. "
                 : highSuspicion ? "It rarely needs to contact internet servers in normal use. "
                 : "It's also used legitimately by scripts and admins, so check whether you or an installer were running something. "),
            "If you weren't running a script or installer just now, block it and run a Microsoft Defender full scan. If a document or email was open, close it and don't enable macros or editing.");
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}

/// <summary>#4: connection straight to a public IP without a DNS lookup, from an app that doesn't normally do that.</summary>
public sealed class DirectIpDetector : Detector
{
    public override string Id => "direct-ip";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Conn.Direction != Direction.Outbound || c.Conn.Protocol != Protocol.Tcp) yield break;
        if (c.Scope != AddressScope.Public || c.Domain is not null || c.Threat is not null) yield break;
        if (ctx.IsWarmingUp) yield break;

        if (ctx.IsLearning)
        {
            ctx.Baseline.MarkDirectIpOk(c.AppKey);
            yield break;
        }
        if (ctx.Baseline.IsDirectIpOk(c.AppKey)) yield break;

        var severity = c.Signature.IsSigned ? Severity.Info : Severity.Medium;
        yield return ForConnection(c, ctx, severity, $"direct-ip:{c.AppKey}",
            $"{c.Conn.ProcessName} connected to a raw IP address",
            $"{Describe(c)}, {SignerText(c.Signature)}, connected to {c.Conn.Remote} without looking up a domain name first. It hasn't done this before.",
            "Normal apps almost always look up a name (like example.com) before connecting. Malware often has its server's IP address hard-coded so it doesn't depend on DNS. P2P apps, games and VPNs also do this legitimately.",
            $"If {c.Conn.ProcessName} is a P2P, gaming or VPN app, choose Trust. Otherwise, check what it is before letting it continue.");
    }
}

/// <summary>#5: regular, low-jitter repeated connections to the same destination ("beaconing").</summary>
public sealed class BeaconDetector : Detector
{
    private const int MinConnections = 8;
    private const int MaxHistory = 24;
    private static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaxInterval = TimeSpan.FromHours(2);
    private static readonly TimeSpan MinSpan = TimeSpan.FromMinutes(5);
    private const double MaxJitter = 0.15; // coefficient of variation of the intervals

    private readonly Dictionary<string, List<DateTimeOffset>> _history = [];

    public override string Id => "beacon";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (c.Conn.Protocol != Protocol.Tcp || c.Conn.Direction != Direction.Outbound || c.Scope != AddressScope.Public) yield break;

        var key = $"{c.AppKey}|{c.Destination}";
        if (!_history.TryGetValue(key, out var times))
            _history[key] = times = [];
        times.Add(c.Conn.Time);
        if (times.Count > MaxHistory) times.RemoveAt(0);
        if (!IsBeacon(times, out var mean)) yield break;

        var severity = c.Signature.Status switch
        {
            SignatureStatus.Signed => Severity.Info,
            SignatureStatus.Unsigned or SignatureStatus.Invalid => Severity.High,
            _ => Severity.Medium,
        };
        yield return ForConnection(c, ctx, severity, $"beacon:{key}",
            $"{c.Conn.ProcessName} is checking in with {c.Destination} on a timer",
            $"{Describe(c)}, {SignerText(c.Signature)}, has connected to {c.DestinationWithPort} {times.Count} times at a steady interval of about {FormatInterval(mean)}.",
            "Malware 'beacons' to its controller on a regular schedule to ask for instructions. Many legitimate apps also poll on a timer (update checks, sync, telemetry), so this matters most for programs you don't recognize.",
            $"If you recognize {c.Conn.ProcessName} and {c.Destination}, choose Trust. If not, look the program up and consider blocking it.");
    }

    public override void OnTick(DetectionContext ctx)
    {
        foreach (var (key, times) in _history)
            if (ctx.Now - times[^1] > MaxInterval * 2)
                _history.Remove(key);
    }

    internal static bool IsBeacon(IReadOnlyList<DateTimeOffset> times, out TimeSpan mean)
    {
        mean = default;
        if (times.Count < MinConnections || times[^1] - times[0] < MinSpan) return false;

        var intervals = new double[times.Count - 1];
        for (var i = 1; i < times.Count; i++)
            intervals[i - 1] = (times[i] - times[i - 1]).TotalSeconds;
        var avg = intervals.Average();
        if (avg < MinInterval.TotalSeconds || avg > MaxInterval.TotalSeconds) return false;
        var stddev = Math.Sqrt(intervals.Sum(x => (x - avg) * (x - avg)) / intervals.Length);
        mean = TimeSpan.FromSeconds(avg);
        return stddev / avg <= MaxJitter;
    }

    private static string FormatInterval(TimeSpan t) =>
        t.TotalMinutes >= 1 ? $"{t.TotalMinutes:0.#} minutes" : $"{t.TotalSeconds:0} seconds";
}

/// <summary>#6: new program listening for network connections, and inbound connections from the internet.</summary>
public sealed class ExposureDetector : Detector
{
    public override string Id => "exposure";

    public override IEnumerable<Alert> OnListeners(ListenerSnapshot s, DetectionContext ctx)
    {
        foreach (var l in s.Listeners)
        {
            if (l.Protocol != Protocol.Tcp) continue;
            var scope = IpClassifier.Classify(l.Local.Address);
            if (scope is AddressScope.Loopback) continue;

            var appKey = Storage.AppKeys.For(l.ProcessName, l.ProcessPath);
            var key = $"listen:{appKey}|{PortKey(l.Local.Port)}";
            if (!ctx.Baseline.AddListener(key, ctx.Now) || ctx.IsLearning) continue;

            var everywhere = scope == AddressScope.Unspecified;
            yield return new Alert
            {
                DetectorId = Id,
                Severity = Severity.Medium,
                DedupKey = key,
                Title = $"{l.ProcessName} started accepting network connections",
                WhatHappened = $"{l.ProcessName} (PID {l.Pid}{(l.ProcessPath is null ? "" : $", {l.ProcessPath}")}) is now listening on TCP port {l.Local.Port}" +
                    (everywhere ? " on all network interfaces." : $" on {l.Local.Address}."),
                WhyItMatters = "A listening program can be reached by other devices on your network (and from the internet if your router or firewall forwards the port). Backdoors and remote-access trojans work this way; so do file sharing, games and development servers.",
                WhatToDo = "If you just started something that should accept connections, this is expected — choose Trust. Otherwise, block the program.",
                ProcessName = l.ProcessName,
                ProcessPath = l.ProcessPath,
                Pid = l.Pid,
                Remote = $"listening {l.Local}",
                FirstSeen = ctx.Now,
                LastSeen = ctx.Now,
            };
        }
    }

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Conn.Direction != Direction.Inbound || c.Conn.Protocol != Protocol.Tcp || c.Scope != AddressScope.Public)
            yield break;

        var key = $"inbound:{c.AppKey}|{PortKey(c.Conn.Local.Port)}";
        if (!ctx.Baseline.AddListener(key, ctx.Now) || ctx.IsLearning) yield break;

        yield return ForConnection(c, ctx, Severity.High, key,
            $"Someone on the internet connected into {c.Conn.ProcessName}",
            $"{Describe(c)} accepted a connection from {c.Conn.Remote} (a public internet address) on local port {c.Conn.Local.Port}. This hasn't happened before.",
            "Inbound connections from the internet mean this program is reachable from outside your network. That's expected for P2P apps or servers you run on purpose, but it's also how attackers get in.",
            "If you don't expect this program to be reachable from the internet, block it and check your router's port-forwarding (UPnP) settings.");
    }

    /// <summary>Ephemeral ports change every run; treat them as one bucket per app.</summary>
    private static string PortKey(int port) => port >= 49152 ? "ephemeral" : port.ToString();
}

/// <summary>#7: remote-access tool connecting out — the hallmark of tech-support scams.</summary>
public sealed class RemoteAccessDetector : Detector
{
    public override string Id => "remote-access";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewFlow || c.Scope != AddressScope.Public) yield break;
        var file = KnownLists.FileName(c.Conn.ProcessName, c.Conn.ProcessPath);
        if (!KnownLists.RemoteAccessTools.Contains(file)) yield break;

        yield return ForConnection(c, ctx, Severity.High, $"rat:{c.AppKey}",
            $"Remote-control software {c.Conn.ProcessName} is online",
            $"{Describe(c)} connected to {c.DestinationWithPort}. This program lets someone else see and control this computer.",
            "Remote-access tools are legitimate for IT support, but scammers (\"Microsoft/your bank/your antivirus support is calling\") use them to take over computers, steal money and install malware.",
            "If nobody you personally trust is helping you right now, disconnect from the internet, close/uninstall this program, and don't let anyone \"fix\" your computer remotely. If it's your own setup, choose Trust.");
    }
}

/// <summary>#8: changes to DNS servers, proxy settings, hosts file or the router's MAC address.</summary>
public sealed class EnvironmentTamperDetector : Detector
{
    public override string Id => "network-tamper";

    public override IEnumerable<Alert> OnEnvironment(EnvironmentObservation o, DetectionContext ctx)
    {
        var previous = ctx.Baseline.GetEnvironment(o.Kind, o.Subject);
        if (previous == o.Value) yield break;
        ctx.Baseline.SetEnvironment(o.Kind, o.Subject, o.Value, ctx.Now);
        if (previous is null) yield break; // first observation: just learn it

        var key = $"env:{o.Kind}:{o.Subject}:{StableHash(o.Value):x8}";
        switch (o.Kind)
        {
            case EnvironmentKinds.HostsFile:
            {
                var before = previous.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
                var after = o.Value.Split('\n', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
                var added = after.Except(before).Take(8).ToList();
                var removed = before.Except(after).Take(8).ToList();
                yield return General(ctx, Severity.High, key, "Your hosts file was changed",
                    $"The hosts file ({o.Subject}) changed." +
                        (added.Count > 0 ? $" Added: {string.Join("; ", added)}." : "") +
                        (removed.Count > 0 ? $" Removed: {string.Join("; ", removed)}." : ""),
                    "The hosts file overrides DNS. Malware edits it to send you to fake banking/login sites or to block antivirus updates. Ad-blockers and developer tools also edit it.",
                    "If you or a tool you trust didn't just edit it, open the file in Notepad (as administrator) and remove entries you don't recognize.");
                break;
            }
            case EnvironmentKinds.Proxy:
            {
                var enabled = o.Value.Contains("enabled=1", StringComparison.Ordinal) || o.Value.Contains("pac=http", StringComparison.OrdinalIgnoreCase);
                yield return General(ctx, enabled ? Severity.High : Severity.Info, key,
                    enabled ? "A web proxy was turned on" : "Web proxy settings changed",
                    $"Proxy settings for {o.Subject} changed from [{previous}] to [{o.Value}].",
                    "A proxy sees all your web traffic. Malware and adware set one to spy on or modify what you browse. Company VPNs and some security tools also set proxies.",
                    "If you didn't set this up, open Settings → Network & internet → Proxy and turn it off, then run a Defender scan.");
                break;
            }
            case EnvironmentKinds.DnsServers:
                yield return General(ctx, Severity.Medium, key, "Your DNS servers changed",
                    $"DNS servers for {o.Subject} changed from {previous} to {o.Value}.",
                    "DNS decides where every website name points. Malware (or a hacked router) changes DNS servers to silently redirect you to fake sites. VPNs also change DNS when they connect.",
                    "If you didn't just connect a VPN or change network settings, check the adapter's DNS settings and your router's admin page.");
                break;
            case EnvironmentKinds.GatewayMac:
                yield return General(ctx, Severity.High, key, "Your router's hardware address changed",
                    $"The gateway {o.Subject} now has MAC address {o.Value} (was {previous}).",
                    "On the same network, the router's hardware (MAC) address shouldn't change. If it does, another device may be impersonating the router to intercept your traffic (ARP spoofing), common on public Wi-Fi. A replaced router also causes this.",
                    "If you didn't replace your router, disconnect from this network, especially if it's public Wi-Fi, and use a trusted connection or VPN.");
                break;
        }
    }

    /// <summary>FNV-1a; string.GetHashCode is randomized per process, which would break dedup across restarts.</summary>
    private static uint StableHash(string s)
    {
        var hash = 2166136261u;
        foreach (var ch in s) hash = (hash ^ ch) * 16777619u;
        return hash;
    }
}

/// <summary>#9: a program used the network for the first time (after the learning period). Info only.</summary>
public sealed class NewAppDetector : Detector
{
    public override string Id => "new-app";

    public override IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx)
    {
        if (!c.IsNewApp || ctx.IsLearning || c.Scope != AddressScope.Public) yield break;
        yield return ForConnection(c, ctx, Severity.Info, $"new-app:{c.AppKey}",
            $"New program online: {c.Conn.ProcessName}",
            $"{Describe(c)}, {SignerText(c.Signature)}, used the internet for the first time (first destination: {c.DestinationWithPort}).",
            "New programs going online is normal after installs and updates. It's listed so you have a record of what started talking to the internet and when.",
            "Nothing, unless you don't recognize the program.");
    }
}

public static class DefaultDetectors
{
    public static IReadOnlyList<Detector> Create() =>
    [
        new ThreatIntelDetector(),
        new UntrustedProgramDetector(),
        new LivingOffTheLandDetector(),
        new DirectIpDetector(),
        new BeaconDetector(),
        new ExposureDetector(),
        new RemoteAccessDetector(),
        new EnvironmentTamperDetector(),
        new NewAppDetector(),
    ];
}
