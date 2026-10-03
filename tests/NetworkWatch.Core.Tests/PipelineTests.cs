using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Tests;

/// <summary>End-to-end detection scenarios through the real pipeline and a temporary SQLite database.</summary>
public sealed class PipelineTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);
    private const string Unsigned = @"C:\Users\me\AppData\Local\Temp\x7f.exe";
    private const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"nw-test-{Guid.NewGuid():N}.db");
    private readonly Database _db;
    private readonly Baseline _baseline;
    private readonly AlertManager _alerts;
    private readonly AlertStore _alertStore;
    private readonly NetworkPipeline _pipeline;
    private readonly CaptureSink _sink = new();
    private ThreatIntel _intel = ThreatIntel.Empty;
    private DateTimeOffset _now;

    public PipelineTests()
    {
        _db = new Database(_dbPath);
        _baseline = new Baseline(_db, T0, TimeSpan.FromDays(7));
        _alertStore = new AlertStore(_db);
        _alerts = new AlertManager(_alertStore, _baseline, NullLogger.Instance, T0);
        _alerts.AddSink(_sink);
        var signatures = new FakeSignatures
        {
            [Chrome] = new(SignatureStatus.Signed, "Google LLC"),
            [Unsigned] = new(SignatureStatus.Unsigned, null),
        };
        _pipeline = new NetworkPipeline(_baseline, _alerts, new ConnectionStore(_db), () => _intel, signatures,
            DefaultDetectors.Create(), NullLogger.Instance, T0);
        _now = T0;
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
            try { File.Delete(f); } catch (IOException) { }
    }

    private void AfterLearning() => _now = T0.AddDays(8);

    private void Connect(string name, string? path, string ip, int port = 443, Direction dir = Direction.Outbound,
        Protocol proto = Protocol.Tcp, int localPort = 50000, int pid = 1234)
    {
        _pipeline.Process(new ConnectionEvent(_now, pid, name, path, proto, dir,
            new IPEndPoint(IPAddress.Parse("192.168.1.10"), localPort), new IPEndPoint(IPAddress.Parse(ip), port), 0), _now);
        _now = _now.AddSeconds(6);
        _pipeline.Flush(_now);
    }

    private void Dns(string name, string ip, int pid = 1234, string? process = null)
    {
        _pipeline.Process(new DnsResolution(_now, pid, name, [IPAddress.Parse(ip)], process), _now);
    }

    [Fact]
    public void UnsignedProgramFromTempIsHighEvenDuringLearning()
    {
        Connect("x7f.exe", Unsigned, "93.184.216.34");

        var alert = Assert.Single(_sink.Alerts, a => a.DetectorId == "untrusted-program");
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Contains("not digitally signed", alert.WhatHappened);
    }

    [Fact]
    public void SignedBrowserProducesNoAlerts()
    {
        Dns("www.example.com", "93.184.216.34");
        Connect("chrome.exe", Chrome, "93.184.216.34");
        AfterLearning();
        Dns("www.example.org", "93.184.216.35");
        Connect("chrome.exe", Chrome, "93.184.216.35");

        Assert.Empty(_sink.Alerts);
    }

    [Fact]
    public void ThreatIntelMatchIsHighAndIgnoresTrust()
    {
        var b = new ThreatIntelBuilder();
        b.AddNetwork("203.0.113.66", new ThreatIndicator("threatfox-ip", ThreatCategory.Malware, "abuse.ch ThreatFox (AsyncRAT)"));
        _intel = b.Build();
        _baseline.Trust(AppKeys.For("chrome.exe", Chrome));

        Connect("chrome.exe", Chrome, "203.0.113.66");

        var alert = Assert.Single(_sink.Alerts);
        Assert.Equal("threat-intel", alert.DetectorId);
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Contains("AsyncRAT", alert.WhatHappened);
    }

    [Fact]
    public void MaliciousDomainLookupAlertsEvenWithoutConnection()
    {
        var b = new ThreatIntelBuilder();
        b.AddDomain("evil.example", new ThreatIndicator("urlhaus-hosts", ThreatCategory.Malware, "abuse.ch URLhaus"));
        _intel = b.Build();

        Dns("payload.evil.example", "0.0.0.0", process: "winword.exe");

        var alert = Assert.Single(_sink.Alerts);
        Assert.Equal(Severity.Medium, alert.Severity); // answered 0.0.0.0 = blocked by DNS filter
        Assert.Contains("DNS filter", alert.WhatHappened);
    }

    [Fact]
    public void DnsArrivingLateStillCorrelates()
    {
        // Connection first, DNS 2 s later (as observed with ETW), flush after the hold.
        _pipeline.Process(new ConnectionEvent(_now, 1, "curl.exe", null, Protocol.Tcp, Direction.Outbound,
            new IPEndPoint(IPAddress.Parse("192.168.1.10"), 50000), new IPEndPoint(IPAddress.Parse("140.82.113.4"), 443), 0), _now);
        _pipeline.Process(new DnsResolution(_now.AddSeconds(2), 1, "github.com", [IPAddress.Parse("140.82.113.4")]), _now.AddSeconds(2));
        _pipeline.Flush(_now.AddSeconds(6));

        var stored = Assert.Single(new ConnectionStore(_db).Recent(10));
        Assert.Equal("github.com", stored.Domain);
    }

    [Fact]
    public void LivingOffTheLandBinaryAlertsUnlessRoutineDomain()
    {
        Dns("www.windowsupdate.com", "13.107.4.50");
        Connect("certutil.exe", @"C:\Windows\System32\certutil.exe", "13.107.4.50");
        Assert.Empty(_sink.Alerts);

        Dns("paste.example", "198.51.100.20");
        Connect("certutil.exe", @"C:\Windows\System32\certutil.exe", "198.51.100.20");
        var alert = Assert.Single(_sink.Alerts);
        Assert.Equal(("lolbin", Severity.High), (alert.DetectorId, alert.Severity));

        Dns("api.example", "198.51.100.21");
        Connect("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "198.51.100.21");
        Assert.Equal(Severity.Medium, _sink.Alerts[^1].Severity);
    }

    [Fact]
    public void DirectIpIsLearnedDuringLearningAndFlaggedAfter()
    {
        _now = T0.AddMinutes(20); // past warm-up, still learning
        Connect("qbittorrent.exe", @"C:\Program Files\qBittorrent\qbittorrent.exe", "151.242.104.187");
        AfterLearning();
        Connect("qbittorrent.exe", @"C:\Program Files\qBittorrent\qbittorrent.exe", "151.242.104.188");
        Assert.DoesNotContain(_sink.Alerts, a => a.DetectorId == "direct-ip");

        Connect("updater.exe", @"C:\Program Files\Vendor\updater.exe", "151.242.104.189");
        var alert = Assert.Single(_sink.Alerts, a => a.DetectorId == "direct-ip");
        Assert.Equal(Severity.Medium, alert.Severity); // signature unknown → not trusted
    }

    [Fact]
    public void RepeatedAlertsAreMergedNotRenotified()
    {
        Connect("x7f.exe", Unsigned, "93.184.216.34");
        _now = _now.AddMinutes(5);
        Connect("x7f.exe", Unsigned, "93.184.216.99");

        Assert.Single(_sink.Alerts, a => a.DetectorId == "untrusted-program");
        var stored = Assert.Single(_alertStore.Query(10), a => a.DetectorId == "untrusted-program");
        Assert.Equal(2, stored.Count);
    }

    [Fact]
    public void TrustSilencesBehavioralDetectors()
    {
        _baseline.Trust(AppKeys.For("x7f.exe", Unsigned));
        Connect("x7f.exe", Unsigned, "93.184.216.34");
        Assert.Empty(_sink.Alerts);
    }

    [Fact]
    public void RemoteAccessToolAlertsHigh()
    {
        Dns("relay.anydesk.com", "195.181.174.10");
        Connect("AnyDesk.exe", @"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "195.181.174.10");

        var alert = Assert.Single(_sink.Alerts, a => a.DetectorId == "remote-access");
        Assert.Equal(Severity.High, alert.Severity);
    }

    [Fact]
    public void EnvironmentChangesAreLearnedThenAlerted()
    {
        void Observe(string kind, string subject, string value) =>
            _pipeline.Process(new EnvironmentObservation(_now, kind, subject, value), _now);

        Observe(EnvironmentKinds.HostsFile, @"C:\Windows\System32\drivers\etc\hosts", "127.0.0.1 localhost");
        Observe(EnvironmentKinds.HostsFile, @"C:\Windows\System32\drivers\etc\hosts", "127.0.0.1 localhost");
        Assert.Empty(_sink.Alerts);

        Observe(EnvironmentKinds.HostsFile, @"C:\Windows\System32\drivers\etc\hosts", "127.0.0.1 localhost\n6.6.6.6 www.mybank.com");
        var alert = Assert.Single(_sink.Alerts);
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Contains("6.6.6.6 www.mybank.com", alert.WhatHappened);
    }

    [Fact]
    public void NewListenerAfterLearningAlertsOnce()
    {
        var sshd = new Listener(Protocol.Tcp, new IPEndPoint(IPAddress.Any, 445), 4, "System", null);
        _pipeline.Process(new ListenerSnapshot(_now, [sshd]), _now);
        AfterLearning();
        var backdoor = new Listener(Protocol.Tcp, new IPEndPoint(IPAddress.Any, 4444), 99, "svc.exe", @"C:\ProgramData\svc.exe");
        var local = new Listener(Protocol.Tcp, new IPEndPoint(IPAddress.Loopback, 5000), 98, "dev.exe", null);
        _pipeline.Process(new ListenerSnapshot(_now, [sshd, backdoor, local]), _now);
        _pipeline.Process(new ListenerSnapshot(_now, [sshd, backdoor, local]), _now);

        var alert = Assert.Single(_sink.Alerts);
        Assert.Contains("4444", alert.WhatHappened);
    }

    [Fact]
    public void BeaconIsDetectedForRegularIntervalsOnly()
    {
        var regular = Enumerable.Range(0, 10).Select(i => T0.AddSeconds(60 * i + (i % 2 == 0 ? 1 : -1))).ToList();
        Assert.True(BeaconDetector.IsBeacon(regular, out var mean));
        Assert.InRange(mean.TotalSeconds, 55, 65);

        var random = new Random(7);
        var irregular = Enumerable.Range(0, 10).Select(i => T0.AddSeconds(i * 60 + random.Next(-50, 50))).ToList();
        Assert.False(BeaconDetector.IsBeacon(irregular, out _));

        var tooShort = Enumerable.Range(0, 10).Select(i => T0.AddSeconds(i * 11)).ToList();
        Assert.False(BeaconDetector.IsBeacon(tooShort, out _)); // spans < 5 minutes
    }

    private sealed class CaptureSink : IAlertSink
    {
        public List<Alert> Alerts { get; } = [];
        public void Publish(Alert alert) => Alerts.Add(alert);
    }

    private sealed class FakeSignatures : Dictionary<string, SignatureInfo>, ISignatureVerifier
    {
        public SignatureInfo Verify(string? path) => path is not null && TryGetValue(path, out var s) ? s : SignatureInfo.Unknown;
    }
}
