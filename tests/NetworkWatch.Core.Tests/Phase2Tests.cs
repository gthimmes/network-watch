using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkWatch.Core.Api;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Tests;

public sealed class Phase2Tests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);
    private const string Unsigned = @"C:\Users\me\AppData\Local\Temp\x7f.exe";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"nw-p2-{Guid.NewGuid():N}");
    private readonly Database _db;
    private readonly Baseline _baseline;
    private readonly AlertStore _alertStore;
    private readonly UsageStore _usage;
    private readonly NetworkPipeline _pipeline;
    private readonly List<Alert> _alerts = [];
    private DateTimeOffset _now = T0;

    public Phase2Tests()
    {
        Directory.CreateDirectory(_dir);
        _db = new Database(Path.Combine(_dir, "test.db"));
        _baseline = new Baseline(_db, T0, TimeSpan.FromDays(7));
        _alertStore = new AlertStore(_db);
        _usage = new UsageStore(_db);
        var manager = new AlertManager(_alertStore, _baseline, NullLogger.Instance, T0);
        manager.AddSink(new Sink(_alerts));
        _pipeline = new NetworkPipeline(_baseline, manager, new ConnectionStore(_db), () => ThreatIntel.Empty, new Signatures(),
            DefaultDetectors.Create(), _log, T0, _usage,
            ip => new GeoInfo("DE", "Germany", 24940, "Hetzner Online GmbH"));
    }

    private readonly ErrorLog _log = new();

    public void Dispose()
    {
        Assert.Empty(_log.Errors); // detectors must never throw (the pipeline would swallow it)
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private void Dns(string name, bool notFound = false, string process = "evil.exe") =>
        _pipeline.Process(new DnsResolution(_now, 77, name, notFound ? [] : [IPAddress.Parse("198.51.100.1")], process, Unsigned, notFound), _now);

    private void Connect(string name, string? path, string ip, int port)
    {
        _pipeline.Process(new ConnectionEvent(_now, 50, name, path, Protocol.Tcp, Direction.Outbound,
            new IPEndPoint(IPAddress.Parse("192.168.1.2"), 50000), new IPEndPoint(IPAddress.Parse(ip), port), 0), _now);
        _now = _now.AddSeconds(6);
        _pipeline.Flush(_now);
    }

    private void Upload(string name, string? path, long bytes) =>
        _pipeline.Process(new TrafficSample(_now, 60, name, path, IPAddress.Parse("203.0.113.9"), bytes, 0), _now);

    [Theory]
    [InlineData("xkqzjvbnwpqtr", true)]
    [InlineData("a8f3kq0zr7m2", true)]
    [InlineData("microsoft", false)]
    [InlineData("googleapis", false)]
    [InlineData("stackoverflow", false)]
    [InlineData("short", false)]
    [InlineData("my-company-portal", false)]
    public void RandomLookingLabels(string label, bool expected) =>
        Assert.Equal(expected, DnsAbuseDetector.IsRandomLooking(label));

    [Theory]
    [InlineData("a.b.example.com", "example.com", "a.b")]
    [InlineData("www.bbc.co.uk", "bbc.co.uk", "www")]
    [InlineData("example.com", "example.com", "")]
    public void SplitsRegistrableDomain(string name, string registrable, string sub) =>
        Assert.Equal((registrable, sub), DnsAbuseDetector.SplitDomain(name));

    [Fact]
    public void BurstOfRandomNxdomainsIsDga()
    {
        var random = new Random(3);
        string Label() => new(Enumerable.Range(0, 14).Select(_ => "bcdfghjklmnpqrstvwxz0123456789"[random.Next(30)]).ToArray());
        for (var i = 0; i < DnsAbuseDetector.DgaThreshold - 1; i++) Dns($"{Label()}.com", notFound: true);
        Assert.Empty(_alerts);

        Dns($"{Label()}.net", notFound: true);
        var alert = Assert.Single(_alerts);
        Assert.Equal(("dns-abuse", Severity.High), (alert.DetectorId, alert.Severity));
    }

    [Fact]
    public void FailedLookupsOfNormalNamesAreNotDga()
    {
        foreach (var name in new[] { "printer", "wpad", "intranet.corp", "mail.contoso.com", "old-server.example.org" })
            for (var i = 0; i < 5; i++) Dns(name, notFound: true);
        Assert.Empty(_alerts);
    }

    [Fact]
    public void ManyLongUniqueSubdomainsIsTunneling()
    {
        for (var i = 0; i < DnsAbuseDetector.TunnelUniqueThreshold; i++)
            Dns($"{Convert.ToHexString(BitConverter.GetBytes(i * 7919L))}{i:x8}deadbeefcafe.exfil.example");
        Assert.Contains(_alerts, a => a.DedupKey.StartsWith("dns-tunnel:", StringComparison.Ordinal));
    }

    [Fact]
    public void SuspiciousPortIsLearnedThenAlerted()
    {
        Connect("qbittorrent.exe", @"C:\Program Files\qBittorrent\qbittorrent.exe", "93.158.213.92", 1337);
        _now = T0.AddDays(8);
        Connect("qbittorrent.exe", @"C:\Program Files\qBittorrent\qbittorrent.exe", "93.158.213.93", 1337);
        Assert.DoesNotContain(_alerts, a => a.DetectorId == "suspicious-port");

        Connect("x7f.exe", Unsigned, "203.0.113.50", 4444);
        var alert = Assert.Single(_alerts, a => a.DetectorId == "suspicious-port");
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Contains("Metasploit", alert.WhyItMatters);
        Assert.Contains("Germany, Hetzner Online GmbH", alert.WhatHappened); // GeoIP in the text
    }

    [Fact]
    public void UploadFarAboveLearnedMaximumAlerts()
    {
        const long mb = 1024 * 1024;
        // Learning: OneDrive normally uploads up to ~100 MB/hour.
        Upload("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", 100 * mb);
        _now = T0.AddDays(8);
        Upload("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", 400 * mb);
        Assert.Empty(_alerts); // under 5x the learned max

        Upload("OneDrive.exe", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", 200 * mb);
        var alert = Assert.Single(_alerts);
        Assert.Equal("upload-volume", alert.DetectorId);
        Assert.Contains("600.0 MB", alert.WhatHappened);
    }

    [Fact]
    public void UsageIsAggregatedPerApp()
    {
        Upload("a.exe", @"C:\a.exe", 1000);
        Upload("a.exe", @"C:\a.exe", 500);
        Upload("b.exe", @"C:\b.exe", 10);

        var totals = _usage.Totals(T0.AddHours(-1));
        Assert.Equal(1500, totals.Single(t => t.ProcessName == "a.exe").BytesSent);
        Assert.Equal("a.exe", totals[0].ProcessName);
    }

    [Fact]
    public async Task CustomIndicatorsAreManagedThroughTheApiAndOnlyByTrustedClients()
    {
        var feeds = new FeedManager(Path.Combine(_dir, "feeds"), Path.Combine(_dir, "custom.txt"), new HttpClient(),
            NullLogger<FeedManager>.Instance, feeds: []);
        var api = new ApiHandler(_alertStore, new ConnectionStore(_db), _usage, _baseline, feeds, null, () => null!);

        await Assert.ThrowsAsync<ApiException>(() => api.HandleAsync(new ApiRequest { Cmd = ApiCommands.AddIndicator, Value = "bad.example" }, false, default));
        await api.HandleAsync(new ApiRequest { Cmd = ApiCommands.AddIndicator, Value = "Bad.Example" }, true, default);
        await api.HandleAsync(new ApiRequest { Cmd = ApiCommands.AddIndicator, Value = "203.0.113.0/24" }, true, default);
        await Assert.ThrowsAsync<ApiException>(() => api.HandleAsync(new ApiRequest { Cmd = ApiCommands.AddIndicator, Value = "not a thing" }, true, default));

        Assert.NotNull(feeds.Current.LookupDomain("x.bad.example"));
        Assert.NotNull(feeds.Current.Lookup(IPAddress.Parse("203.0.113.77")));

        await api.HandleAsync(new ApiRequest { Cmd = ApiCommands.RemoveIndicator, Value = "bad.example" }, true, default);
        Assert.Null(feeds.Current.LookupDomain("bad.example"));
        Assert.Equal(["203.0.113.0/24"], feeds.CustomIndicators());
    }

    [Fact]
    public void DigestSummarizesTheDay()
    {
        Connect("x7f.exe", Unsigned, "93.184.216.34", 443); // untrusted program → High
        Upload("x7f.exe", Unsigned, 5000);
        var api = new ApiHandler(_alertStore, new ConnectionStore(_db), _usage, _baseline,
            new FeedManager(_dir, Path.Combine(_dir, "c.txt"), new HttpClient(), NullLogger<FeedManager>.Instance, []), null, () => null!);

        var learning = api.Digest(T0.AddHours(-1));
        Assert.Equal(1, learning.High);
        Assert.Single(learning.NewPrograms);
        Assert.StartsWith("1 high and 0 medium alert(s); busiest: x7f.exe", learning.Summary); // new programs aren't news while learning

        _baseline.EndLearning(DateTimeOffset.Now);
        Assert.StartsWith("1 high and 0 medium alert(s); 1 new program(s) went online; busiest: x7f.exe", api.Digest(T0.AddHours(-1)).Summary);
    }

    private sealed class ErrorLog : Microsoft.Extensions.Logging.ILogger
    {
        public List<string> Errors { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel level) => true;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel level, Microsoft.Extensions.Logging.EventId id, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (level >= Microsoft.Extensions.Logging.LogLevel.Error) Errors.Add($"{formatter(state, exception)}: {exception}");
        }
    }

    private sealed class Sink(List<Alert> alerts) : IAlertSink
    {
        public void Publish(Alert alert) => alerts.Add(alert);
    }

    private sealed class Signatures : ISignatureVerifier
    {
        public SignatureInfo Verify(string? path) => path switch
        {
            Unsigned => new SignatureInfo(SignatureStatus.Unsigned, null),
            null => SignatureInfo.Unknown,
            _ => new SignatureInfo(SignatureStatus.Signed, "Vendor"),
        };
    }
}
