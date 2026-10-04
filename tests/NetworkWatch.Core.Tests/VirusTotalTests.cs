using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Tests;

public sealed class VirusTotalTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"nw-vt-{Guid.NewGuid():N}");
    private readonly Database _db;
    private readonly AlertStore _store;
    private readonly AlertManager _manager;
    private readonly List<Alert> _raised = [];
    private readonly FakeVt _vt = new();
    private readonly Secrets _secrets = new();
    private readonly VirusTotalEnricher _enricher;
    private readonly string _exe;

    public VirusTotalTests()
    {
        Directory.CreateDirectory(_dir);
        _db = new Database(Path.Combine(_dir, "t.db"));
        _store = new AlertStore(_db);
        var baseline = new Baseline(_db, DateTimeOffset.Now);
        _manager = new AlertManager(_store, baseline, NullLogger.Instance, DateTimeOffset.Now);
        _manager.AddSink(new Sink(_raised));
        _enricher = new VirusTotalEnricher(new HttpClient(_vt), _secrets, _db, _store, () => _manager, NullLogger.Instance, TimeSpan.Zero);
        _exe = Path.Combine(_dir, "sample.exe");
        File.WriteAllBytes(_exe, [1, 2, 3, 4]);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    private Alert StoredAlert()
    {
        var alert = new Alert
        {
            DetectorId = "untrusted-program", Severity = Severity.High, Title = "Untrusted program sample.exe", WhatHappened = "It ran.",
            WhyItMatters = "-", WhatToDo = "-", DedupKey = Guid.NewGuid().ToString(), ProcessName = "sample.exe", ProcessPath = _exe,
            FirstSeen = DateTimeOffset.Now, LastSeen = DateTimeOffset.Now,
        };
        return alert with { Id = _store.Insert(alert) };
    }

    [Fact]
    public async Task MaliciousVerdictRaisesHighAlertAndHashIsSentNotTheFile()
    {
        _secrets.Value = "test-key";
        _vt.Respond(HttpStatusCode.OK, """{"data":{"attributes":{"last_analysis_stats":{"malicious":41,"suspicious":2,"undetected":20,"harmless":0},"popular_threat_classification":{"suggested_threat_label":"trojan.asyncrat/msil"}}}}""");

        await _enricher.EnrichAsync(StoredAlert(), default);

        var alert = Assert.Single(_raised);
        Assert.Equal(("virustotal", Severity.High), (alert.DetectorId, alert.Severity));
        Assert.Contains("41 of 63", alert.WhatHappened);
        Assert.Contains("trojan.asyncrat/msil", alert.WhatHappened);
        var request = Assert.Single(_vt.Requests);
        Assert.Equal("test-key", request.Headers.GetValues("x-apikey").Single());
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Matches("/api/v3/files/[0-9a-f]{64}$", request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task CleanAndUnknownResultsBecomeNotesAndAreCached()
    {
        _secrets.Value = "test-key";
        _vt.Respond(HttpStatusCode.OK, """{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":60,"harmless":10}}}}""");
        var first = StoredAlert();
        await _enricher.EnrichAsync(first, default);
        Assert.Empty(_raised);
        Assert.Contains("VirusTotal: 0 of 70 engines flag this file.", _store.Get(first.Id)!.WhatHappened);

        var second = StoredAlert();
        await _enricher.EnrichAsync(second, default); // same file: served from cache
        Assert.Single(_vt.Requests);
        Assert.Contains("0 of 70", _store.Get(second.Id)!.WhatHappened);

        File.WriteAllBytes(_exe, [9, 9, 9]);
        _vt.Respond(HttpStatusCode.NotFound, "{}");
        var third = StoredAlert();
        await _enricher.EnrichAsync(third, default);
        Assert.Contains("never seen this file", _store.Get(third.Id)!.WhatHappened);
    }

    [Fact]
    public async Task NothingIsSentWithoutAKey()
    {
        _secrets.Value = null;
        Assert.False(_enricher.IsEnabled);
        _enricher.Publish(StoredAlert()); // ignored when disabled
        await _enricher.EnrichAsync(StoredAlert(), default);
        Assert.Empty(_vt.Requests);
    }

    private sealed class FakeVt : HttpMessageHandler
    {
        private (HttpStatusCode Status, string Body) _next = (HttpStatusCode.OK, "{}");
        public List<HttpRequestMessage> Requests { get; } = [];
        public void Respond(HttpStatusCode status, string body) => _next = (status, body);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request);
            return Task.FromResult(new HttpResponseMessage(_next.Status) { Content = new StringContent(_next.Body) });
        }
    }

    private sealed class Secrets : ISecretStore
    {
        public string? Value { get; set; }
        public string? Get(string name) => Value;
        public void Set(string name, string? value) => Value = value;
    }

    private sealed class Sink(List<Alert> alerts) : IAlertSink
    {
        public void Publish(Alert alert) => alerts.Add(alert);
    }
}
