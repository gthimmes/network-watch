using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Tests;

public sealed class RemoteLogonTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"nw-logon-{Guid.NewGuid():N}.db");
    private readonly NetworkPipeline _pipeline;
    private readonly List<Alert> _alerts = [];
    private DateTimeOffset _now = T0;

    public RemoteLogonTests()
    {
        var db = new Database(_dbPath);
        var baseline = new Baseline(db, T0, TimeSpan.FromDays(7));
        var manager = new AlertManager(new AlertStore(db), baseline, NullLogger.Instance, T0);
        manager.AddSink(new Sink(_alerts));
        _pipeline = new NetworkPipeline(baseline, manager, null, () => ThreatIntel.Empty, new NullSignatureVerifier(),
            DefaultDetectors.Create(), NullLogger.Instance, T0);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var f in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
            try { File.Delete(f); } catch (IOException) { }
    }

    private void Logon(string ip, bool success = true, LogonKind kind = LogonKind.RemoteDesktop, bool historical = false) =>
        _pipeline.Process(new RemoteLogon(_now, success, @"PC\me", IPAddress.Parse(ip), kind, "LAPTOP", historical), _now);

    [Fact]
    public void KnownLanRdpSourceIsQuietAndNewOneAlertsAfterLearning()
    {
        Logon("192.168.50.136", historical: true); // seen in last week's log at startup
        _now = T0.AddDays(8);
        Logon("192.168.50.136");
        Assert.Empty(_alerts);

        Logon("192.168.50.77");
        var alert = Assert.Single(_alerts);
        Assert.Equal(Severity.Medium, alert.Severity);
        Assert.Contains("192.168.50.77", alert.WhatHappened);
    }

    [Fact]
    public void SignInFromTheInternetIsAlwaysHigh()
    {
        Logon("203.0.113.5", kind: LogonKind.Network, historical: true);
        var alert = Assert.Single(_alerts);
        Assert.Equal(Severity.High, alert.Severity);
    }

    [Fact]
    public void LanFileSharingLogonsAreIgnored()
    {
        _now = T0.AddDays(8);
        Logon("192.168.50.20", kind: LogonKind.Network);
        Assert.Empty(_alerts);
    }

    [Fact]
    public void PasswordGuessingTriggersAtThreshold()
    {
        for (var i = 0; i < RemoteLogonDetector.PublicFailureThreshold - 1; i++) Logon("198.51.100.66", success: false);
        Assert.Empty(_alerts);
        Logon("198.51.100.66", success: false);
        Assert.Equal(Severity.High, Assert.Single(_alerts).Severity);

        for (var i = 0; i < RemoteLogonDetector.PrivateFailureThreshold; i++) Logon("192.168.50.9", success: false);
        Assert.Equal(Severity.Medium, _alerts[^1].Severity);
        Assert.Equal(2, _alerts.Count);
    }

    [Fact]
    public void HistoricalFailuresAndLoopbackAreIgnored()
    {
        for (var i = 0; i < 20; i++) Logon("198.51.100.66", success: false, historical: true);
        for (var i = 0; i < 20; i++) Logon("127.0.0.1", success: false);
        Assert.Empty(_alerts);
    }

    private sealed class Sink(List<Alert> alerts) : IAlertSink
    {
        public void Publish(Alert alert) => alerts.Add(alert);
    }
}
