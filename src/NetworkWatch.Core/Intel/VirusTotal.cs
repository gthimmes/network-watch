using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Intel;

/// <summary>Stores secrets (API keys) encrypted so other local users can't read them. OS-specific.</summary>
public interface ISecretStore
{
    string? Get(string name);
    void Set(string name, string? value);
}

public sealed record VirusTotalVerdict(bool Known, int Malicious, int Suspicious, int Total, string? Label);

/// <summary>
/// Opt-in VirusTotal lookups by SHA-256 hash (files are never uploaded). Runs as an alert sink: when an alert
/// names a program that deserves a second opinion, its hash is looked up in the background (free API tier:
/// at most 4 requests/minute) and either a note is appended to the alert or, if engines flag the file,
/// a new High alert is raised. Results are cached by hash.
/// </summary>
public sealed class VirusTotalEnricher : IAlertSink
{
    public const string SecretName = "virustotal-api-key";
    internal const int MaliciousThreshold = 3;

    private static readonly HashSet<string> DetectorsToCheck =
        ["untrusted-program", "direct-ip", "beacon", "suspicious-port", "upload-volume", "threat-intel", "exposure", "new-app", "dns-abuse"];

    private readonly Channel<Alert> _queue = Channel.CreateBounded<Alert>(new BoundedChannelOptions(200) { FullMode = BoundedChannelFullMode.DropOldest });
    private readonly HttpClient _http;
    private readonly ISecretStore _secrets;
    private readonly AlertStore _alerts;
    private readonly Func<AlertManager> _alertManager;
    private readonly Database _db;
    private readonly ILogger _logger;
    private readonly TimeSpan _spacing;
    private readonly HashSet<string> _queuedPaths = new(StringComparer.OrdinalIgnoreCase);

    public VirusTotalEnricher(HttpClient http, ISecretStore secrets, Database db, AlertStore alerts, Func<AlertManager> alertManager,
        ILogger logger, TimeSpan? spacing = null)
    {
        _http = http;
        _secrets = secrets;
        _db = db;
        _alerts = alerts;
        _alertManager = alertManager;
        _logger = logger;
        _spacing = spacing ?? TimeSpan.FromSeconds(16);
        using var c = db.Open();
        Database.Execute(c, """
            CREATE TABLE IF NOT EXISTS vt_cache (sha256 TEXT PRIMARY KEY, checked INTEGER NOT NULL, known INTEGER NOT NULL,
                malicious INTEGER NOT NULL, suspicious INTEGER NOT NULL, total INTEGER NOT NULL, label TEXT)
            """);
    }

    public bool IsEnabled => !string.IsNullOrEmpty(_secrets.Get(SecretName));

    public void Publish(Alert alert)
    {
        if (alert.DetectorId == "virustotal" || alert.ProcessPath is null || !DetectorsToCheck.Contains(alert.DetectorId)) return;
        // Signed new apps aren't worth a lookup; unsigned ones are (their text says "not digitally signed").
        if (alert.DetectorId == "new-app" && !alert.WhatHappened.Contains("not digitally signed", StringComparison.Ordinal)) return;
        if (!IsEnabled) return;
        lock (_queuedPaths)
            if (!_queuedPaths.Add(alert.ProcessPath)) return;
        _queue.Writer.TryWrite(alert);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        await foreach (var alert in _queue.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            try
            {
                var lookedUp = await EnrichAsync(alert, ct).ConfigureAwait(false);
                if (lookedUp) await Task.Delay(_spacing, ct).ConfigureAwait(false); // free tier: 4 lookups/minute
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception ex) { _logger.LogWarning("VirusTotal lookup for {Path} failed: {Error}", alert.ProcessPath, ex.Message); }
            finally
            {
                lock (_queuedPaths) _queuedPaths.Remove(alert.ProcessPath!);
            }
        }
    }

    /// <summary>Returns true if an API request was made (for rate limiting).</summary>
    internal async Task<bool> EnrichAsync(Alert alert, CancellationToken ct)
    {
        var path = alert.ProcessPath!;
        if (!File.Exists(path)) return false;
        var sha256 = await HashAsync(path, ct).ConfigureAwait(false);

        var verdict = Cached(sha256);
        var requested = false;
        if (verdict is null)
        {
            var key = _secrets.Get(SecretName);
            if (string.IsNullOrEmpty(key)) return false;
            verdict = await QueryAsync(sha256, key, ct).ConfigureAwait(false);
            requested = true;
            if (verdict is null) return true; // quota or error: try again for a later alert
            Cache(sha256, verdict);
        }

        var name = alert.ProcessName ?? Path.GetFileName(path);
        if (verdict.Malicious >= MaliciousThreshold)
        {
            _alertManager().Raise(new Alert
            {
                DetectorId = "virustotal",
                Severity = Severity.High,
                DedupKey = $"vt:{sha256}",
                Title = $"VirusTotal: {verdict.Malicious} security vendors flag {name} as malicious",
                WhatHappened = $"{path} (SHA-256 {sha256}) is flagged as malicious by {verdict.Malicious} of {verdict.Total} antivirus engines on VirusTotal" +
                    (verdict.Label is null ? "." : $" (\"{verdict.Label}\").") + $" It came up because of an earlier alert: {alert.Title}.",
                WhyItMatters = "Several independent antivirus engines agreeing a file is malicious is strong evidence this program is malware.",
                WhatToDo = "Block it now, then run a Microsoft Defender full scan and an offline scan (Windows Security → Virus & threat protection → Scan options). Change passwords from a different, clean device.",
                ProcessName = alert.ProcessName,
                ProcessPath = path,
                Pid = alert.Pid,
                FirstSeen = DateTimeOffset.Now,
                LastSeen = DateTimeOffset.Now,
            }, respectsTrust: false, DateTimeOffset.Now);
        }
        else
        {
            _alerts.AppendNote(alert.Id, verdict.Known
                ? $"VirusTotal: {verdict.Malicious} of {verdict.Total} engines flag this file{(verdict.Suspicious > 0 ? $" ({verdict.Suspicious} more call it suspicious)" : "")}."
                : "VirusTotal has never seen this file. That's normal for software you built yourself or niche tools, but also for new or targeted malware.");
        }
        return requested;
    }

    internal async Task<VirusTotalVerdict?> QueryAsync(string sha256, string apiKey, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256}");
        request.Headers.Add("x-apikey", apiKey);
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound) return new VirusTotalVerdict(false, 0, 0, 0, null);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("VirusTotal returned {Status} for {Hash}", (int)response.StatusCode, sha256);
            return null;
        }
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        var attributes = doc.RootElement.GetProperty("data").GetProperty("attributes");
        var stats = attributes.GetProperty("last_analysis_stats");
        int Stat(string n) => stats.TryGetProperty(n, out var v) ? v.GetInt32() : 0;
        var total = stats.EnumerateObject().Sum(p => p.Value.GetInt32());
        string? label = attributes.TryGetProperty("popular_threat_classification", out var c) &&
                        c.TryGetProperty("suggested_threat_label", out var l) ? l.GetString() : null;
        return new VirusTotalVerdict(true, Stat("malicious"), Stat("suspicious"), total, label);
    }

    private static async Task<string> HashAsync(string path, CancellationToken ct)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false));
    }

    private VirusTotalVerdict? Cached(string sha256)
    {
        using var c = _db.Open();
        using var cmd = Database.Command(c, "SELECT known, malicious, suspicious, total, label, checked FROM vt_cache WHERE sha256 = $h", ("$h", sha256));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        // Unknown files are re-checked after a day (they may have been submitted by someone since).
        if (r.GetInt64(0) == 0 && DateTimeOffset.Now - Database.FromUnixMs(r.GetInt64(5)) > TimeSpan.FromDays(1)) return null;
        return new VirusTotalVerdict(r.GetInt64(0) != 0, r.GetInt32(1), r.GetInt32(2), r.GetInt32(3), r.IsDBNull(4) ? null : r.GetString(4));
    }

    private void Cache(string sha256, VirusTotalVerdict v)
    {
        using var c = _db.Open();
        Database.Execute(c, """
            INSERT INTO vt_cache(sha256, checked, known, malicious, suspicious, total, label) VALUES($h, $t, $k, $m, $s, $n, $l)
            ON CONFLICT(sha256) DO UPDATE SET checked = $t, known = $k, malicious = $m, suspicious = $s, total = $n, label = $l
            """, ("$h", sha256), ("$t", Database.ToUnixMs(DateTimeOffset.Now)), ("$k", v.Known ? 1 : 0), ("$m", v.Malicious),
            ("$s", v.Suspicious), ("$n", v.Total), ("$l", v.Label));
    }
}
