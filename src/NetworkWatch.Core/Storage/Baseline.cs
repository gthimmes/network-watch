using System.Globalization;

namespace NetworkWatch.Core.Storage;

/// <summary>
/// What "normal" looks like on this machine: which apps use the network, which ones talk to
/// raw IPs, which listeners exist, current network configuration, and the user's trust rules.
/// Learned during the learning period; afterwards deviations become alerts.
/// Cached in memory and persisted to SQLite. Thread-safe.
/// </summary>
public sealed class Baseline
{
    /// <summary>Trust rule detector id meaning "all behavioral detectors".</summary>
    public const string AllDetectors = "";

    private const string LearningStartedKey = "learning_started";
    private const string LearningDaysKey = "learning_days";

    private readonly Database _db;
    private readonly Lock _lock = new();
    private readonly Dictionary<string, AppState> _apps = [];
    private readonly HashSet<string> _listeners = [];
    private readonly Dictionary<(string Kind, string Subject), string> _environment = [];
    private readonly HashSet<(string AppKey, string DetectorId)> _trust = [];
    private DateTimeOffset _learningStarted;
    private TimeSpan _learningPeriod;

    private sealed class AppState
    {
        public required string Name;
        public string? Path;
        public string? Signer;
        public DateTimeOffset FirstSeen;
        public DateTimeOffset LastSeen;
        public DateTimeOffset LastPersisted;
        public bool DirectIpOk;
        public long MaxHourlyUpload;
    }

    public Baseline(Database db, DateTimeOffset now, TimeSpan? defaultLearningPeriod = null)
    {
        _db = db;
        var started = db.GetSetting(LearningStartedKey);
        if (started is null)
        {
            _learningStarted = now;
            db.SetSetting(LearningStartedKey, now.ToString("O", CultureInfo.InvariantCulture));
        }
        else
        {
            _learningStarted = DateTimeOffset.Parse(started, CultureInfo.InvariantCulture);
        }
        var days = db.GetSetting(LearningDaysKey);
        _learningPeriod = days is not null ? TimeSpan.FromDays(double.Parse(days, CultureInfo.InvariantCulture)) : defaultLearningPeriod ?? TimeSpan.FromDays(7);
        Load();
    }

    // ── Learning period ─────────────────────────────────────────────────────

    public DateTimeOffset LearningEndsAt { get { lock (_lock) return _learningStarted + _learningPeriod; } }

    public bool IsLearning(DateTimeOffset now) => now < LearningEndsAt;

    public void EndLearning(DateTimeOffset now)
    {
        lock (_lock)
        {
            _learningStarted = now - _learningPeriod;
            _db.SetSetting(LearningStartedKey, _learningStarted.ToString("O", CultureInfo.InvariantCulture));
        }
    }

    public void RestartLearning(DateTimeOffset now)
    {
        lock (_lock)
        {
            _learningStarted = now;
            _db.SetSetting(LearningStartedKey, now.ToString("O", CultureInfo.InvariantCulture));
        }
    }

    // ── Apps ────────────────────────────────────────────────────────────────

    /// <summary>Records network activity for an app. Returns true if the app was never seen before.</summary>
    public bool TouchApp(string appKey, string name, string? path, string? signer, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (_apps.TryGetValue(appKey, out var app))
            {
                app.LastSeen = now;
                if (app.Signer is null && signer is not null) app.Signer = signer;
                if (now - app.LastPersisted > TimeSpan.FromMinutes(10)) PersistApp(appKey, app);
                return false;
            }
            app = new AppState { Name = name, Path = path, Signer = signer, FirstSeen = now, LastSeen = now };
            _apps[appKey] = app;
            PersistApp(appKey, app);
            return true;
        }
    }

    public bool IsDirectIpOk(string appKey)
    {
        lock (_lock) return _apps.TryGetValue(appKey, out var app) && app.DirectIpOk;
    }

    public void MarkDirectIpOk(string appKey)
    {
        lock (_lock)
        {
            if (_apps.TryGetValue(appKey, out var app) && !app.DirectIpOk)
            {
                app.DirectIpOk = true;
                PersistApp(appKey, app);
            }
        }
    }

    public long MaxHourlyUpload(string appKey)
    {
        lock (_lock) return _apps.TryGetValue(appKey, out var app) ? app.MaxHourlyUpload : 0;
    }

    /// <summary>
    /// Raises the learned maximum hourly upload for an app (persisted at most every 10 minutes). Creates the
    /// app entry if traffic is seen before any connection (e.g. connections already open at service start).
    /// </summary>
    public void RecordHourlyUpload(string appKey, string name, string? path, long bytes, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (!_apps.TryGetValue(appKey, out var app))
                _apps[appKey] = app = new AppState { Name = name, Path = path, FirstSeen = now, LastSeen = now };
            if (bytes <= app.MaxHourlyUpload) return;
            app.MaxHourlyUpload = bytes;
            if (now - app.LastPersisted > TimeSpan.FromMinutes(10)) PersistApp(appKey, app);
        }
    }

    public IReadOnlyList<AppRecord> Apps()
    {
        lock (_lock)
            return _apps.Select(kv => new AppRecord(kv.Key, kv.Value.Name, kv.Value.Path, kv.Value.Signer, kv.Value.FirstSeen,
                    kv.Value.LastSeen, kv.Value.DirectIpOk, _trust.Contains((kv.Key, AllDetectors))))
                .OrderByDescending(a => a.LastSeen).ToList();
    }

    private void PersistApp(string key, AppState app)
    {
        app.LastPersisted = app.LastSeen;
        using var db = _db.Open();
        Database.Execute(db, """
            INSERT INTO apps(app_key, process_name, process_path, signer, first_seen, last_seen, direct_ip_ok, max_hourly_upload)
            VALUES($k, $n, $p, $s, $f, $l, $d, $u)
            ON CONFLICT(app_key) DO UPDATE SET last_seen = $l, signer = $s, direct_ip_ok = $d, max_hourly_upload = $u
            """,
            ("$k", key), ("$n", app.Name), ("$p", app.Path), ("$s", app.Signer), ("$f", Database.ToUnixMs(app.FirstSeen)),
            ("$l", Database.ToUnixMs(app.LastSeen)), ("$d", app.DirectIpOk ? 1 : 0), ("$u", app.MaxHourlyUpload));
    }

    // ── Listeners ───────────────────────────────────────────────────────────

    /// <summary>Returns true if the listener key was not known before (and records it).</summary>
    public bool AddListener(string key, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (!_listeners.Add(key)) return false;
            using var db = _db.Open();
            Database.Execute(db, "INSERT OR IGNORE INTO listeners(key, first_seen) VALUES($k, $t)", ("$k", key), ("$t", Database.ToUnixMs(now)));
            return true;
        }
    }

    // ── Environment ─────────────────────────────────────────────────────────

    public string? GetEnvironment(string kind, string subject)
    {
        lock (_lock) return _environment.GetValueOrDefault((kind, subject));
    }

    public void SetEnvironment(string kind, string subject, string value, DateTimeOffset now)
    {
        lock (_lock)
        {
            _environment[(kind, subject)] = value;
            using var db = _db.Open();
            Database.Execute(db, """
                INSERT INTO environment(kind, subject, value, updated) VALUES($k, $s, $v, $t)
                ON CONFLICT(kind, subject) DO UPDATE SET value = $v, updated = $t
                """, ("$k", kind), ("$s", subject), ("$v", value), ("$t", Database.ToUnixMs(now)));
        }
    }

    // ── Trust ───────────────────────────────────────────────────────────────

    /// <summary>True if the user trusted this app for this detector, or for all behavioral detectors.</summary>
    public bool IsTrusted(string appKey, string detectorId)
    {
        lock (_lock) return _trust.Contains((appKey, AllDetectors)) || _trust.Contains((appKey, detectorId));
    }

    public void Trust(string appKey, string detectorId = AllDetectors)
    {
        lock (_lock)
        {
            if (!_trust.Add((appKey, detectorId))) return;
            using var db = _db.Open();
            Database.Execute(db, "INSERT OR IGNORE INTO trust(app_key, detector_id, created) VALUES($a, $d, $t)",
                ("$a", appKey), ("$d", detectorId), ("$t", Database.ToUnixMs(DateTimeOffset.Now)));
        }
    }

    public void Untrust(string appKey)
    {
        lock (_lock)
        {
            _trust.RemoveWhere(t => t.AppKey == appKey);
            using var db = _db.Open();
            Database.Execute(db, "DELETE FROM trust WHERE app_key = $a", ("$a", appKey));
        }
    }

    // ── Load ────────────────────────────────────────────────────────────────

    private void Load()
    {
        using var db = _db.Open();
        using (var cmd = Database.Command(db, "SELECT app_key, process_name, process_path, signer, first_seen, last_seen, direct_ip_ok, max_hourly_upload FROM apps"))
        using (var r = cmd.ExecuteReader())
            while (r.Read())
                _apps[r.GetString(0)] = new AppState
                {
                    Name = r.GetString(1),
                    Path = r.IsDBNull(2) ? null : r.GetString(2),
                    Signer = r.IsDBNull(3) ? null : r.GetString(3),
                    FirstSeen = Database.FromUnixMs(r.GetInt64(4)),
                    LastSeen = Database.FromUnixMs(r.GetInt64(5)),
                    LastPersisted = Database.FromUnixMs(r.GetInt64(5)),
                    DirectIpOk = r.GetInt64(6) != 0,
                    MaxHourlyUpload = r.GetInt64(7),
                };
        using (var cmd = Database.Command(db, "SELECT key FROM listeners"))
        using (var r = cmd.ExecuteReader())
            while (r.Read()) _listeners.Add(r.GetString(0));
        using (var cmd = Database.Command(db, "SELECT kind, subject, value FROM environment"))
        using (var r = cmd.ExecuteReader())
            while (r.Read()) _environment[(r.GetString(0), r.GetString(1))] = r.GetString(2);
        using (var cmd = Database.Command(db, "SELECT app_key, detector_id FROM trust"))
        using (var r = cmd.ExecuteReader())
            while (r.Read()) _trust.Add((r.GetString(0), r.GetString(1)));
    }
}
