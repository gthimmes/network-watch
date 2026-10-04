namespace NetworkWatch.Core.Storage;

public sealed record AppUsage(string AppKey, string ProcessName, long BytesSent, long BytesReceived);

/// <summary>Per-app traffic totals by hour. Samples are aggregated in memory and flushed about once a minute.</summary>
public sealed class UsageStore(Database database)
{
    private readonly Dictionary<(string AppKey, long Hour), (string Name, long Sent, long Received)> _pending = [];
    private readonly Lock _lock = new();

    public static long HourOf(DateTimeOffset time) => time.ToUnixTimeSeconds() / 3600;

    public void Add(string appKey, string processName, DateTimeOffset time, long sent, long received)
    {
        lock (_lock)
        {
            var key = (appKey, HourOf(time));
            var current = _pending.GetValueOrDefault(key, (processName, 0, 0));
            _pending[key] = (processName, current.Sent + sent, current.Received + received);
        }
    }

    public void Flush()
    {
        List<KeyValuePair<(string AppKey, long Hour), (string Name, long Sent, long Received)>> rows;
        lock (_lock)
        {
            if (_pending.Count == 0) return;
            rows = [.. _pending];
            _pending.Clear();
        }
        using var db = database.Open();
        using var tx = db.BeginTransaction();
        foreach (var ((appKey, hour), (name, sent, received)) in rows)
            Database.Execute(db, """
                INSERT INTO usage(app_key, hour, process_name, sent, received) VALUES($a, $h, $n, $s, $r)
                ON CONFLICT(app_key, hour) DO UPDATE SET sent = sent + $s, received = received + $r, process_name = $n
                """, ("$a", appKey), ("$h", hour), ("$n", name), ("$s", sent), ("$r", received));
        tx.Commit();
    }

    /// <summary>Totals per app since <paramref name="since"/>, biggest uploaders first. Includes unflushed data.</summary>
    public IReadOnlyList<AppUsage> Totals(DateTimeOffset since, int limit = 50)
    {
        Flush();
        using var db = database.Open();
        using var cmd = Database.Command(db, """
            SELECT app_key, MAX(process_name), SUM(sent), SUM(received) FROM usage WHERE hour >= $h
            GROUP BY app_key ORDER BY SUM(sent) + SUM(received) DESC LIMIT $limit
            """, ("$h", HourOf(since)), ("$limit", limit));
        using var r = cmd.ExecuteReader();
        var list = new List<AppUsage>();
        while (r.Read())
            list.Add(new AppUsage(r.GetString(0), r.GetString(1), r.GetInt64(2), r.GetInt64(3)));
        return list;
    }
}
