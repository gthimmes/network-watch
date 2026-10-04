using Microsoft.Data.Sqlite;

namespace NetworkWatch.Core.Storage;

public sealed class ConnectionStore(Database database)
{
    public void Insert(EnrichedConnection c)
    {
        using var db = database.Open();
        Database.Execute(db, """
            INSERT INTO connections(time, pid, process_name, process_path, protocol, direction, remote_ip, remote_port,
                                    local_port, domain, scope, signer, signature, threat, country, network)
            VALUES($time, $pid, $name, $path, $proto, $dir, $rip, $rport, $lport, $domain, $scope, $signer, $sig, $threat, $country, $network)
            """,
            ("$time", Database.ToUnixMs(c.Conn.Time)), ("$pid", c.Conn.Pid), ("$name", c.Conn.ProcessName), ("$path", c.Conn.ProcessPath),
            ("$proto", c.Conn.Protocol.ToString()), ("$dir", c.Conn.Direction.ToString()),
            ("$rip", c.Conn.Remote.Address.ToString()), ("$rport", c.Conn.Remote.Port), ("$lport", c.Conn.Local.Port),
            ("$domain", c.Domain), ("$scope", c.Scope.ToString()), ("$signer", c.Signature.Signer), ("$sig", c.Signature.Status.ToString()),
            ("$threat", c.Threat?.Description), ("$country", c.Geo?.Country ?? c.Geo?.CountryCode), ("$network", c.Geo?.Organization));
    }

    public IReadOnlyList<ConnectionRecord> Recent(int limit, string? search = null)
    {
        using var db = database.Open();
        var where = string.IsNullOrWhiteSpace(search) ? "" :
            "WHERE process_name LIKE $q OR domain LIKE $q OR remote_ip LIKE $q OR process_path LIKE $q OR country LIKE $q OR network LIKE $q";
        using var cmd = Database.Command(db, $"SELECT * FROM connections {where} ORDER BY id DESC LIMIT $limit",
            ("$limit", limit), ("$q", $"%{search}%"));
        using var r = cmd.ExecuteReader();
        var list = new List<ConnectionRecord>();
        while (r.Read())
            list.Add(new ConnectionRecord(
                r.GetInt64(r.GetOrdinal("id")), Database.FromUnixMs(r.GetInt64(r.GetOrdinal("time"))), r.GetInt32(r.GetOrdinal("pid")),
                r.GetString(r.GetOrdinal("process_name")), Str(r, "process_path"), r.GetString(r.GetOrdinal("protocol")),
                r.GetString(r.GetOrdinal("direction")), r.GetString(r.GetOrdinal("remote_ip")), r.GetInt32(r.GetOrdinal("remote_port")),
                r.GetInt32(r.GetOrdinal("local_port")), Str(r, "domain"), r.GetString(r.GetOrdinal("scope")), Str(r, "signer"),
                r.GetString(r.GetOrdinal("signature")), Str(r, "threat"), Str(r, "country"), Str(r, "network")));
        return list;
    }

    public long CountSince(DateTimeOffset since)
    {
        using var db = database.Open();
        using var cmd = Database.Command(db, "SELECT COUNT(*) FROM connections WHERE time >= $t", ("$t", Database.ToUnixMs(since)));
        return (long)cmd.ExecuteScalar()!;
    }

    internal static string? Str(SqliteDataReader r, string column)
    {
        var i = r.GetOrdinal(column);
        return r.IsDBNull(i) ? null : r.GetString(i);
    }
}

public sealed class AlertStore(Database database)
{
    public long Insert(Alert a)
    {
        using var db = database.Open();
        using var cmd = Database.Command(db, """
            INSERT INTO alerts(detector_id, severity, title, what, why, todo, dedup_key, process_name, process_path, pid,
                               remote, domain, first_seen, last_seen, count, status)
            VALUES($det, $sev, $title, $what, $why, $todo, $key, $name, $path, $pid, $remote, $domain, $first, $last, $count, $status);
            SELECT last_insert_rowid();
            """,
            ("$det", a.DetectorId), ("$sev", (int)a.Severity), ("$title", a.Title), ("$what", a.WhatHappened), ("$why", a.WhyItMatters),
            ("$todo", a.WhatToDo), ("$key", a.DedupKey), ("$name", a.ProcessName), ("$path", a.ProcessPath), ("$pid", a.Pid),
            ("$remote", a.Remote), ("$domain", a.Domain), ("$first", Database.ToUnixMs(a.FirstSeen)), ("$last", Database.ToUnixMs(a.LastSeen)),
            ("$count", a.Count), ("$status", (int)a.Status));
        return (long)cmd.ExecuteScalar()!;
    }

    public void Touch(long id, DateTimeOffset lastSeen)
    {
        using var db = database.Open();
        Database.Execute(db, "UPDATE alerts SET last_seen = $t, count = count + 1 WHERE id = $id", ("$t", Database.ToUnixMs(lastSeen)), ("$id", id));
    }

    public void SetStatus(long id, AlertStatus status)
    {
        using var db = database.Open();
        Database.Execute(db, "UPDATE alerts SET status = $s WHERE id = $id", ("$s", (int)status), ("$id", id));
    }

    public void AcknowledgeAll()
    {
        using var db = database.Open();
        Database.Execute(db, "UPDATE alerts SET status = $s WHERE status = $new", ("$s", (int)AlertStatus.Acknowledged), ("$new", (int)AlertStatus.New));
    }

    /// <summary>Most recent alert per dedup key seen since <paramref name="since"/> (to rebuild dedup state on start).</summary>
    public IReadOnlyList<(string Key, long Id, DateTimeOffset LastSeen)> RecentKeys(DateTimeOffset since)
    {
        using var db = database.Open();
        using var cmd = Database.Command(db, "SELECT dedup_key, MAX(id), MAX(last_seen) FROM alerts WHERE last_seen >= $t GROUP BY dedup_key",
            ("$t", Database.ToUnixMs(since)));
        using var r = cmd.ExecuteReader();
        var list = new List<(string, long, DateTimeOffset)>();
        while (r.Read())
            list.Add((r.GetString(0), r.GetInt64(1), Database.FromUnixMs(r.GetInt64(2))));
        return list;
    }

    public IReadOnlyList<Alert> Query(int limit, Severity minSeverity = Severity.Info, long afterId = 0)
    {
        using var db = database.Open();
        using var cmd = Database.Command(db,
            "SELECT * FROM alerts WHERE severity >= $sev AND id > $after ORDER BY last_seen DESC LIMIT $limit",
            ("$sev", (int)minSeverity), ("$after", afterId), ("$limit", limit));
        return Read(cmd);
    }

    public Alert? Get(long id)
    {
        using var db = database.Open();
        using var cmd = Database.Command(db, "SELECT * FROM alerts WHERE id = $id", ("$id", id));
        return Read(cmd).FirstOrDefault();
    }

    /// <summary>Alerts first raised since <paramref name="since"/>.</summary>
    public IReadOnlyList<Alert> RaisedSince(DateTimeOffset since)
    {
        using var db = database.Open();
        using var cmd = Database.Command(db, "SELECT * FROM alerts WHERE first_seen >= $t ORDER BY severity DESC, last_seen DESC",
            ("$t", Database.ToUnixMs(since)));
        return Read(cmd);
    }

    public (int High, int Medium) CountUnacknowledged()
    {
        using var db = database.Open();
        using var cmd = Database.Command(db,
            "SELECT severity, COUNT(*) FROM alerts WHERE status = $new AND severity >= $med GROUP BY severity",
            ("$new", (int)AlertStatus.New), ("$med", (int)Severity.Medium));
        using var r = cmd.ExecuteReader();
        int high = 0, medium = 0;
        while (r.Read())
        {
            if (r.GetInt32(0) == (int)Severity.High) high = r.GetInt32(1);
            else medium = r.GetInt32(1);
        }
        return (high, medium);
    }

    private static List<Alert> Read(SqliteCommand cmd)
    {
        using var r = cmd.ExecuteReader();
        var list = new List<Alert>();
        while (r.Read())
        {
            var pidOrdinal = r.GetOrdinal("pid");
            list.Add(new Alert
            {
                Id = r.GetInt64(r.GetOrdinal("id")),
                DetectorId = r.GetString(r.GetOrdinal("detector_id")),
                Severity = (Severity)r.GetInt32(r.GetOrdinal("severity")),
                Title = r.GetString(r.GetOrdinal("title")),
                WhatHappened = r.GetString(r.GetOrdinal("what")),
                WhyItMatters = r.GetString(r.GetOrdinal("why")),
                WhatToDo = r.GetString(r.GetOrdinal("todo")),
                DedupKey = r.GetString(r.GetOrdinal("dedup_key")),
                ProcessName = ConnectionStore.Str(r, "process_name"),
                ProcessPath = ConnectionStore.Str(r, "process_path"),
                Pid = r.IsDBNull(pidOrdinal) ? null : r.GetInt32(pidOrdinal),
                Remote = ConnectionStore.Str(r, "remote"),
                Domain = ConnectionStore.Str(r, "domain"),
                FirstSeen = Database.FromUnixMs(r.GetInt64(r.GetOrdinal("first_seen"))),
                LastSeen = Database.FromUnixMs(r.GetInt64(r.GetOrdinal("last_seen"))),
                Count = r.GetInt32(r.GetOrdinal("count")),
                Status = (AlertStatus)r.GetInt32(r.GetOrdinal("status")),
            });
        }
        return list;
    }
}
