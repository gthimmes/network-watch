using Microsoft.Data.Sqlite;

namespace NetworkWatch.Core.Storage;

/// <summary>
/// SQLite store for connections, alerts, baseline and trust rules. WAL mode, so readers
/// (API, tools) don't block the pipeline writer. Each call uses a pooled connection.
/// </summary>
public sealed class Database
{
    private readonly string _connectionString;

    public Database(string path)
    {
        Path = path;
        _connectionString = new SqliteConnectionStringBuilder { DataSource = path, Pooling = true, DefaultTimeout = 10 }.ToString();
        Initialize();
    }

    public string Path { get; }

    internal SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout = 5000;";
        pragma.ExecuteNonQuery();
        return connection;
    }

    private void Initialize()
    {
        using var db = Open();
        Execute(db, """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY,
                time INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                process_path TEXT,
                protocol TEXT NOT NULL,
                direction TEXT NOT NULL,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                local_port INTEGER NOT NULL,
                domain TEXT,
                scope TEXT NOT NULL,
                signer TEXT,
                signature TEXT NOT NULL,
                threat TEXT);
            CREATE INDEX IF NOT EXISTS ix_connections_time ON connections(time);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                detector_id TEXT NOT NULL,
                severity INTEGER NOT NULL,
                title TEXT NOT NULL,
                what TEXT NOT NULL,
                why TEXT NOT NULL,
                todo TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                process_name TEXT,
                process_path TEXT,
                pid INTEGER,
                remote TEXT,
                domain TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                count INTEGER NOT NULL,
                status INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts(dedup_key, last_seen);
            CREATE INDEX IF NOT EXISTS ix_alerts_last_seen ON alerts(last_seen);
            CREATE TABLE IF NOT EXISTS apps (
                app_key TEXT PRIMARY KEY,
                process_name TEXT NOT NULL,
                process_path TEXT,
                signer TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                direct_ip_ok INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS listeners (key TEXT PRIMARY KEY, first_seen INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS environment (
                kind TEXT NOT NULL, subject TEXT NOT NULL, value TEXT NOT NULL, updated INTEGER NOT NULL,
                PRIMARY KEY (kind, subject));
            CREATE TABLE IF NOT EXISTS trust (
                app_key TEXT NOT NULL, detector_id TEXT NOT NULL, created INTEGER NOT NULL,
                PRIMARY KEY (app_key, detector_id));
            """);
    }

    internal static void Execute(SqliteConnection db, string sql, params (string Name, object? Value)[] parameters)
    {
        using var cmd = Command(db, sql, parameters);
        cmd.ExecuteNonQuery();
    }

    internal static SqliteCommand Command(SqliteConnection db, string sql, params (string Name, object? Value)[] parameters)
    {
        var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }

    internal static long ToUnixMs(DateTimeOffset time) => time.ToUnixTimeMilliseconds();

    internal static DateTimeOffset FromUnixMs(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms).ToLocalTime();

    // ── Settings ────────────────────────────────────────────────────────────

    public string? GetSetting(string key)
    {
        using var db = Open();
        using var cmd = Command(db, "SELECT value FROM settings WHERE key = $k", ("$k", key));
        return cmd.ExecuteScalar() as string;
    }

    public void SetSetting(string key, string value)
    {
        using var db = Open();
        Execute(db, "INSERT INTO settings(key, value) VALUES($k, $v) ON CONFLICT(key) DO UPDATE SET value = $v", ("$k", key), ("$v", value));
    }

    // ── Retention ───────────────────────────────────────────────────────────

    public void Prune(DateTimeOffset connectionsBefore, DateTimeOffset alertsBefore)
    {
        using var db = Open();
        Execute(db, "DELETE FROM connections WHERE time < $t", ("$t", ToUnixMs(connectionsBefore)));
        Execute(db, "DELETE FROM alerts WHERE last_seen < $t", ("$t", ToUnixMs(alertsBefore)));
    }
}
