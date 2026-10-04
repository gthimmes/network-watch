using System.IO.Compression;
using System.Net;
using MaxMind.Db;
using Microsoft.Extensions.Logging;

namespace NetworkWatch.Core.Intel;

public sealed record GeoInfo(string? CountryCode, string? Country, long? Asn, string? Organization)
{
    public override string ToString() =>
        string.Join(", ", new[] { Country ?? CountryCode, Organization }.Where(s => !string.IsNullOrEmpty(s)));
}

/// <summary>
/// Country and network-owner (ASN) lookups from the free DB-IP "lite" databases
/// (https://db-ip.com, CC BY 4.0), downloaded monthly into the data directory. Offline lookups only.
/// </summary>
public sealed class GeoIpService(string directory, HttpClient http, ILogger<GeoIpService> logger) : IDisposable
{
    private volatile Reader? _country;
    private volatile Reader? _asn;

    public bool IsLoaded => _country is not null || _asn is not null;

    public const string Attribution = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0";

    public GeoInfo? Lookup(IPAddress address)
    {
        address = DnsCorrelator.Normalize(address);
        if (!IpClassifier.IsPublic(address)) return null;
        string? code = null, country = null, org = null;
        long? asn = null;
        try
        {
            if (_country?.Find<Dictionary<string, object>>(address) is { } c && c.GetValueOrDefault("country") is Dictionary<string, object> ctry)
            {
                code = ctry.GetValueOrDefault("iso_code") as string;
                country = (ctry.GetValueOrDefault("names") as Dictionary<string, object>)?.GetValueOrDefault("en") as string;
            }
            if (_asn?.Find<Dictionary<string, object>>(address) is { } a)
            {
                asn = a.GetValueOrDefault("autonomous_system_number") is { } n ? Convert.ToInt64(n) : null;
                org = a.GetValueOrDefault("autonomous_system_organization") as string;
            }
        }
        catch (Exception ex) when (ex is InvalidDatabaseException or InvalidCastException)
        {
            return null;
        }
        return code is null && org is null ? null : new GeoInfo(code, country, asn, org);
    }

    public void Load()
    {
        _country = Open("country");
        _asn = Open("asn");
        logger.LogInformation("GeoIP databases: country {Country}, ASN {Asn}", _country is not null ? "loaded" : "missing", _asn is not null ? "loaded" : "missing");
    }

    /// <summary>Downloads this month's databases if the local copies are missing or from an older month.</summary>
    public async Task RefreshAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(directory);
        var month = DateTime.UtcNow.ToString("yyyy-MM");
        var changed = false;
        foreach (var kind in new[] { "country", "asn" })
        {
            var path = PathFor(kind);
            if (File.Exists(path) && File.GetLastWriteTimeUtc(path).ToString("yyyy-MM") == month) continue;
            // New months are published early in the month; fall back to the previous month's file.
            foreach (var m in new[] { month, DateTime.UtcNow.AddMonths(-1).ToString("yyyy-MM") })
            {
                try
                {
                    var bytes = await http.GetByteArrayAsync($"https://download.db-ip.com/free/dbip-{kind}-lite-{m}.mmdb.gz", ct).ConfigureAwait(false);
                    var temp = path + ".tmp";
                    await using (var gz = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress))
                    await using (var file = File.Create(temp))
                        await gz.CopyToAsync(file, ct).ConfigureAwait(false);
                    using (new Reader(temp)) { } // validate before replacing
                    if (kind == "country") _country = null; else _asn = null; // release before replacing
                    File.Move(temp, path, overwrite: true);
                    changed = true;
                    logger.LogInformation("GeoIP {Kind} database updated ({Month})", kind, m);
                    break;
                }
                catch (Exception ex) when (ex is HttpRequestException or InvalidDatabaseException or InvalidDataException or IOException)
                {
                    logger.LogWarning("GeoIP {Kind} {Month} download failed: {Error}", kind, m, ex.Message);
                }
            }
        }
        if (changed || !IsLoaded) Load();
    }

    private Reader? Open(string kind)
    {
        var path = PathFor(kind);
        if (!File.Exists(path)) return null;
        try { return new Reader(path, FileAccessMode.Memory); }
        catch (Exception ex) when (ex is InvalidDatabaseException or IOException)
        {
            logger.LogWarning("GeoIP {Kind} database unreadable: {Error}", kind, ex.Message);
            return null;
        }
    }

    private string PathFor(string kind) => Path.Combine(directory, $"dbip-{kind}-lite.mmdb");

    public void Dispose()
    {
        _country?.Dispose();
        _asn?.Dispose();
    }
}
