using Microsoft.Extensions.Logging;

namespace NetworkWatch.Core.Intel;

/// <summary>
/// Downloads feeds into a local cache directory and builds <see cref="ThreatIntel"/> snapshots.
/// Works offline from the cache; a failed download keeps the previous cached copy.
/// Also loads the user's custom list (custom-indicators.txt in the data directory).
/// </summary>
public sealed class FeedManager(
    string cacheDirectory,
    string customListPath,
    HttpClient http,
    ILogger<FeedManager> logger,
    IReadOnlyList<FeedDefinition>? feeds = null)
{
    private readonly IReadOnlyList<FeedDefinition> _feeds = feeds ?? DefaultFeeds.All;
    private volatile ThreatIntel _current = ThreatIntel.Empty;

    public ThreatIntel Current => _current;

    public DateTimeOffset? LastRefresh { get; private set; }

    public static readonly FeedDefinition CustomFeed =
        new("custom", "", FeedFormat.Mixed, ThreatCategory.Custom, "Your custom blocklist");

    /// <summary>Builds a snapshot from whatever is in the cache, without network access.</summary>
    public ThreatIntel LoadFromCache()
    {
        var builder = new ThreatIntelBuilder();
        foreach (var feed in _feeds)
        {
            var path = CachePath(feed);
            if (File.Exists(path))
                FeedParser.Parse(feed, File.ReadAllText(path), builder);
        }
        if (File.Exists(customListPath))
            FeedParser.Parse(CustomFeed, File.ReadAllText(customListPath), builder);

        _current = builder.Build();
        logger.LogInformation("Threat intel loaded: {Total} indicators ({Breakdown})",
            _current.TotalIndicators, string.Join(", ", _current.CountsBySource.Select(kv => $"{kv.Key}={kv.Value}")));
        return _current;
    }

    /// <summary>Downloads every feed whose cache is older than <paramref name="maxAge"/>, then reloads.</summary>
    public async Task<ThreatIntel> RefreshAsync(TimeSpan maxAge, CancellationToken ct)
    {
        Directory.CreateDirectory(cacheDirectory);
        foreach (var feed in _feeds)
        {
            var path = CachePath(feed);
            if (File.Exists(path) && DateTime.UtcNow - File.GetLastWriteTimeUtc(path) < maxAge)
                continue;
            try
            {
                var content = await http.GetStringAsync(feed.Url, ct);
                var probe = new ThreatIntelBuilder();
                var count = FeedParser.Parse(feed, content, probe);
                if (count == 0 && feed.Name != "feodo")
                {
                    // Don't replace a good cache with an error page or an empty response.
                    logger.LogWarning("Feed {Feed} returned no indicators; keeping cached copy", feed.Name);
                    continue;
                }
                var temp = path + ".tmp";
                await File.WriteAllTextAsync(temp, content, ct);
                File.Move(temp, path, overwrite: true);
                logger.LogInformation("Feed {Feed} updated: {Count} indicators", feed.Name, count);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
            {
                if (ct.IsCancellationRequested) throw;
                logger.LogWarning("Feed {Feed} download failed: {Error}", feed.Name, ex.Message);
            }
        }
        LastRefresh = DateTimeOffset.Now;
        return LoadFromCache();
    }

    // ── Custom list ─────────────────────────────────────────────────────────

    private readonly Lock _customLock = new();

    public IReadOnlyList<string> CustomIndicators()
    {
        lock (_customLock)
            return File.Exists(customListPath)
                ? File.ReadAllLines(customListPath).Select(l => l.Trim()).Where(l => l.Length > 0 && l[0] != '#').ToList()
                : [];
    }

    /// <summary>Adds an IP, CIDR or domain to the custom list and reloads. Throws on invalid input.</summary>
    public void AddCustomIndicator(string value)
    {
        value = value.Trim().ToLowerInvariant();
        if (!new ThreatIntelBuilder().AddNetwork(value, new ThreatIndicator("custom", ThreatCategory.Custom, "")) &&
            !new ThreatIntelBuilder().AddDomain(value, new ThreatIndicator("custom", ThreatCategory.Custom, "")))
            throw new ArgumentException($"'{value}' isn't an IP address, CIDR range or domain name.");
        lock (_customLock)
        {
            var existing = CustomIndicators();
            if (existing.Contains(value, StringComparer.OrdinalIgnoreCase)) return;
            WriteCustom([.. existing, value]);
        }
        LoadFromCache();
    }

    public bool RemoveCustomIndicator(string value)
    {
        bool removed;
        lock (_customLock)
        {
            var existing = CustomIndicators().ToList();
            removed = existing.RemoveAll(v => v.Equals(value.Trim(), StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed) WriteCustom(existing);
        }
        if (removed) LoadFromCache();
        return removed;
    }

    private void WriteCustom(IEnumerable<string> values)
    {
        var temp = customListPath + ".tmp";
        File.WriteAllLines(temp, ["# Your custom blocklist: one IP, CIDR range or domain per line. Managed with 'nwctl indicators'.", .. values]);
        File.Move(temp, customListPath, overwrite: true);
    }

    private string CachePath(FeedDefinition feed) => Path.Combine(cacheDirectory, feed.Name + ".txt");
}
