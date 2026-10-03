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

    private string CachePath(FeedDefinition feed) => Path.Combine(cacheDirectory, feed.Name + ".txt");
}
