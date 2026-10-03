using System.Reflection;
using NetworkWatch.Collectors.Windows;
using NetworkWatch.Core;
using NetworkWatch.Core.Api;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Service;

/// <summary>Composition root for the monitoring engine; one instance per service process.</summary>
public sealed class Engine
{
    public Engine(ServicePaths paths, ILoggerFactory loggers, IHttpClientFactory http)
    {
        StartedAt = DateTimeOffset.Now;
        Paths = paths;
        Database = new Database(paths.DatabasePath);
        Baseline = new Baseline(Database, StartedAt);
        AlertStore = new AlertStore(Database);
        Connections = new ConnectionStore(Database);
        Alerts = new AlertManager(AlertStore, Baseline, loggers.CreateLogger("Alerts"), StartedAt);
        Feeds = new FeedManager(paths.FeedCacheDirectory, paths.CustomIndicatorsPath, http.CreateClient("feeds"), loggers.CreateLogger<FeedManager>());
        Processes = new ProcessResolver();
        Enforcer = new WindowsFirewallEnforcer();
        Pipeline = new NetworkPipeline(Baseline, Alerts, Connections, () => Feeds.Current, new WindowsSignatureVerifier(),
            DefaultDetectors.Create(), loggers.CreateLogger<NetworkPipeline>(), StartedAt);
        Api = new ApiHandler(AlertStore, Connections, Baseline, Enforcer, Status, ct => Feeds.RefreshAsync(TimeSpan.Zero, ct));
    }

    public static string Version { get; } =
        typeof(Engine).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public DateTimeOffset StartedAt { get; }
    public ServicePaths Paths { get; }
    public Database Database { get; }
    public Baseline Baseline { get; }
    public AlertStore AlertStore { get; }
    public ConnectionStore Connections { get; }
    public AlertManager Alerts { get; }
    public FeedManager Feeds { get; }
    public ProcessResolver Processes { get; }
    public IEnforcer Enforcer { get; }
    public NetworkPipeline Pipeline { get; }
    public ApiHandler Api { get; }
    public List<string> CollectorErrors { get; } = [];

    public StatusDto Status()
    {
        var (high, medium) = AlertStore.CountUnacknowledged();
        var stats = Pipeline.Stats;
        return new StatusDto
        {
            Version = Version,
            StartedAt = StartedAt,
            IsLearning = Baseline.IsLearning(DateTimeOffset.Now),
            LearningEndsAt = Baseline.LearningEndsAt,
            EventsProcessed = Interlocked.Read(ref stats.EventsProcessed),
            ConnectionsSeen = Interlocked.Read(ref stats.ConnectionsSeen),
            FlowsStored = Interlocked.Read(ref stats.FlowsStored),
            DnsResolutions = Interlocked.Read(ref stats.DnsResolutions),
            LastEvent = stats.LastEvent,
            ThreatIndicators = Feeds.Current.TotalIndicators,
            FeedsRefreshed = Feeds.LastRefresh,
            AppsKnown = Baseline.Apps().Count,
            UnacknowledgedHigh = high,
            UnacknowledgedMedium = medium,
            CollectorErrors = [.. CollectorErrors],
        };
    }
}

public sealed class ServicePaths
{
    public ServicePaths(string? dataDirectory = null)
    {
        DataDirectory = dataDirectory
            ?? Environment.GetEnvironmentVariable("NETWORKWATCH_DATA")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetworkWatch");
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogDirectory);
    }

    public string DataDirectory { get; }
    public string DatabasePath => Path.Combine(DataDirectory, "networkwatch.db");
    public string LogDirectory => Path.Combine(DataDirectory, "logs");
    public string FeedCacheDirectory => Path.Combine(DataDirectory, "feeds");
    public string CustomIndicatorsPath => Path.Combine(DataDirectory, "custom-indicators.txt");

    /// <summary>Only executables under this folder (admin-writable only) may send mutating API commands.</summary>
    public static string InstallDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NetworkWatch");
}
