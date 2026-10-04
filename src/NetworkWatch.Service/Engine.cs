using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
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
        paths.Secure(loggers.CreateLogger<Engine>());
        Database = new Database(paths.DatabasePath);
        Baseline = new Baseline(Database, StartedAt);
        AlertStore = new AlertStore(Database);
        Connections = new ConnectionStore(Database);
        Alerts = new AlertManager(AlertStore, Baseline, loggers.CreateLogger("Alerts"), StartedAt);
        Feeds = new FeedManager(paths.FeedCacheDirectory, paths.CustomIndicatorsPath, http.CreateClient("feeds"), loggers.CreateLogger<FeedManager>());
        Usage = new UsageStore(Database);
        Geo = new GeoIpService(paths.GeoDirectory, http.CreateClient("feeds"), loggers.CreateLogger<GeoIpService>());
        Processes = new ProcessResolver();
        Enforcer = new WindowsFirewallEnforcer();
        Pipeline = new NetworkPipeline(Baseline, Alerts, Connections, () => Feeds.Current, new WindowsSignatureVerifier(),
            DefaultDetectors.Create(), loggers.CreateLogger<NetworkPipeline>(), StartedAt, Usage, Geo.Lookup);
        Secrets = new DpapiSecretStore(Database);
        VirusTotal = new VirusTotalEnricher(http.CreateClient("virustotal"), Secrets, Database, AlertStore, () => Alerts, loggers.CreateLogger<VirusTotalEnricher>());
        Alerts.AddSink(VirusTotal);
        Api = new ApiHandler(AlertStore, Connections, Usage, Baseline, Feeds, Enforcer, Status, Secrets);
    }

    public UsageStore Usage { get; }
    public ISecretStore Secrets { get; }
    public VirusTotalEnricher VirusTotal { get; }
    public GeoIpService Geo { get; }

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
            RemoteLogons = Interlocked.Read(ref stats.RemoteLogons),
            VirusTotalEnabled = VirusTotal.IsEnabled,
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

    /// <summary>
    /// The data folder lives under ProgramData, which by default lets any user create files. Lock it to
    /// SYSTEM/Administrators (full) and Users (read) so other processes can read logs and the database but
    /// can't plant or alter feeds, custom indicators or the database. Only effective when running as admin/SYSTEM.
    /// </summary>
    public void Secure(ILogger logger)
    {
        try
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(admins);
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(DataDirectory).SetAccessControl(security);

            // Reset everything below to plain inheritance and take ownership away from any user who created files.
            foreach (var entry in new DirectoryInfo(DataDirectory).EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
            {
                if (entry is DirectoryInfo dir)
                {
                    var s = new DirectorySecurity();
                    s.SetAccessRuleProtection(false, false);
                    s.SetOwner(admins);
                    dir.SetAccessControl(s);
                }
                else if (entry is FileInfo file)
                {
                    var s = new FileSecurity();
                    s.SetAccessRuleProtection(false, false);
                    s.SetOwner(admins);
                    file.SetAccessControl(s);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IOException or PrivilegeNotHeldException)
        {
            logger.LogWarning("Could not secure data directory {Dir}: {Error}", DataDirectory, ex.Message);
        }
    }

    public string DataDirectory { get; }
    public string DatabasePath => Path.Combine(DataDirectory, "networkwatch.db");
    public string LogDirectory => Path.Combine(DataDirectory, "logs");
    public string FeedCacheDirectory => Path.Combine(DataDirectory, "feeds");
    public string CustomIndicatorsPath => Path.Combine(DataDirectory, "custom-indicators.txt");
    public string GeoDirectory => Path.Combine(DataDirectory, "geo");

    /// <summary>Only executables under this folder (admin-writable only) may send mutating API commands.</summary>
    public static string InstallDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NetworkWatch");
}
