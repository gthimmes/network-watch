using System.Threading.Channels;
using NetworkWatch.Collectors.Windows;
using NetworkWatch.Core;

namespace NetworkWatch.Service;

/// <summary>Runs the collectors and feeds their events through the pipeline.</summary>
public sealed class MonitorWorker(Engine engine, ILogger<MonitorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        logger.LogInformation("Network Watch {Version} starting. Data: {Data}. Learning until {LearningEnds:g}.",
            Engine.Version, engine.Paths.DataDirectory, engine.Baseline.LearningEndsAt);

        var channel = Channel.CreateBounded<NetEvent>(new BoundedChannelOptions(200_000)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.DropOldest,
        });

        ICollector[] collectors =
        [
            new EtwNetworkCollector(engine.Processes, "NetworkWatch-Service-Kernel", "NetworkWatch-Service-Dns"),
            new ListenerCollector(engine.Processes),
            new EnvironmentCollector(),
        ];
        var running = collectors.Select(c => RunCollector(c, channel.Writer, ct)).ToList();

        await engine.Pipeline.RunAsync(channel.Reader, ct).ConfigureAwait(false);
        await Task.WhenAll(running).ConfigureAwait(false);
        logger.LogInformation("Network Watch stopped.");
    }

    private async Task RunCollector(ICollector collector, ChannelWriter<NetEvent> sink, CancellationToken ct)
    {
        // Restart a failing collector with backoff; one broken source shouldn't stop the others.
        var delay = TimeSpan.FromSeconds(5);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                logger.LogInformation("Collector {Collector} starting", collector.Name);
                await collector.RunAsync(sink, ct).ConfigureAwait(false);
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                var message = $"{DateTimeOffset.Now:g} {collector.Name}: {ex.Message}";
                lock (engine.CollectorErrors)
                {
                    engine.CollectorErrors.Add(message);
                    if (engine.CollectorErrors.Count > 20) engine.CollectorErrors.RemoveAt(0);
                }
                logger.LogError(ex, "Collector {Collector} failed; restarting in {Delay}", collector.Name, delay);
                await Task.Delay(delay, ct).ConfigureAwait(false);
                delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 300));
            }
        }
    }
}

/// <summary>Loads cached threat intel at startup, then refreshes stale feeds every hour (each feed max every 6 h).</summary>
public sealed class FeedWorker(Engine engine, ILogger<FeedWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        engine.Feeds.LoadFromCache();
        engine.Geo.Load();
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                await engine.Feeds.RefreshAsync(TimeSpan.FromHours(6), ct).ConfigureAwait(false);
                await engine.Geo.RefreshAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Feed refresh failed");
            }
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }
}

/// <summary>Retention: connections 30 days, alerts 90 days.</summary>
public sealed class MaintenanceWorker(Engine engine, ILogger<MaintenanceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(6));
        do
        {
            try
            {
                var now = DateTimeOffset.Now;
                engine.Database.Prune(now.AddDays(-30), now.AddDays(-90));
                FileLoggerProvider.DeleteOldLogs(engine.Paths.LogDirectory, TimeSpan.FromDays(14));
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Maintenance failed");
            }
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }
}
