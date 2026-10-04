using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core;

public sealed class PipelineStats
{
    public long EventsProcessed;
    public long ConnectionsSeen;
    public long FlowsStored;
    public long DnsResolutions;
    public DateTimeOffset? LastEvent;
}

/// <summary>
/// The engine: collector events in, alerts out.
/// connections → (UDP de-dup) → reorder buffer → DNS correlation, signature, threat intel →
/// baseline + storage → detectors → <see cref="AlertManager"/>.
/// Single-threaded: call <see cref="Process"/>/<see cref="Flush"/> from one thread, or use <see cref="RunAsync"/>.
/// </summary>
public sealed class NetworkPipeline
{
    /// <summary>DNS events arrive up to ~3 s after the connections they explain (separate ETW session).</summary>
    public static readonly TimeSpan ReorderHold = TimeSpan.FromSeconds(5);

    private readonly Baseline _baseline;
    private readonly AlertManager _alerts;
    private readonly ConnectionStore? _connections;
    private readonly Func<ThreatIntel> _intel;
    private readonly ISignatureVerifier _signatures;
    private readonly IReadOnlyList<Detector> _detectors;
    private readonly ILogger _logger;
    private readonly DnsCorrelator _dns = new();
    private readonly FlowTracker _flows = new(TimeSpan.FromMinutes(2));
    private readonly ReorderBuffer<(ConnectionEvent Conn, AddressScope Scope, bool IsNewFlow)> _pending = new(ReorderHold);
    private readonly DateTimeOffset _startedAt;
    private readonly UsageStore? _usage;
    private readonly Func<System.Net.IPAddress, GeoInfo?> _geo;
    private DateTimeOffset _lastHousekeeping;

    public NetworkPipeline(
        Baseline baseline,
        AlertManager alerts,
        ConnectionStore? connections,
        Func<ThreatIntel> intel,
        ISignatureVerifier signatures,
        IReadOnlyList<Detector> detectors,
        ILogger logger,
        DateTimeOffset startedAt,
        UsageStore? usage = null,
        Func<System.Net.IPAddress, GeoInfo?>? geo = null)
    {
        _baseline = baseline;
        _alerts = alerts;
        _connections = connections;
        _intel = intel;
        _signatures = signatures;
        _detectors = detectors;
        _logger = logger;
        _startedAt = startedAt;
        _lastHousekeeping = startedAt;
        _usage = usage;
        _geo = geo ?? (_ => null);
    }

    public PipelineStats Stats { get; } = new();

    public async Task RunAsync(ChannelReader<NetEvent> reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var wait = reader.WaitToReadAsync(ct).AsTask();
            var completed = await Task.WhenAny(wait, Task.Delay(500, ct)).ConfigureAwait(false);
            if (completed == wait && !await wait.ConfigureAwait(false)) break; // channel completed

            while (reader.TryRead(out var ev))
                SafeProcess(ev, DateTimeOffset.Now);
            SafeFlush(DateTimeOffset.Now, all: false);
        }

        // Late DNS answers may still be queued; use them before flushing what's pending.
        while (reader.TryRead(out var late))
            if (late is DnsResolution) SafeProcess(late, DateTimeOffset.Now);
        SafeFlush(DateTimeOffset.Now, all: true);
    }

    private void SafeProcess(NetEvent ev, DateTimeOffset now)
    {
        try { Process(ev, now); }
        catch (Exception ex) { _logger.LogError(ex, "Pipeline failed on {EventType}", ev.GetType().Name); }
    }

    private void SafeFlush(DateTimeOffset now, bool all)
    {
        try { Flush(now, all); }
        catch (Exception ex) { _logger.LogError(ex, "Pipeline flush failed"); }
    }

    public void Process(NetEvent ev, DateTimeOffset now)
    {
        Stats.EventsProcessed++;
        Stats.LastEvent = now;
        switch (ev)
        {
            case DnsResolution dns:
                Stats.DnsResolutions++;
                _dns.Record(dns);
                RunDetectors(now, d => d.OnDns(dns, Context(now)));
                break;

            case ConnectionEvent c:
                Stats.ConnectionsSeen++;
                var scope = IpClassifier.Classify(c.Remote.Address);
                if (scope is AddressScope.Loopback or AddressScope.Unspecified or AddressScope.Multicast or AddressScope.Broadcast)
                    break;
                var isNew = _flows.IsNew(c);
                // UDP events are per datagram; only the first of a flow matters. TCP connects/accepts are
                // per connection and all of them are kept (beacon detection needs every connect).
                if (c.Protocol == Protocol.Udp && !isNew) break;
                _pending.Add((c, scope, isNew), now);
                break;

            case ListenerSnapshot snapshot:
                RunDetectors(now, d => d.OnListeners(snapshot, Context(now)));
                break;

            case EnvironmentObservation observation:
                RunDetectors(now, d => d.OnEnvironment(observation, Context(now)));
                break;

            case TrafficSample sample:
                var key = AppKeys.For(sample.ProcessName, sample.ProcessPath);
                _usage?.Add(key, sample.ProcessName, sample.Time, sample.BytesSent, sample.BytesReceived);
                var traffic = new EnrichedTraffic(sample, key, _signatures.Verify(sample.ProcessPath));
                RunDetectors(now, d => d.OnTraffic(traffic, Context(now)));
                break;
        }
    }

    public void Flush(DateTimeOffset now, bool all = false)
    {
        foreach (var (c, scope, isNew) in all ? _pending.DrainAll() : _pending.DrainReady(now))
            HandleConnection(c, scope, isNew, now);

        if (now - _lastHousekeeping >= TimeSpan.FromMinutes(1))
        {
            _lastHousekeeping = now;
            _flows.Prune(now);
            _dns.Prune(now - TimeSpan.FromHours(6));
            _alerts.PruneDedup(now);
            _usage?.Flush();
            var ctx = Context(now);
            foreach (var detector in _detectors) detector.OnTick(ctx);
        }
    }

    private void HandleConnection(ConnectionEvent c, AddressScope scope, bool isNewFlow, DateTimeOffset now)
    {
        var domain = _dns.Lookup(c.Remote.Address)?.Name;
        var signature = _signatures.Verify(c.ProcessPath);
        var intel = _intel();
        var threat = intel.Lookup(c.Remote.Address) ?? intel.LookupDomain(domain);
        var appKey = AppKeys.For(c.ProcessName, c.ProcessPath);
        var isNewApp = isNewFlow && _baseline.TouchApp(appKey, c.ProcessName, c.ProcessPath, signature.Signer, now);

        var geo = scope == AddressScope.Public && isNewFlow ? _geo(c.Remote.Address) : null;
        var enriched = new EnrichedConnection(c, scope, domain, signature, threat, isNewFlow, isNewApp, appKey, geo);
        if (isNewFlow && _connections is not null)
        {
            _connections.Insert(enriched);
            Stats.FlowsStored++;
        }
        RunDetectors(now, d => d.OnConnection(enriched, Context(now)));
    }

    private DetectionContext Context(DateTimeOffset now) => new(now, _intel(), _baseline, _startedAt);

    private void RunDetectors(DateTimeOffset now, Func<Detector, IEnumerable<Alert>> hook)
    {
        foreach (var detector in _detectors)
        {
            try
            {
                foreach (var alert in hook(detector))
                    _alerts.Raise(alert, detector.RespectsTrust, now);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Detector {Detector} failed", detector.Id);
            }
        }
    }
}
