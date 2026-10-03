using Microsoft.Extensions.Logging;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core;

/// <summary>Delivery target for new alerts (tray clients, logs, webhooks...). Must not block.</summary>
public interface IAlertSink
{
    void Publish(Alert alert);
}

/// <summary>
/// Applies trust rules, merges repeats of the same alert within the dedup window
/// (incrementing its count instead of re-notifying), persists, and fans out to sinks.
/// </summary>
public sealed class AlertManager
{
    private readonly AlertStore _store;
    private readonly Baseline _baseline;
    private readonly ILogger _logger;
    private readonly TimeSpan _dedupWindow;
    private readonly Dictionary<string, (long Id, DateTimeOffset LastSeen)> _recent = [];
    private readonly List<IAlertSink> _sinks = [];
    private readonly Lock _lock = new();

    public AlertManager(AlertStore store, Baseline baseline, ILogger logger, DateTimeOffset now, TimeSpan? dedupWindow = null)
    {
        _store = store;
        _baseline = baseline;
        _logger = logger;
        _dedupWindow = dedupWindow ?? TimeSpan.FromHours(24);
        foreach (var (key, id, lastSeen) in store.RecentKeys(now - _dedupWindow))
            _recent[key] = (id, lastSeen);
    }

    public void AddSink(IAlertSink sink)
    {
        lock (_lock) _sinks.Add(sink);
    }

    /// <summary>Returns the stored alert if it was new and delivered, null if suppressed or merged.</summary>
    public Alert? Raise(Alert candidate, bool respectsTrust, DateTimeOffset now)
    {
        if (respectsTrust && candidate.ProcessName is not null &&
            _baseline.IsTrusted(AppKeys.For(candidate.ProcessName, candidate.ProcessPath), candidate.DetectorId))
            return null;

        IAlertSink[] sinks;
        Alert stored;
        lock (_lock)
        {
            if (_recent.TryGetValue(candidate.DedupKey, out var previous) && now - previous.LastSeen < _dedupWindow)
            {
                _store.Touch(previous.Id, now);
                _recent[candidate.DedupKey] = (previous.Id, now);
                return null;
            }

            var id = _store.Insert(candidate);
            stored = candidate with { Id = id };
            _recent[candidate.DedupKey] = (id, now);
            sinks = [.. _sinks];
        }

        _logger.Log(stored.Severity == Severity.High ? LogLevel.Warning : LogLevel.Information,
            "Alert {Id} [{Severity}] {Title}: {What}", stored.Id, stored.Severity, stored.Title, stored.WhatHappened);
        foreach (var sink in sinks)
        {
            try { sink.Publish(stored); }
            catch (Exception ex) { _logger.LogWarning(ex, "Alert sink {Sink} failed", sink.GetType().Name); }
        }
        return stored;
    }

    public void PruneDedup(DateTimeOffset now)
    {
        lock (_lock)
            foreach (var (key, value) in _recent)
                if (now - value.LastSeen >= _dedupWindow)
                    _recent.Remove(key);
    }
}
