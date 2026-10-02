using System.Net;

namespace NetworkWatch.Core;

public readonly record struct FlowKey(int Pid, Protocol Protocol, Direction Direction, IPAddress RemoteAddress, int RemotePort);

/// <summary>
/// Collapses the stream of per-packet/per-connect events into flows: reports a
/// flow as new only if it hasn't been seen within the idle window.
/// </summary>
public sealed class FlowTracker(TimeSpan idleWindow)
{
    private readonly Dictionary<FlowKey, DateTimeOffset> _lastSeen = [];
    private readonly Lock _lock = new();

    public int ActiveFlows { get { lock (_lock) return _lastSeen.Count; } }

    public bool IsNew(ConnectionEvent e)
    {
        var key = new FlowKey(e.Pid, e.Protocol, e.Direction, DnsCorrelator.Normalize(e.Remote.Address), e.Remote.Port);
        lock (_lock)
        {
            var isNew = !_lastSeen.TryGetValue(key, out var last) || e.Time - last >= idleWindow;
            _lastSeen[key] = e.Time;
            return isNew;
        }
    }

    public void Prune(DateTimeOffset now)
    {
        lock (_lock)
        {
            foreach (var (key, last) in _lastSeen)
                if (now - last >= idleWindow)
                    _lastSeen.Remove(key);
        }
    }
}
