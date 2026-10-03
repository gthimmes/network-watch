namespace NetworkWatch.Core;

/// <summary>
/// Holds items for a fixed time after they arrive before releasing them, in arrival order.
/// Used to delay connection events so the DNS answer that preceded them, which may be
/// delivered later by a separate trace session, has time to reach the <see cref="DnsCorrelator"/>.
/// Not thread-safe; use from the single pipeline reader.
/// </summary>
public sealed class ReorderBuffer<T>(TimeSpan hold)
{
    private readonly Queue<(DateTimeOffset Arrived, T Item)> _queue = new();

    public int Count => _queue.Count;

    public void Add(T item, DateTimeOffset now) => _queue.Enqueue((now, item));

    public IEnumerable<T> DrainReady(DateTimeOffset now)
    {
        while (_queue.TryPeek(out var head) && now - head.Arrived >= hold)
            yield return _queue.Dequeue().Item;
    }

    public IEnumerable<T> DrainAll()
    {
        while (_queue.TryDequeue(out var entry))
            yield return entry.Item;
    }
}
