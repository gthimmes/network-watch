using System.Threading.Channels;

namespace NetworkWatch.Core;

/// <summary>
/// OS-specific source of network/process telemetry. Implementations live in
/// NetworkWatch.Collectors.&lt;OS&gt; and write normalized events into the sink.
/// </summary>
public interface ICollector
{
    string Name { get; }

    /// <summary>Runs until <paramref name="ct"/> is cancelled.</summary>
    Task RunAsync(ChannelWriter<NetEvent> sink, CancellationToken ct);
}
