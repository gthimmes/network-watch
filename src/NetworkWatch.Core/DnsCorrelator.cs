using System.Collections.Concurrent;
using System.Net;

namespace NetworkWatch.Core;

public sealed record DnsEntry(string Name, DateTimeOffset Time, int Pid);

/// <summary>
/// Remembers which domain name each IP address was resolved from, so a raw
/// connection to 142.250.80.46 can be shown as www.google.com. An IP with no
/// entry means the process connected without a DNS lookup we observed.
/// </summary>
public sealed class DnsCorrelator
{
    private readonly ConcurrentDictionary<IPAddress, DnsEntry> _byAddress = new();

    public int Count => _byAddress.Count;

    public void Record(DnsResolution resolution)
    {
        var entry = new DnsEntry(resolution.QueryName, resolution.Time, resolution.Pid);
        foreach (var address in resolution.Addresses)
            _byAddress[Normalize(address)] = entry;
    }

    public DnsEntry? Lookup(IPAddress address) =>
        _byAddress.TryGetValue(Normalize(address), out var entry) ? entry : null;

    /// <summary>Drops entries last resolved before <paramref name="cutoff"/>.</summary>
    public void Prune(DateTimeOffset cutoff)
    {
        foreach (var (address, entry) in _byAddress)
            if (entry.Time < cutoff)
                _byAddress.TryRemove(address, out _);
    }

    public static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
