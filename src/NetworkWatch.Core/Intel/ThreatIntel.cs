using System.Net;
using System.Net.Sockets;

namespace NetworkWatch.Core.Intel;

public enum ThreatCategory
{
    /// <summary>Known malware command-and-control or distribution infrastructure.</summary>
    Malware,
    /// <summary>Network ranges run by criminals (e.g. Spamhaus DROP).</summary>
    BadNetwork,
    /// <summary>Tor exit relay: not malicious by itself, but notable for inbound traffic.</summary>
    Tor,
    /// <summary>User-supplied indicator.</summary>
    Custom,
}

public sealed record ThreatIndicator(string Source, ThreatCategory Category, string Description, bool Compromised = false);

/// <summary>Immutable snapshot of all loaded indicators. Swapped atomically on refresh.</summary>
public sealed class ThreatIntel
{
    public static readonly ThreatIntel Empty = new ThreatIntelBuilder().Build();

    private readonly Dictionary<int, Dictionary<UInt128, ThreatIndicator>> _v4ByPrefix;
    private readonly Dictionary<int, Dictionary<UInt128, ThreatIndicator>> _v6ByPrefix;
    private readonly Dictionary<string, ThreatIndicator> _domains;

    internal ThreatIntel(
        Dictionary<int, Dictionary<UInt128, ThreatIndicator>> v4,
        Dictionary<int, Dictionary<UInt128, ThreatIndicator>> v6,
        Dictionary<string, ThreatIndicator> domains,
        IReadOnlyDictionary<string, int> countsBySource)
    {
        _v4ByPrefix = v4;
        _v6ByPrefix = v6;
        _v4Prefixes = [.. v4.Keys.OrderDescending()];
        _v6Prefixes = [.. v6.Keys.OrderDescending()];
        _domains = domains;
        CountsBySource = countsBySource;
    }

    private readonly int[] _v4Prefixes;
    private readonly int[] _v6Prefixes;

    public IReadOnlyDictionary<string, int> CountsBySource { get; }

    public int TotalIndicators => CountsBySource.Values.Sum();

    public ThreatIndicator? Lookup(IPAddress address)
    {
        address = DnsCorrelator.Normalize(address);
        var isV4 = address.AddressFamily == AddressFamily.InterNetwork;
        var (table, prefixes, bits) = isV4 ? (_v4ByPrefix, _v4Prefixes, 32) : (_v6ByPrefix, _v6Prefixes, 128);
        var value = ToUInt128(address);

        // Most specific match wins: try longest prefixes first.
        foreach (var prefix in prefixes)
            if (table[prefix].TryGetValue(Mask(value, prefix, bits), out var indicator))
                return indicator;
        return null;
    }

    /// <summary>Exact host match, then parent domains (a listed "evil.example" also matches "x.evil.example").</summary>
    public ThreatIndicator? LookupDomain(string? name)
    {
        if (string.IsNullOrEmpty(name)) return null;
        var host = name.TrimEnd('.');
        while (true)
        {
            if (_domains.TryGetValue(host, out var indicator))
                return indicator;
            var dot = host.IndexOf('.');
            // Stop before testing a bare TLD.
            if (dot < 0 || host.IndexOf('.', dot + 1) < 0) return null;
            host = host[(dot + 1)..];
        }
    }

    internal static UInt128 ToUInt128(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out var written);
        UInt128 value = 0;
        for (var i = 0; i < written; i++)
            value = (value << 8) | bytes[i];
        return value;
    }

    internal static UInt128 Mask(UInt128 value, int prefix, int bits) =>
        prefix == 0 ? 0 : value & (UInt128.MaxValue << (bits - prefix)) & (bits == 128 ? UInt128.MaxValue : (UInt128.One << bits) - 1);
}

public sealed class ThreatIntelBuilder
{
    private readonly Dictionary<int, Dictionary<UInt128, ThreatIndicator>> _v4 = [];
    private readonly Dictionary<int, Dictionary<UInt128, ThreatIndicator>> _v6 = [];
    private readonly Dictionary<string, ThreatIndicator> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _counts = [];

    /// <summary>Adds an IP ("1.2.3.4") or CIDR ("1.2.3.0/24"). Returns false if unparseable.</summary>
    public bool AddNetwork(string text, ThreatIndicator indicator)
    {
        var slash = text.IndexOf('/');
        var addressPart = slash >= 0 ? text[..slash] : text;
        if (!IPAddress.TryParse(addressPart.Trim(), out var address)) return false;
        address = DnsCorrelator.Normalize(address);

        var isV4 = address.AddressFamily == AddressFamily.InterNetwork;
        var bits = isV4 ? 32 : 128;
        var prefix = bits;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..].Trim(), out prefix) || prefix < 0 || prefix > bits))
            return false;

        var table = isV4 ? _v4 : _v6;
        if (!table.TryGetValue(prefix, out var byNetwork))
            table[prefix] = byNetwork = [];
        byNetwork.TryAdd(ThreatIntel.Mask(ThreatIntel.ToUInt128(address), prefix, bits), indicator);
        Count(indicator);
        return true;
    }

    public bool AddDomain(string domain, ThreatIndicator indicator)
    {
        domain = domain.Trim().TrimEnd('.');
        if (domain.Length == 0 || domain.Contains(' ') || !domain.Contains('.')) return false;
        if (IPAddress.TryParse(domain, out _)) return AddNetwork(domain, indicator);
        _domains.TryAdd(domain, indicator);
        Count(indicator);
        return true;
    }

    private void Count(ThreatIndicator indicator) =>
        _counts[indicator.Source] = _counts.GetValueOrDefault(indicator.Source) + 1;

    public ThreatIntel Build() => new(_v4, _v6, _domains, new Dictionary<string, int>(_counts));
}
