using System.Net;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Parses the QueryResults string from Microsoft-Windows-DNS-Client event 3008, e.g.
/// <c>"type:  5 www.google.com;::ffff:142.250.80.46;2607:f8b0:4006:80f::2004;"</c>.
/// CNAME entries ("type: N name") are skipped; only addresses are returned.
/// </summary>
public static class DnsResultParser
{
    public static IReadOnlyList<IPAddress> Parse(string? queryResults)
    {
        if (string.IsNullOrWhiteSpace(queryResults))
            return [];

        var addresses = new List<IPAddress>();
        foreach (var part in queryResults.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
                continue;
            if (IPAddress.TryParse(part, out var address))
                addresses.Add(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address);
        }
        return addresses;
    }
}
