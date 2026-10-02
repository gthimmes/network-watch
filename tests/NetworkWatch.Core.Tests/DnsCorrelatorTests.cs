using System.Net;
using NetworkWatch.Core;

namespace NetworkWatch.Core.Tests;

public class DnsCorrelatorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void MapsEveryResolvedAddressBackToTheQueryName()
    {
        var dns = new DnsCorrelator();
        dns.Record(new DnsResolution(T0, 42, "example.com", [IPAddress.Parse("93.184.216.34"), IPAddress.Parse("2606:2800:220:1::")]));

        Assert.Equal("example.com", dns.Lookup(IPAddress.Parse("93.184.216.34"))?.Name);
        Assert.Equal("example.com", dns.Lookup(IPAddress.Parse("2606:2800:220:1::"))?.Name);
        Assert.Null(dns.Lookup(IPAddress.Parse("1.1.1.1")));
    }

    [Fact]
    public void TreatsIpv4MappedAddressesAsIpv4()
    {
        var dns = new DnsCorrelator();
        dns.Record(new DnsResolution(T0, 1, "example.com", [IPAddress.Parse("93.184.216.34")]));

        Assert.Equal("example.com", dns.Lookup(IPAddress.Parse("::ffff:93.184.216.34"))?.Name);
    }

    [Fact]
    public void LatestResolutionWins()
    {
        var dns = new DnsCorrelator();
        var ip = IPAddress.Parse("104.16.0.1");
        dns.Record(new DnsResolution(T0, 1, "a.example", [ip]));
        dns.Record(new DnsResolution(T0.AddSeconds(5), 1, "b.example", [ip]));

        Assert.Equal("b.example", dns.Lookup(ip)?.Name);
    }

    [Fact]
    public void PruneDropsOldEntries()
    {
        var dns = new DnsCorrelator();
        dns.Record(new DnsResolution(T0, 1, "old.example", [IPAddress.Parse("1.2.3.4")]));
        dns.Record(new DnsResolution(T0.AddHours(2), 1, "new.example", [IPAddress.Parse("5.6.7.8")]));

        dns.Prune(T0.AddHours(1));

        Assert.Null(dns.Lookup(IPAddress.Parse("1.2.3.4")));
        Assert.NotNull(dns.Lookup(IPAddress.Parse("5.6.7.8")));
    }
}
