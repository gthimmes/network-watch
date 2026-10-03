using System.Net;
using NetworkWatch.Core.Intel;

namespace NetworkWatch.Core.Tests;

public class ThreatIntelTests
{
    private static readonly ThreatIndicator Bad = new("test", ThreatCategory.Malware, "test feed");

    [Fact]
    public void MatchesExactIpsAndCidrRanges()
    {
        var b = new ThreatIntelBuilder();
        b.AddNetwork("203.0.113.7", Bad);
        b.AddNetwork("198.51.100.0/24", Bad);
        b.AddNetwork("2001:db8:abcd::/48", Bad);
        var intel = b.Build();

        Assert.NotNull(intel.Lookup(IPAddress.Parse("203.0.113.7")));
        Assert.Null(intel.Lookup(IPAddress.Parse("203.0.113.8")));
        Assert.NotNull(intel.Lookup(IPAddress.Parse("198.51.100.255")));
        Assert.Null(intel.Lookup(IPAddress.Parse("198.51.101.0")));
        Assert.NotNull(intel.Lookup(IPAddress.Parse("::ffff:198.51.100.9")));
        Assert.NotNull(intel.Lookup(IPAddress.Parse("2001:db8:abcd:12::1")));
        Assert.Null(intel.Lookup(IPAddress.Parse("2001:db8:abce::1")));
    }

    [Fact]
    public void DomainMatchesIncludeSubdomainsButNotParents()
    {
        var b = new ThreatIntelBuilder();
        b.AddDomain("evil.example", Bad);
        var intel = b.Build();

        Assert.NotNull(intel.LookupDomain("evil.example"));
        Assert.NotNull(intel.LookupDomain("cdn.EVIL.example."));
        Assert.Null(intel.LookupDomain("example"));
        Assert.Null(intel.LookupDomain("notevil.example"));
        Assert.Null(intel.LookupDomain(null));
    }

    [Fact]
    public void ParsesThreatFoxCsv()
    {
        var feed = DefaultFeeds.All.Single(f => f.Name == "threatfox-ip");
        var csv = """
            # "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
            "2026-10-03 19:45:07", "1949016", "5.175.169.209:56001", "ip:port", "botnet_cc", "win.pure_rat", "PureHVNC", "PureRAT", "", "75", "False", "None", "RAT", "0", "abuse_ch"
            "2026-10-03 19:28:43", "1949001", "zepaho.workers.dev", "domain", "botnet_cc", "php.shin", "None", "php.shin_webshell", "", "50", "True", "None", "x", "0", "xscon"
            """;
        var b = new ThreatIntelBuilder();

        Assert.Equal(2, FeedParser.Parse(feed, csv, b));
        var intel = b.Build();
        Assert.Contains("PureRAT", intel.Lookup(IPAddress.Parse("5.175.169.209"))!.Description);
        Assert.True(intel.LookupDomain("zepaho.workers.dev")!.Compromised);
        Assert.Null(intel.LookupDomain("workers.dev"));
    }

    [Fact]
    public void ParsesSpamhausHostsAndIpLists()
    {
        var b = new ThreatIntelBuilder();
        Assert.Equal(1, FeedParser.Parse(DefaultFeeds.All.Single(f => f.Name == "spamhaus-drop-v4"),
            """{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}""" + "\n" + """{"type":"metadata","timestamp":1}""", b));
        Assert.Equal(1, FeedParser.Parse(DefaultFeeds.All.Single(f => f.Name == "urlhaus-hosts"),
            "# comment\n127.0.0.1\t123.ywxww.net\n", b));
        Assert.Equal(2, FeedParser.Parse(DefaultFeeds.All.Single(f => f.Name == "feodo"),
            "#####\n162.243.103.246\n178.62.3.223\n", b));
        Assert.Equal(3, FeedParser.Parse(Intel.FeedManager.CustomFeed, "10.9.9.9 # note\nbad.example\n192.0.2.0/28\n", b));
        var intel = b.Build();

        Assert.Contains("SBL256894", intel.Lookup(IPAddress.Parse("1.10.31.1"))!.Description);
        Assert.NotNull(intel.LookupDomain("123.ywxww.net"));
        Assert.NotNull(intel.Lookup(IPAddress.Parse("178.62.3.223")));
        Assert.Equal(ThreatCategory.Custom, intel.LookupDomain("bad.example")!.Category);
        Assert.NotNull(intel.Lookup(IPAddress.Parse("192.0.2.15")));
        Assert.Equal(7, intel.TotalIndicators);
    }
}
