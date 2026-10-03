namespace NetworkWatch.Core.Intel;

public enum FeedFormat
{
    /// <summary>One IP or CIDR per line; '#' and ';' comments.</summary>
    IpList,
    /// <summary>Spamhaus DROP JSON lines: {"cidr":"1.2.3.0/24","sblid":"SBL1"}.</summary>
    SpamhausJson,
    /// <summary>ThreatFox CSV export (ip:port or domain IOCs).</summary>
    ThreatFoxCsv,
    /// <summary>hosts-file format: "127.0.0.1 evil.example".</summary>
    HostsFile,
    /// <summary>Mixed IPs, CIDRs and domains, one per line (custom user list).</summary>
    Mixed,
}

public sealed record FeedDefinition(string Name, string Url, FeedFormat Format, ThreatCategory Category, string Description);

public static class DefaultFeeds
{
    /// <summary>Keyless feeds. All are free for personal/non-commercial use; see each site's terms.</summary>
    public static readonly IReadOnlyList<FeedDefinition> All =
    [
        new("threatfox-ip", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", FeedFormat.ThreatFoxCsv, ThreatCategory.Malware,
            "abuse.ch ThreatFox: malware command-and-control server"),
        new("threatfox-domain", "https://threatfox.abuse.ch/export/csv/domains/recent/", FeedFormat.ThreatFoxCsv, ThreatCategory.Malware,
            "abuse.ch ThreatFox: malware domain"),
        new("urlhaus-hosts", "https://urlhaus.abuse.ch/downloads/hostfile/", FeedFormat.HostsFile, ThreatCategory.Malware,
            "abuse.ch URLhaus: site distributing malware"),
        new("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", FeedFormat.IpList, ThreatCategory.Malware,
            "abuse.ch Feodo Tracker: botnet command-and-control server"),
        new("spamhaus-drop-v4", "https://www.spamhaus.org/drop/drop_v4.json", FeedFormat.SpamhausJson, ThreatCategory.BadNetwork,
            "Spamhaus DROP: network controlled by criminals (\"Don't Route Or Peer\")"),
        new("spamhaus-drop-v6", "https://www.spamhaus.org/drop/drop_v6.json", FeedFormat.SpamhausJson, ThreatCategory.BadNetwork,
            "Spamhaus DROP: network controlled by criminals (\"Don't Route Or Peer\")"),
        new("tor-exits", "https://check.torproject.org/torbulkexitlist", FeedFormat.IpList, ThreatCategory.Tor,
            "Tor exit relay"),
    ];
}

public static class FeedParser
{
    /// <summary>Parses feed content into the builder. Returns the number of indicators added.</summary>
    public static int Parse(FeedDefinition feed, string content, ThreatIntelBuilder builder)
    {
        var added = 0;
        foreach (var rawLine in content.AsSpan().EnumerateLines())
        {
            var line = rawLine.Trim();
            if (line.IsEmpty || line[0] == '#' || line[0] == ';') continue;
            if (ParseLine(feed, line.ToString(), builder)) added++;
        }
        return added;
    }

    private static bool ParseLine(FeedDefinition feed, string line, ThreatIntelBuilder builder)
    {
        switch (feed.Format)
        {
            case FeedFormat.IpList:
                return builder.AddNetwork(StripComment(line), new ThreatIndicator(feed.Name, feed.Category, feed.Description));

            case FeedFormat.SpamhausJson:
            {
                var cidr = JsonField(line, "cidr");
                var sbl = JsonField(line, "sblid");
                return cidr is not null && builder.AddNetwork(cidr,
                    new ThreatIndicator(feed.Name, feed.Category, sbl is null ? feed.Description : $"{feed.Description}, {sbl}"));
            }

            case FeedFormat.HostsFile:
            {
                var parts = StripComment(line).Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                return parts.Length >= 2 && builder.AddDomain(parts[1], new ThreatIndicator(feed.Name, feed.Category, feed.Description));
            }

            case FeedFormat.ThreatFoxCsv:
            {
                // "first_seen","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias",
                // "malware_printable","last_seen","confidence_level","is_compromised",...
                var fields = SplitQuotedCsv(line);
                if (fields.Count < 11) return false;
                var (value, type, malware) = (fields[2], fields[3], fields[7]);
                var compromised = fields[10].Equals("True", StringComparison.OrdinalIgnoreCase);
                var description = string.IsNullOrEmpty(malware) || malware == "None" ? feed.Description : $"{feed.Description} ({malware})";
                var indicator = new ThreatIndicator(feed.Name, feed.Category, description, compromised);
                return type switch
                {
                    "ip:port" => builder.AddNetwork(value[..Math.Max(0, value.LastIndexOf(':'))], indicator),
                    "domain" => builder.AddDomain(value, indicator),
                    _ => false,
                };
            }

            case FeedFormat.Mixed:
            {
                var value = StripComment(line);
                var indicator = new ThreatIndicator(feed.Name, feed.Category, feed.Description);
                return builder.AddNetwork(value, indicator) || builder.AddDomain(value, indicator);
            }
        }
        return false;
    }

    private static string StripComment(string line)
    {
        var cut = line.IndexOfAny(['#', ';']);
        return (cut >= 0 ? line[..cut] : line).Trim();
    }

    private static string? JsonField(string line, string name)
    {
        var key = $"\"{name}\":\"";
        var start = line.IndexOf(key, StringComparison.Ordinal);
        if (start < 0) return null;
        start += key.Length;
        var end = line.IndexOf('"', start);
        return end > start ? line[start..end] : null;
    }

    internal static List<string> SplitQuotedCsv(string line)
    {
        var fields = new List<string>();
        var i = 0;
        while (i < line.Length)
        {
            while (i < line.Length && line[i] is ' ' or ',') i++;
            if (i >= line.Length) break;
            if (line[i] == '"')
            {
                var end = line.IndexOf('"', i + 1);
                if (end < 0) end = line.Length;
                fields.Add(line[(i + 1)..end]);
                i = end + 1;
            }
            else
            {
                var end = line.IndexOf(',', i);
                if (end < 0) end = line.Length;
                fields.Add(line[i..end].Trim());
                i = end;
            }
        }
        return fields;
    }
}
