using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Threading.Channels;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Watches the Security event log for remote sign-ins: 4624 (success) and 4625 (failure) with logon type 3
/// (network) or 10 (Remote Desktop). At startup, replays the last week as historical events so existing
/// remote-access patterns are learned instead of alerted. Requires SYSTEM/admin (Security log).
/// Windows audits logon success and failure by default.
/// </summary>
public sealed class RemoteLogonCollector(TimeSpan? backfill = null) : ICollector
{
    private readonly TimeSpan _backfill = backfill ?? TimeSpan.FromDays(7);

    private static readonly EventLogPropertySelector Selector = new(
    [
        "Event/EventData/Data[@Name='TargetUserName']",
        "Event/EventData/Data[@Name='TargetDomainName']",
        "Event/EventData/Data[@Name='LogonType']",
        "Event/EventData/Data[@Name='IpAddress']",
        "Event/EventData/Data[@Name='WorkstationName']",
    ]);

    public string Name => "Windows remote sign-ins";

    public static string Query(TimeSpan? within) =>
        "*[System[(EventID=4624 or EventID=4625)" +
        (within is { } w ? $" and TimeCreated[timediff(@SystemTime) <= {(long)w.TotalMilliseconds}]" : "") +
        "]] and *[EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]";

    public async Task RunAsync(ChannelWriter<NetEvent> sink, CancellationToken ct)
    {
        using (var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, Query(_backfill))))
        {
            for (var record = reader.ReadEvent(); record is not null && !ct.IsCancellationRequested; record = reader.ReadEvent())
                using (record)
                    if (Parse(record, historical: true) is { } logon) sink.TryWrite(logon);
        }

        using var watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, Query(null)));
        watcher.EventRecordWritten += (_, e) =>
        {
            if (e.EventRecord is null) return;
            using (e.EventRecord)
                if (Parse(e.EventRecord, historical: false) is { } logon) sink.TryWrite(logon);
        };
        watcher.Enabled = true;
        try { await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        watcher.Enabled = false;
    }

    internal static RemoteLogon? Parse(EventRecord record, bool historical)
    {
        if (record is not EventLogRecord logRecord) return null;
        var values = logRecord.GetPropertyValues(Selector);
        var user = values[0] as string ?? "";
        var domain = values[1] as string;
        var type = Convert.ToInt32(values[2] ?? 0);
        if (values[3] is not string ip || !IPAddress.TryParse(ip, out var source)) return null; // "-" for local logons
        if (user.EndsWith('$')) return null; // computer accounts (domain machine-to-machine traffic)
        return new RemoteLogon(
            new DateTimeOffset(record.TimeCreated ?? DateTime.Now),
            record.Id == 4624,
            string.IsNullOrEmpty(domain) || domain == "-" ? user : $@"{domain}\{user}",
            source,
            type == 10 ? LogonKind.RemoteDesktop : LogonKind.Network,
            values[4] as string,
            historical);
    }
}
