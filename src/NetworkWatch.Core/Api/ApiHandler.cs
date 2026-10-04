using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Api;

public sealed record DigestDto(
    DateTimeOffset Since,
    bool IsLearning,
    DateTimeOffset LearningEndsAt,
    int High,
    int Medium,
    int Info,
    IReadOnlyList<string> NotableAlerts,
    IReadOnlyList<AppRecord> NewPrograms,
    IReadOnlyList<AppUsage> TopTalkers,
    long Connections,
    int BlockedPrograms)
{
    /// <summary>One or two plain sentences for a notification.</summary>
    public string Summary
    {
        get
        {
            var parts = new List<string>();
            parts.Add(High + Medium == 0 ? "Nothing suspicious" : $"{High} high and {Medium} medium alert(s)");
            // While learning, every program is "new"; that's not news.
            if (NewPrograms.Count > 0 && !IsLearning) parts.Add($"{NewPrograms.Count} new program(s) went online");
            if (TopTalkers.Count > 0) parts.Add($"busiest: {TopTalkers[0].ProcessName} ({UploadVolumeDetector.FormatBytes(TopTalkers[0].BytesSent + TopTalkers[0].BytesReceived)})");
            return string.Join("; ", parts) + ".";
        }
    }
}

/// <summary>Transport-independent command handling for the local API.</summary>
public sealed class ApiHandler(
    AlertStore alerts,
    ConnectionStore connections,
    UsageStore usage,
    Baseline baseline,
    FeedManager feeds,
    IEnforcer? enforcer,
    Func<StatusDto> status)
{
    public async Task<object?> HandleAsync(ApiRequest request, bool trustedClient, CancellationToken ct)
    {
        if (ApiCommands.Mutating.Contains(request.Cmd) && !trustedClient)
            throw new ApiException($"'{request.Cmd}' is only allowed from Network Watch's installed tray app or CLI.");

        var limit = Math.Clamp(request.Limit ?? 100, 1, 5000);
        var since = DateTimeOffset.Now.AddHours(-Math.Clamp(request.Hours ?? 24, 1, 24 * 90));
        switch (request.Cmd)
        {
            case ApiCommands.Status:
                return status();

            case ApiCommands.Alerts:
                return alerts.Query(limit, request.MinSeverity ?? Severity.Info, request.AfterId ?? 0);

            case ApiCommands.Alert:
                return RequireAlert(request);

            case ApiCommands.Ack:
                alerts.SetStatus(RequireAlert(request).Id, AlertStatus.Acknowledged);
                return null;

            case ApiCommands.AckAll:
                alerts.AcknowledgeAll();
                return null;

            case ApiCommands.Connections:
                return connections.Recent(limit, request.Search);

            case ApiCommands.Apps:
                return baseline.Apps();

            case ApiCommands.Usage:
                return usage.Totals(since, limit);

            case ApiCommands.Digest:
                return Digest(since);

            case ApiCommands.Trust:
            {
                string appKey;
                var detector = request.DetectorId;
                if (request.AlertId is not null)
                {
                    var alert = RequireAlert(request);
                    appKey = alert.AppKeyOrNull() ?? throw new ApiException("This alert isn't about a specific program.");
                    alerts.SetStatus(alert.Id, AlertStatus.Acknowledged);
                }
                else
                {
                    appKey = request.AppKey ?? throw new ApiException("trust needs alertId or appKey.");
                }
                baseline.Trust(appKey, detector ?? Baseline.AllDetectors);
                return new TrustResult(appKey, detector);
            }

            case ApiCommands.Untrust:
                baseline.Untrust(request.AppKey ?? throw new ApiException("untrust needs appKey."));
                return null;

            case ApiCommands.Block:
            {
                var path = request.ProcessPath;
                if (request.AlertId is not null)
                {
                    var alert = RequireAlert(request);
                    path = alert.ProcessPath ?? throw new ApiException("The program's file path is unknown, so it can't be blocked.");
                    alerts.SetStatus(alert.Id, AlertStatus.Acknowledged);
                }
                if (string.IsNullOrEmpty(path)) throw new ApiException("block needs alertId or processPath.");
                RequireEnforcer().BlockProgram(path);
                return RequireEnforcer().ListRules().Where(r => r.ProcessPath.Equals(path, StringComparison.OrdinalIgnoreCase)).ToList();
            }

            case ApiCommands.Unblock:
                return RequireEnforcer().UnblockProgram(request.ProcessPath ?? throw new ApiException("unblock needs processPath."));

            case ApiCommands.Blocks:
                return RequireEnforcer().ListRules();

            case ApiCommands.Indicators:
                return feeds.CustomIndicators();

            case ApiCommands.AddIndicator:
                try { feeds.AddCustomIndicator(request.Value ?? throw new ApiException("addIndicator needs a value.")); }
                catch (ArgumentException ex) { throw new ApiException(ex.Message); }
                return feeds.CustomIndicators();

            case ApiCommands.RemoveIndicator:
                if (!feeds.RemoveCustomIndicator(request.Value ?? throw new ApiException("removeIndicator needs a value.")))
                    throw new ApiException($"'{request.Value}' isn't on your custom list.");
                return feeds.CustomIndicators();

            case ApiCommands.EndLearning:
                baseline.EndLearning(DateTimeOffset.Now);
                return status();

            case ApiCommands.RestartLearning:
                baseline.RestartLearning(DateTimeOffset.Now);
                return status();

            case ApiCommands.RefreshFeeds:
                await feeds.RefreshAsync(TimeSpan.Zero, ct).ConfigureAwait(false);
                return status();

            default:
                throw new ApiException($"Unknown command '{request.Cmd}'.");
        }
    }

    public DigestDto Digest(DateTimeOffset since)
    {
        var raised = alerts.RaisedSince(since);
        return new DigestDto(
            since,
            baseline.IsLearning(DateTimeOffset.Now),
            baseline.LearningEndsAt,
            raised.Count(a => a.Severity == Severity.High),
            raised.Count(a => a.Severity == Severity.Medium),
            raised.Count(a => a.Severity == Severity.Info),
            raised.Where(a => a.Severity >= Severity.Medium).Take(5).Select(a => $"[{a.Severity}] {a.Title}").ToList(),
            baseline.Apps().Where(a => a.FirstSeen >= since).ToList(),
            usage.Totals(since, 5),
            connections.CountSince(since),
            enforcer?.ListRules().Select(r => r.ProcessPath).Distinct(StringComparer.OrdinalIgnoreCase).Count() ?? 0);
    }

    private Alert RequireAlert(ApiRequest request) =>
        alerts.Get(request.AlertId ?? throw new ApiException("alertId is required."))
            ?? throw new ApiException($"Alert {request.AlertId} not found.");

    private IEnforcer RequireEnforcer() => enforcer ?? throw new ApiException("Blocking isn't available on this system.");
}
