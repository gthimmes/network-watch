using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Api;

/// <summary>Transport-independent command handling for the local API.</summary>
public sealed class ApiHandler(
    AlertStore alerts,
    ConnectionStore connections,
    Baseline baseline,
    IEnforcer? enforcer,
    Func<StatusDto> status,
    Func<CancellationToken, Task> refreshFeeds)
{
    public async Task<object?> HandleAsync(ApiRequest request, bool trustedClient, CancellationToken ct)
    {
        if (ApiCommands.Mutating.Contains(request.Cmd) && !trustedClient)
            throw new ApiException($"'{request.Cmd}' is only allowed from Network Watch's installed tray app or CLI.");

        var limit = Math.Clamp(request.Limit ?? 100, 1, 5000);
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

            case ApiCommands.EndLearning:
                baseline.EndLearning(DateTimeOffset.Now);
                return status();

            case ApiCommands.RestartLearning:
                baseline.RestartLearning(DateTimeOffset.Now);
                return status();

            case ApiCommands.RefreshFeeds:
                await refreshFeeds(ct).ConfigureAwait(false);
                return status();

            default:
                throw new ApiException($"Unknown command '{request.Cmd}'.");
        }
    }

    private Alert RequireAlert(ApiRequest request) =>
        alerts.Get(request.AlertId ?? throw new ApiException("alertId is required."))
            ?? throw new ApiException($"Alert {request.AlertId} not found.");

    private IEnforcer RequireEnforcer() => enforcer ?? throw new ApiException("Blocking isn't available on this system.");
}
