using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core.Api;

/// <summary>
/// Local API: newline-delimited JSON over a named pipe (Windows) / Unix socket (later).
/// Each request line gets exactly one response line with the same id. After "subscribe",
/// the server instead pushes one <see cref="ApiPush"/> line per new alert.
/// </summary>
public static class ApiCommands
{
    public const string Status = "status";
    public const string Alerts = "alerts";
    public const string Alert = "alert";
    public const string Ack = "ack";
    public const string AckAll = "ackAll";
    public const string Connections = "connections";
    public const string Apps = "apps";
    public const string Trust = "trust";
    public const string Untrust = "untrust";
    public const string Block = "block";
    public const string Unblock = "unblock";
    public const string Blocks = "blocks";
    public const string EndLearning = "endLearning";
    public const string RestartLearning = "restartLearning";
    public const string RefreshFeeds = "refreshFeeds";
    public const string Subscribe = "subscribe";
    public const string Indicators = "indicators";
    public const string AddIndicator = "addIndicator";
    public const string RemoveIndicator = "removeIndicator";
    public const string Usage = "usage";
    public const string Digest = "digest";

    /// <summary>Commands that change behavior; only accepted from trusted (installed) clients.</summary>
    public static readonly IReadOnlySet<string> Mutating = new HashSet<string>
    {
        Trust, Untrust, Block, Unblock, EndLearning, RestartLearning, AddIndicator, RemoveIndicator,
    };
}

public sealed record ApiRequest
{
    public int Id { get; init; }
    public required string Cmd { get; init; }
    public long? AlertId { get; init; }
    public string? AppKey { get; init; }
    public string? ProcessPath { get; init; }
    /// <summary>For trust: limit to this detector; null = all behavioral detectors.</summary>
    public string? DetectorId { get; init; }
    public int? Limit { get; init; }
    public string? Search { get; init; }
    public Severity? MinSeverity { get; init; }
    public long? AfterId { get; init; }
    /// <summary>IP, CIDR or domain for indicator commands.</summary>
    public string? Value { get; init; }
    /// <summary>Look-back window in hours (usage, digest).</summary>
    public int? Hours { get; init; }
}

public sealed record ApiResponse
{
    public int Id { get; init; }
    public bool Ok { get; init; }
    public string? Error { get; init; }
    public JsonElement? Data { get; init; }
}

public sealed record ApiPush(string Event, Alert? Alert);

public sealed record StatusDto
{
    public required string Version { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required bool IsLearning { get; init; }
    public required DateTimeOffset LearningEndsAt { get; init; }
    public required long EventsProcessed { get; init; }
    public required long ConnectionsSeen { get; init; }
    public required long FlowsStored { get; init; }
    public required long DnsResolutions { get; init; }
    public DateTimeOffset? LastEvent { get; init; }
    public required int ThreatIndicators { get; init; }
    public DateTimeOffset? FeedsRefreshed { get; init; }
    public required int AppsKnown { get; init; }
    public required int UnacknowledgedHigh { get; init; }
    public required int UnacknowledgedMedium { get; init; }
    public required IReadOnlyList<string> CollectorErrors { get; init; }
}

public sealed record TrustResult(string AppKey, string? DetectorId);

public static class ApiJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

/// <summary>Thrown by handlers for user-facing errors (bad arguments, not allowed).</summary>
public sealed class ApiException(string message) : Exception(message);

public static class AppKeyExtensions
{
    public static string? AppKeyOrNull(this Alert alert) =>
        alert.ProcessName is null ? null : AppKeys.For(alert.ProcessName, alert.ProcessPath);
}
