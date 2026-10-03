namespace NetworkWatch.Core;

/// <summary>
/// Info: timeline/digest only. Medium: shown in the alert list, tray turns yellow.
/// High: toast notification, tray turns red.
/// </summary>
public enum Severity { Info = 0, Medium = 1, High = 2 }

public enum AlertStatus { New = 0, Acknowledged = 1 }

public sealed record Alert
{
    public long Id { get; init; }
    public required string DetectorId { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string WhatHappened { get; init; }
    public required string WhyItMatters { get; init; }
    public required string WhatToDo { get; init; }

    /// <summary>Alerts with the same key within the dedup window are merged (Count incremented).</summary>
    public required string DedupKey { get; init; }

    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public int? Pid { get; init; }
    public string? Remote { get; init; }
    public string? Domain { get; init; }

    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public int Count { get; init; } = 1;
    public AlertStatus Status { get; init; }
}
