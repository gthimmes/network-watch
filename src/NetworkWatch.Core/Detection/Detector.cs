using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Core;

/// <summary>A connection after DNS correlation, signature check and threat-intel lookup.</summary>
public sealed record EnrichedConnection(
    ConnectionEvent Conn,
    AddressScope Scope,
    string? Domain,
    SignatureInfo Signature,
    ThreatIndicator? Threat,
    bool IsNewFlow,
    bool IsNewApp,
    string AppKey,
    GeoInfo? Geo = null)
{
    /// <summary>Domain if known, else the IP, for display.</summary>
    public string Destination => Domain ?? Conn.Remote.Address.ToString();

    /// <summary>"example.com:443 (United States, Cloudflare, Inc.)" — location included when known.</summary>
    public string DestinationWithPort => $"{Destination}:{Conn.Remote.Port}" + (Geo is null ? "" : $" ({Geo})");
}

public sealed record DetectionContext(
    DateTimeOffset Now,
    ThreatIntel Intel,
    Baseline Baseline,
    DateTimeOffset StartedAt)
{
    public bool IsLearning => Baseline.IsLearning(Now);

    /// <summary>
    /// Right after startup, connections may use DNS answers cached before we started
    /// watching, so "no DNS lookup seen" is unreliable for a while.
    /// </summary>
    public bool IsWarmingUp => Now - StartedAt < TimeSpan.FromMinutes(10);
}

/// <summary>
/// Base class for detections. Each hook returns zero or more alert candidates; the
/// <see cref="AlertManager"/> handles trust rules, de-duplication and delivery.
/// Detectors run on the single pipeline thread, so they may keep unsynchronized state.
/// </summary>
public abstract class Detector
{
    public abstract string Id { get; }

    /// <summary>False for detectors whose alerts must not be silenced by "Trust this app" (threat intel).</summary>
    public virtual bool RespectsTrust => true;

    public virtual IEnumerable<Alert> OnConnection(EnrichedConnection c, DetectionContext ctx) => [];
    public virtual IEnumerable<Alert> OnDns(DnsResolution d, DetectionContext ctx) => [];
    public virtual IEnumerable<Alert> OnListeners(ListenerSnapshot s, DetectionContext ctx) => [];
    public virtual IEnumerable<Alert> OnEnvironment(EnvironmentObservation o, DetectionContext ctx) => [];
    public virtual IEnumerable<Alert> OnTraffic(EnrichedTraffic t, DetectionContext ctx) => [];

    /// <summary>Called about once a minute for housekeeping.</summary>
    public virtual void OnTick(DetectionContext ctx) { }

    protected Alert ForConnection(EnrichedConnection c, DetectionContext ctx, Severity severity, string dedupKey,
        string title, string what, string why, string todo) => new()
    {
        DetectorId = Id,
        Severity = severity,
        DedupKey = dedupKey,
        Title = title,
        WhatHappened = what,
        WhyItMatters = why,
        WhatToDo = todo,
        ProcessName = c.Conn.ProcessName,
        ProcessPath = c.Conn.ProcessPath,
        Pid = c.Conn.Pid,
        Remote = $"{c.Conn.Remote.Address}:{c.Conn.Remote.Port}",
        Domain = c.Domain,
        FirstSeen = ctx.Now,
        LastSeen = ctx.Now,
    };

    protected Alert General(DetectionContext ctx, Severity severity, string dedupKey, string title, string what, string why, string todo) => new()
    {
        DetectorId = Id,
        Severity = severity,
        DedupKey = dedupKey,
        Title = title,
        WhatHappened = what,
        WhyItMatters = why,
        WhatToDo = todo,
        FirstSeen = ctx.Now,
        LastSeen = ctx.Now,
    };

    protected static string Describe(EnrichedConnection c) =>
        $"{c.Conn.ProcessName} (PID {c.Conn.Pid}{(c.Conn.ProcessPath is null ? "" : $", {c.Conn.ProcessPath}")}" +
        $"{(c.Conn.ParentProcessName is null ? "" : $", started by {c.Conn.ParentProcessName}")})";

    protected internal static string SignerText(SignatureInfo s) => s.Status switch
    {
        SignatureStatus.Signed => $"signed by {s.Signer ?? "a trusted publisher"}",
        SignatureStatus.Unsigned => "not digitally signed",
        SignatureStatus.Invalid => "has an INVALID digital signature",
        _ => "signature unknown",
    };
}
