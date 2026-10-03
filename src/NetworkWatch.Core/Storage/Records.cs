namespace NetworkWatch.Core.Storage;

/// <summary>A stored connection flow (first event of a flow), enriched.</summary>
public sealed record ConnectionRecord(
    long Id,
    DateTimeOffset Time,
    int Pid,
    string ProcessName,
    string? ProcessPath,
    string Protocol,
    string Direction,
    string RemoteIp,
    int RemotePort,
    int LocalPort,
    string? Domain,
    string Scope,
    string? Signer,
    string Signature,
    string? Threat);

public sealed record AppRecord(
    string AppKey,
    string ProcessName,
    string? ProcessPath,
    string? Signer,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    bool DirectIpOk,
    bool Trusted);

public static class AppKeys
{
    /// <summary>Stable identity for an application: full path when known, else the process name.</summary>
    public static string For(string processName, string? processPath) =>
        !string.IsNullOrEmpty(processPath) ? processPath.ToLowerInvariant() : "name:" + processName.ToLowerInvariant();
}
