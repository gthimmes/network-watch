using System.Net;

namespace NetworkWatch.Core;

public enum Protocol { Tcp, Udp }

public enum Direction { Outbound, Inbound }

/// <summary>Base type for everything a collector emits.</summary>
public abstract record NetEvent(DateTimeOffset Time, int Pid);

/// <summary>A connection attempt/accept (TCP) or datagram (UDP) attributed to a process.</summary>
public sealed record ConnectionEvent(
    DateTimeOffset Time,
    int Pid,
    string ProcessName,
    string? ProcessPath,
    Protocol Protocol,
    Direction Direction,
    IPEndPoint Local,
    IPEndPoint Remote,
    int Bytes,
    string? CommandLine = null,
    string? ParentProcessName = null) : NetEvent(Time, Pid);

/// <summary>
/// A completed DNS lookup made by a process, with the addresses it resolved to.
/// <see cref="NameNotFound"/> lookups (NXDOMAIN) have no addresses; bursts of them indicate DGA malware.
/// </summary>
public sealed record DnsResolution(
    DateTimeOffset Time,
    int Pid,
    string QueryName,
    IReadOnlyList<IPAddress> Addresses,
    string? ProcessName = null,
    string? ProcessPath = null,
    bool NameNotFound = false) : NetEvent(Time, Pid);

/// <summary>Bytes exchanged by a process with one remote address since the previous sample (collectors aggregate ~30 s).</summary>
public sealed record TrafficSample(
    DateTimeOffset Time,
    int Pid,
    string ProcessName,
    string? ProcessPath,
    IPAddress Remote,
    long BytesSent,
    long BytesReceived) : NetEvent(Time, Pid);

public sealed record Listener(Protocol Protocol, IPEndPoint Local, int Pid, string ProcessName, string? ProcessPath);

/// <summary>Periodic full list of listening sockets. The core diffs it against the baseline.</summary>
public sealed record ListenerSnapshot(DateTimeOffset Time, IReadOnlyList<Listener> Listeners) : NetEvent(Time, 0);

/// <summary>
/// Current value of a piece of network configuration (DNS servers, proxy, hosts file,
/// gateway MAC). Collectors report values periodically; the core detects changes.
/// </summary>
public sealed record EnvironmentObservation(DateTimeOffset Time, string Kind, string Subject, string Value) : NetEvent(Time, 0);

public enum LogonKind
{
    /// <summary>Network logon (file sharing, remote management, the first step of an NLA Remote Desktop logon).</summary>
    Network = 3,
    /// <summary>Remote Desktop.</summary>
    RemoteDesktop = 10,
}

/// <summary>
/// A sign-in to this computer from another machine, successful or failed. <see cref="Historical"/> events come
/// from reading past logs at startup; they seed the baseline and are not treated as new activity.
/// </summary>
public sealed record RemoteLogon(
    DateTimeOffset Time,
    bool Success,
    string User,
    IPAddress Source,
    LogonKind Kind,
    string? Workstation,
    bool Historical) : NetEvent(Time, 0);

public static class EnvironmentKinds
{
    public const string DnsServers = "dns-servers";
    public const string Proxy = "proxy";
    public const string HostsFile = "hosts-file";
    public const string GatewayMac = "gateway-mac";
}
