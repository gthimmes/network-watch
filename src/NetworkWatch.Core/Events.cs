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
    string? CommandLine = null) : NetEvent(Time, Pid);

/// <summary>A completed DNS lookup made by a process, with the addresses it resolved to.</summary>
public sealed record DnsResolution(
    DateTimeOffset Time,
    int Pid,
    string QueryName,
    IReadOnlyList<IPAddress> Addresses,
    string? ProcessName = null,
    string? ProcessPath = null) : NetEvent(Time, Pid);

public sealed record Listener(Protocol Protocol, IPEndPoint Local, int Pid, string ProcessName, string? ProcessPath);

/// <summary>Periodic full list of listening sockets. The core diffs it against the baseline.</summary>
public sealed record ListenerSnapshot(DateTimeOffset Time, IReadOnlyList<Listener> Listeners) : NetEvent(Time, 0);

/// <summary>
/// Current value of a piece of network configuration (DNS servers, proxy, hosts file,
/// gateway MAC). Collectors report values periodically; the core detects changes.
/// </summary>
public sealed record EnvironmentObservation(DateTimeOffset Time, string Kind, string Subject, string Value) : NetEvent(Time, 0);

public static class EnvironmentKinds
{
    public const string DnsServers = "dns-servers";
    public const string Proxy = "proxy";
    public const string HostsFile = "hosts-file";
    public const string GatewayMac = "gateway-mac";
}
