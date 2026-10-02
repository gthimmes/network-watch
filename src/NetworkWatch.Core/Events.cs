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
    int Bytes) : NetEvent(Time, Pid);

/// <summary>A completed DNS lookup made by a process, with the addresses it resolved to.</summary>
public sealed record DnsResolution(
    DateTimeOffset Time,
    int Pid,
    string QueryName,
    IReadOnlyList<IPAddress> Addresses) : NetEvent(Time, Pid);
