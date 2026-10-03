using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Polls the TCP listener tables (IPv4 + IPv6, with owning PIDs) and emits a
/// <see cref="ListenerSnapshot"/>. ETW has no reliable "socket started listening" event.
/// </summary>
public sealed partial class ListenerCollector(ProcessResolver processes, TimeSpan? interval = null) : ICollector
{
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromSeconds(15);

    public string Name => "Windows TCP listeners";

    public async Task RunAsync(ChannelWriter<NetEvent> sink, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(_interval);
        do
        {
            sink.TryWrite(new ListenerSnapshot(DateTimeOffset.Now, Snapshot()));
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    public IReadOnlyList<Listener> Snapshot()
    {
        var list = new List<Listener>();
        foreach (var (address, port, pid) in ReadTable(AddressFamily.InterNetwork).Concat(ReadTable(AddressFamily.InterNetworkV6)))
        {
            var process = processes.Resolve(pid);
            list.Add(new Listener(Protocol.Tcp, new IPEndPoint(address, port), pid, process.Name, process.Path));
        }
        return list;
    }

    private static List<(IPAddress Address, int Port, int Pid)> ReadTable(AddressFamily family)
    {
        var result = new List<(IPAddress, int, int)>();
        var af = family == AddressFamily.InterNetwork ? AfInet : AfInet6;
        var size = 0;
        GetExtendedTcpTable(0, ref size, false, af, TcpTableOwnerPidListener, 0);
        if (size == 0) return result;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, af, TcpTableOwnerPidListener, 0) != 0)
                return result;

            var count = Marshal.ReadInt32(buffer);
            var row = buffer + 4;
            for (var i = 0; i < count; i++)
            {
                if (family == AddressFamily.InterNetwork)
                {
                    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 x DWORD)
                    var localAddr = (uint)Marshal.ReadInt32(row, 4);
                    var localPort = NetworkPort(Marshal.ReadInt32(row, 8));
                    var pid = Marshal.ReadInt32(row, 20);
                    result.Add((new IPAddress(localAddr), localPort, pid));
                    row += 24;
                }
                else
                {
                    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScopeId, localPort, remoteAddr[16], remoteScopeId, remotePort, state, pid
                    var bytes = new byte[16];
                    Marshal.Copy(row, bytes, 0, 16);
                    var scopeId = (uint)Marshal.ReadInt32(row, 16);
                    var localPort = NetworkPort(Marshal.ReadInt32(row, 20));
                    var pid = Marshal.ReadInt32(row, 52);
                    result.Add((new IPAddress(bytes, scopeId), localPort, pid));
                    row += 56;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    private static int NetworkPort(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidListener = 3;

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(nint table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int af, int tableClass, uint reserved);
}
