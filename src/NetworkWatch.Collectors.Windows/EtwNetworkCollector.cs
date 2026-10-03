using System.Net;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Real-time ETW collector: kernel TCP/IP + process events, plus the
/// Microsoft-Windows-DNS-Client provider for per-process DNS lookups.
/// Requires administrator rights.
/// </summary>
public sealed class EtwNetworkCollector(
    ProcessResolver? processes = null,
    string kernelSessionName = "NetworkWatch-Kernel",
    string dnsSessionName = "NetworkWatch-Dns") : ICollector
{
    private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
    private const int DnsQueryCompletedEventId = 3008;

    // Session names must differ between the service and the spike: creating a session with an
    // existing name takes it over.
    private readonly ProcessResolver _processes = processes ?? new ProcessResolver();

    public string Name => "Windows ETW";

    public static bool IsElevated => TraceEventSession.IsElevated() == true;

    public async Task RunAsync(ChannelWriter<NetEvent> sink, CancellationToken ct)
    {
        if (!IsElevated)
            throw new UnauthorizedAccessException("ETW kernel tracing requires administrator rights.");

        // Creating a session with an existing name replaces it, which cleans up after a crash.
        using var kernel = new TraceEventSession(kernelSessionName) { StopOnDispose = true };
        using var dns = new TraceEventSession(dnsSessionName) { StopOnDispose = true };

        kernel.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process);
        dns.EnableProvider(DnsClientProvider);

        HookKernel(kernel.Source.Kernel, sink);
        HookDns(new RegisteredTraceEventParser(dns.Source), sink);

        using var stop = ct.Register(() => { kernel.Stop(); dns.Stop(); });

        await Task.WhenAll(
            Task.Factory.StartNew(() => kernel.Source.Process(), TaskCreationOptions.LongRunning),
            Task.Factory.StartNew(() => dns.Source.Process(), TaskCreationOptions.LongRunning));
    }

    private void HookKernel(KernelTraceEventParser k, ChannelWriter<NetEvent> sink)
    {
        k.ProcessStart += d => _processes.OnStart(d.ProcessID, d.ImageFileName, d.CommandLine, d.ParentID);
        k.ProcessDCStart += d => _processes.OnStart(d.ProcessID, d.ImageFileName, d.CommandLine, d.ParentID);
        k.ProcessStop += d => _processes.OnStop(d.ProcessID);

        k.TcpIpConnect += d => Emit(sink, d, Protocol.Tcp, Direction.Outbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
        k.TcpIpConnectIPV6 += d => Emit(sink, d, Protocol.Tcp, Direction.Outbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
        k.TcpIpAccept += d => Emit(sink, d, Protocol.Tcp, Direction.Inbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
        k.TcpIpAcceptIPV6 += d => Emit(sink, d, Protocol.Tcp, Direction.Inbound, d.saddr, d.sport, d.daddr, d.dport, d.size);

        k.UdpIpSend += d => Emit(sink, d, Protocol.Udp, Direction.Outbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
        k.UdpIpSendIPV6 += d => Emit(sink, d, Protocol.Udp, Direction.Outbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
        k.UdpIpRecv += d => Emit(sink, d, Protocol.Udp, Direction.Inbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
        k.UdpIpRecvIPV6 += d => Emit(sink, d, Protocol.Udp, Direction.Inbound, d.saddr, d.sport, d.daddr, d.dport, d.size);
    }

    private void Emit(ChannelWriter<NetEvent> sink, TraceEvent d, Protocol protocol, Direction direction,
        IPAddress saddr, int sport, IPAddress daddr, int dport, int size)
    {
        // Kernel TCP/IP events always report saddr as the local side and daddr as the remote side.
        var process = _processes.Resolve(d.ProcessID, d.ProcessName);
        sink.TryWrite(new ConnectionEvent(
            new DateTimeOffset(d.TimeStamp), d.ProcessID, process.Name, process.Path,
            protocol, direction, new IPEndPoint(saddr, sport), new IPEndPoint(daddr, dport), size, process.CommandLine, process.ParentName));
    }

    private void HookDns(RegisteredTraceEventParser parser, ChannelWriter<NetEvent> sink)
    {
        parser.All += d =>
        {
            if ((int)d.ID != DnsQueryCompletedEventId)
                return;
            if (d.PayloadByName("QueryName") is not string name || string.IsNullOrEmpty(name))
                return;

            var addresses = DnsResultParser.Parse(d.PayloadByName("QueryResults") as string);
            if (addresses.Count == 0) return;
            var process = _processes.Resolve(d.ProcessID);
            sink.TryWrite(new DnsResolution(new DateTimeOffset(d.TimeStamp), d.ProcessID, name, addresses, process.Name, process.Path));
        };
    }
}
