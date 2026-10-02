using System.Net;
using NetworkWatch.Core;

namespace NetworkWatch.Core.Tests;

public class FlowTrackerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    private static ConnectionEvent Conn(DateTimeOffset time, int pid = 100, string remote = "8.8.8.8", int port = 443, Protocol protocol = Protocol.Tcp) =>
        new(time, pid, "app.exe", null, protocol, Direction.Outbound,
            new IPEndPoint(IPAddress.Parse("192.168.1.5"), 50000), new IPEndPoint(IPAddress.Parse(remote), port), 0);

    [Fact]
    public void RepeatWithinWindowIsNotNew()
    {
        var flows = new FlowTracker(TimeSpan.FromMinutes(2));
        Assert.True(flows.IsNew(Conn(T0)));
        Assert.False(flows.IsNew(Conn(T0.AddSeconds(30))));
    }

    [Fact]
    public void ActivityKeepsFlowAlive()
    {
        var flows = new FlowTracker(TimeSpan.FromMinutes(2));
        flows.IsNew(Conn(T0));
        flows.IsNew(Conn(T0.AddMinutes(1.5)));
        Assert.False(flows.IsNew(Conn(T0.AddMinutes(3))));
    }

    [Fact]
    public void IdleBeyondWindowIsNewAgain()
    {
        var flows = new FlowTracker(TimeSpan.FromMinutes(2));
        flows.IsNew(Conn(T0));
        Assert.True(flows.IsNew(Conn(T0.AddMinutes(5))));
    }

    [Fact]
    public void DifferentProcessPortOrProtocolIsADifferentFlow()
    {
        var flows = new FlowTracker(TimeSpan.FromMinutes(2));
        flows.IsNew(Conn(T0));
        Assert.True(flows.IsNew(Conn(T0, pid: 200)));
        Assert.True(flows.IsNew(Conn(T0, port: 80)));
        Assert.True(flows.IsNew(Conn(T0, protocol: Protocol.Udp)));
        Assert.True(flows.IsNew(Conn(T0, remote: "1.1.1.1")));
    }
}
