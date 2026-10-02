using System.Net;
using NetworkWatch.Core;

namespace NetworkWatch.Core.Tests;

public class IpClassifierTests
{
    [Theory]
    [InlineData("8.8.8.8", AddressScope.Public)]
    [InlineData("142.250.80.46", AddressScope.Public)]
    [InlineData("127.0.0.1", AddressScope.Loopback)]
    [InlineData("10.1.2.3", AddressScope.Private)]
    [InlineData("172.16.0.1", AddressScope.Private)]
    [InlineData("172.31.255.255", AddressScope.Private)]
    [InlineData("172.32.0.1", AddressScope.Public)]
    [InlineData("192.168.1.10", AddressScope.Private)]
    [InlineData("100.64.0.1", AddressScope.Private)]
    [InlineData("169.254.10.10", AddressScope.LinkLocal)]
    [InlineData("224.0.0.251", AddressScope.Multicast)]
    [InlineData("239.255.255.250", AddressScope.Multicast)]
    [InlineData("255.255.255.255", AddressScope.Broadcast)]
    [InlineData("0.0.0.0", AddressScope.Unspecified)]
    [InlineData("::1", AddressScope.Loopback)]
    [InlineData("::", AddressScope.Unspecified)]
    [InlineData("fe80::1", AddressScope.LinkLocal)]
    [InlineData("fd00::1", AddressScope.Private)]
    [InlineData("ff02::fb", AddressScope.Multicast)]
    [InlineData("2607:f8b0:4006:80f::2004", AddressScope.Public)]
    [InlineData("::ffff:192.168.1.1", AddressScope.Private)]
    [InlineData("::ffff:8.8.8.8", AddressScope.Public)]
    public void Classifies(string address, AddressScope expected) =>
        Assert.Equal(expected, IpClassifier.Classify(IPAddress.Parse(address)));
}
