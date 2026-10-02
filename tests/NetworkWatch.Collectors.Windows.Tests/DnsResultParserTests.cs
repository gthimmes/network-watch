using System.Net;
using NetworkWatch.Collectors.Windows;

namespace NetworkWatch.Collectors.Windows.Tests;

public class DnsResultParserTests
{
    [Fact]
    public void ParsesMixedCnameIpv4MappedAndIpv6Results()
    {
        var result = DnsResultParser.Parse("type:  5 www.google.com;::ffff:142.250.80.46;2607:f8b0:4006:80f::2004;");

        Assert.Equal([IPAddress.Parse("142.250.80.46"), IPAddress.Parse("2607:f8b0:4006:80f::2004")], result);
    }

    [Fact]
    public void ParsesPlainIpv4()
    {
        Assert.Equal([IPAddress.Parse("1.1.1.1")], DnsResultParser.Parse("1.1.1.1;"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("type:  5 alias.example.com;")]
    public void ReturnsEmptyWhenNoAddresses(string? input)
    {
        Assert.Empty(DnsResultParser.Parse(input));
    }
}
