using System.Net;
using System.Net.Sockets;

namespace NetworkWatch.Core;

public enum AddressScope { Unspecified, Loopback, LinkLocal, Private, Multicast, Broadcast, Public }

public static class IpClassifier
{
    public static AddressScope Classify(IPAddress address)
    {
        address = DnsCorrelator.Normalize(address);

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return b switch
            {
                [0, 0, 0, 0] => AddressScope.Unspecified,
                [255, 255, 255, 255] => AddressScope.Broadcast,
                [127, ..] => AddressScope.Loopback,
                [169, 254, ..] => AddressScope.LinkLocal,
                [10, ..] => AddressScope.Private,
                [172, >= 16 and <= 31, ..] => AddressScope.Private,
                [192, 168, ..] => AddressScope.Private,
                [100, >= 64 and <= 127, ..] => AddressScope.Private, // carrier-grade NAT
                [>= 224 and <= 239, ..] => AddressScope.Multicast,
                _ => AddressScope.Public,
            };
        }

        if (address.Equals(IPAddress.IPv6None)) return AddressScope.Unspecified;
        if (IPAddress.IsLoopback(address)) return AddressScope.Loopback;
        if (address.IsIPv6LinkLocal) return AddressScope.LinkLocal;
        if (address.IsIPv6Multicast) return AddressScope.Multicast;
        if (address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal) return AddressScope.Private;
        return AddressScope.Public;
    }

    public static bool IsPublic(IPAddress address) => Classify(address) == AddressScope.Public;
}
