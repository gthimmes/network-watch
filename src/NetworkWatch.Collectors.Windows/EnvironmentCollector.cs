using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Channels;
using Microsoft.Win32;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Periodically reports network configuration the core watches for tampering:
/// per-network DNS servers, gateway MAC address, hosts file contents and per-user proxy settings.
/// The core stores values and alerts on changes, so this just reports current state.
/// </summary>
public sealed partial class EnvironmentCollector(TimeSpan? interval = null) : ICollector
{
    private readonly TimeSpan _interval = interval ?? TimeSpan.FromSeconds(30);

    public static string HostsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");

    public string Name => "Windows network configuration";

    public async Task RunAsync(ChannelWriter<NetEvent> sink, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(_interval);
        do
        {
            foreach (var observation in Observe(DateTimeOffset.Now))
                sink.TryWrite(observation);
        }
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    public IEnumerable<EnvironmentObservation> Observe(DateTimeOffset now)
    {
        var results = new List<EnvironmentObservation>();
        Try(() => ObserveAdapters(now, results));
        Try(() =>
        {
            if (File.Exists(HostsPath))
                results.Add(new EnvironmentObservation(now, EnvironmentKinds.HostsFile, HostsPath, NormalizeHosts(File.ReadAllText(HostsPath))));
        });
        Try(() => ObserveProxies(now, results));
        return results;
    }

    private static void Try(Action action)
    {
        try { action(); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NetworkInformationException or System.Security.SecurityException) { }
    }

    private static void ObserveAdapters(DateTimeOffset now, List<EnvironmentObservation> results)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;
            var props = nic.GetIPProperties();
            var gateway = props.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));

            // Subject includes the gateway so moving between networks (home/office/café) isn't a "change".
            var network = $"{nic.Name} via {gateway?.ToString() ?? "no gateway"}";
            var dns = props.DnsAddresses.Where(a => !a.IsIPv6SiteLocal).Select(a => a.ToString()).Order().ToList();
            if (dns.Count > 0)
                results.Add(new EnvironmentObservation(now, EnvironmentKinds.DnsServers, network, string.Join(", ", dns)));

            if (gateway is not null && GetMac(gateway) is { } mac)
                results.Add(new EnvironmentObservation(now, EnvironmentKinds.GatewayMac, $"{gateway} on {nic.Name}", mac));
        }
    }

    /// <summary>Non-comment hosts entries, whitespace-normalized, one per line.</summary>
    public static string NormalizeHosts(string content)
    {
        var lines = new List<string>();
        foreach (var raw in content.Split('\n'))
        {
            var hash = raw.IndexOf('#');
            var line = (hash >= 0 ? raw[..hash] : raw).Trim();
            if (line.Length == 0) continue;
            lines.Add(string.Join(' ', line.Split((char[])[' ', '\t'], StringSplitOptions.RemoveEmptyEntries)));
        }
        return string.Join('\n', lines);
    }

    /// <summary>WinINET proxy settings live per user (HKCU); the service reads every loaded user hive.</summary>
    private static void ObserveProxies(DateTimeOffset now, List<EnvironmentObservation> results)
    {
        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.EndsWith("_Classes", StringComparison.Ordinal))
                continue;
            using var key = Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key is null) continue;
            var enabled = key.GetValue("ProxyEnable") is int e ? e : 0;
            var server = key.GetValue("ProxyServer") as string ?? "";
            var pac = key.GetValue("AutoConfigURL") as string ?? "";
            results.Add(new EnvironmentObservation(now, EnvironmentKinds.Proxy, AccountName(sid),
                $"enabled={enabled};server={server};pac={pac}"));
        }
    }

    private static string AccountName(string sid)
    {
        try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch (Exception) { return sid; }
    }

    private static string? GetMac(IPAddress ipv4)
    {
        Span<byte> addressBytes = stackalloc byte[4];
        ipv4.TryWriteBytes(addressBytes, out _);
        var dest = BitConverter.ToUInt32(addressBytes);
        var mac = new byte[6];
        var length = (uint)mac.Length;
        if (SendARP(dest, 0, mac, ref length) != 0 || length != 6) return null;
        return string.Join("-", mac.Select(b => b.ToString("X2")));
    }

    [LibraryImport("iphlpapi.dll")]
    private static partial int SendARP(uint destIp, uint srcIp, [Out] byte[] macAddr, ref uint physicalAddrLen);
}
