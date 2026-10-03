using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetworkWatch.Collectors.Windows;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows.Tests;

/// <summary>Tests against the real OS. None of these need administrator rights.</summary>
public class WindowsSystemTests
{
    private static string System32(string file) => Path.Combine(Environment.SystemDirectory, file);

    [Fact]
    public void WindowsBinariesAreSignedEmbeddedOrViaCatalog()
    {
        var results = new[] { "cmd.exe", "ping.exe", "ipconfig.exe", "whoami.exe", "curl.exe", "svchost.exe" }
            .Select(System32).Where(File.Exists)
            .Select(WindowsSignatureVerifier.VerifyUncached).ToList();

        Assert.All(results, r => Assert.Equal(SignatureStatus.Signed, r.Status));
        // Most in-box binaries carry no embedded signature and are only signed through the catalog database.
        Assert.Contains(results, r => r.Signer == "Microsoft Windows (catalog)");
    }

    [Fact]
    public void EmbeddedSignatureReportsSigner()
    {
        var dotnet = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
        var info = WindowsSignatureVerifier.VerifyUncached(dotnet);
        Assert.Equal(SignatureStatus.Signed, info.Status);
        Assert.Equal("Microsoft Corporation", info.Signer);
    }

    [Fact]
    public void LocallyBuiltBinaryIsUnsignedAndMissingPathIsUnknown()
    {
        // Our own freshly built assembly is never signed.
        var temp = Path.Combine(Path.GetTempPath(), $"nw-unsigned-{Guid.NewGuid():N}.exe");
        File.Copy(typeof(ProcessResolver).Assembly.Location, temp);
        try
        {
            Assert.Equal(SignatureStatus.Unsigned, new WindowsSignatureVerifier().Verify(temp).Status);
            Assert.Equal(SignatureStatus.Unknown, new WindowsSignatureVerifier().Verify(@"C:\does\not\exist.exe").Status);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void ListenerSnapshotIncludesOurOwnListenerWithPid()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var snapshot = new ListenerCollector(new ProcessResolver()).Snapshot();
            var mine = Assert.Single(snapshot, l => l.Local.Port == port && l.Local.Address.Equals(IPAddress.Loopback));
            Assert.Equal(Environment.ProcessId, mine.Pid);
            Assert.NotNull(mine.ProcessPath);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void ProcessResolverFindsOwnPath()
    {
        var identity = new ProcessResolver().Resolve(Environment.ProcessId);
        Assert.Equal(Process.GetCurrentProcess().MainModule!.FileName, identity.Path, ignoreCase: true);
    }

    [Theory]
    [InlineData("\"C:\\Windows\\System32\\curl.exe\" -s https://x", "curl.exe", true)]
    [InlineData("C:/Windows/System32/curl.exe -s https://x", "curl.exe", true)]
    [InlineData("C:\\Windows\\System32\\curl -s", "curl.exe", true)]
    [InlineData("curl.exe -s https://x", "curl.exe", false)]              // relative: unknown
    [InlineData("\"C:\\Windows\\System32\\cmd.exe\" /c x", "curl.exe", false)] // different image
    [InlineData(null, "curl.exe", false)]
    public void PathFromCommandLineOnlyAcceptsMatchingAbsolutePaths(string? commandLine, string image, bool found)
    {
        var path = ProcessResolver.PathFromCommandLine(commandLine, image);
        Assert.Equal(found, path is not null);
        if (found) Assert.Equal(Path.Combine(Environment.SystemDirectory, image), path, ignoreCase: true);
    }

    [Fact]
    public void EnvironmentObservationIncludesHostsFileAndDns()
    {
        var observations = new EnvironmentCollector().Observe(DateTimeOffset.Now).ToList();
        Assert.Contains(observations, o => o.Kind == EnvironmentKinds.HostsFile);
        Assert.Contains(observations, o => o.Kind == EnvironmentKinds.DnsServers);
    }

    [Fact]
    public void HostsNormalizationDropsCommentsAndWhitespace()
    {
        var normalized = EnvironmentCollector.NormalizeHosts("# header\r\n127.0.0.1\t  localhost   # loop\r\n\r\n  6.6.6.6 bank.example\r\n");
        Assert.Equal("127.0.0.1 localhost\n6.6.6.6 bank.example", normalized);
    }
}
