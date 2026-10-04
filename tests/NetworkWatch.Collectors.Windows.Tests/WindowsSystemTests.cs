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
    public void StoreAppFilesWithoutEmbeddedSignatureAreSignedByPackage()
    {
        var windowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
        string[] exes;
        try { exes = Directory.GetFiles(windowsApps, "*.exe", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; } // listing WindowsApps can be denied; covered live instead
        var unsignedInStore = exes.FirstOrDefault(e => !IsEmbeddedSigned(e));
        if (unsignedInStore is null) return;

        var info = WindowsSignatureVerifier.VerifyUncached(unsignedInStore);
        Assert.Equal(SignatureStatus.Signed, info.Status);
        Assert.EndsWith("(Store package)", info.Signer);

        static bool IsEmbeddedSigned(string file)
        {
#pragma warning disable SYSLIB0057 // reads the Authenticode signer; no replacement API
            try { System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(file); return true; }
#pragma warning restore SYSLIB0057
            catch (Exception) { return false; }
        }
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
    public void SecretsAreEncryptedAtRestAndRoundTrip()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nw-secret-{Guid.NewGuid():N}.db");
        try
        {
            var db = new NetworkWatch.Core.Storage.Database(path);
            var store = new DpapiSecretStore(db);
            store.Set("k", "super-secret-value");
            Assert.Equal("super-secret-value", store.Get("k"));
            Assert.DoesNotContain("super-secret", db.GetSetting("secret:k"));
            store.Set("k", null);
            Assert.Null(store.Get("k"));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var f in new[] { path, path + "-wal", path + "-shm" }) try { File.Delete(f); } catch (IOException) { }
        }
    }

    [Fact]
    public void HostsNormalizationDropsCommentsAndWhitespace()
    {
        var normalized = EnvironmentCollector.NormalizeHosts("# header\r\n127.0.0.1\t  localhost   # loop\r\n\r\n  6.6.6.6 bank.example\r\n");
        Assert.Equal("127.0.0.1 localhost\n6.6.6.6 bank.example", normalized);
    }
}
