using System.Net;

namespace NetworkWatch.Core;

/// <summary>
/// #13: remote sign-ins. Alerts on Remote Desktop sign-ins from devices that never signed in before, any remote
/// sign-in from the internet, and password-guessing (bursts of failed sign-ins from one address).
/// </summary>
public sealed class RemoteLogonDetector : Detector
{
    private static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(10);
    internal const int PublicFailureThreshold = 5;
    internal const int PrivateFailureThreshold = 10;

    private readonly Dictionary<IPAddress, List<DateTimeOffset>> _failures = [];

    public override string Id => "remote-logon";

    public override IEnumerable<Alert> OnRemoteLogon(RemoteLogon e, DetectionContext ctx)
    {
        var scope = IpClassifier.Classify(e.Source);
        if (scope is AddressScope.Loopback or AddressScope.Unspecified) yield break;
        var fromInternet = scope == AddressScope.Public;
        var where = fromInternet ? "the internet" : "your local network";
        var kind = e.Kind == LogonKind.RemoteDesktop ? "Remote Desktop" : "a network (file sharing / remote management)";

        if (!e.Success)
        {
            if (e.Historical) yield break;
            if (!_failures.TryGetValue(e.Source, out var times)) _failures[e.Source] = times = [];
            times.RemoveAll(t => ctx.Now - t > FailureWindow);
            times.Add(e.Time);
            if (times.Count < (fromInternet ? PublicFailureThreshold : PrivateFailureThreshold)) yield break;

            yield return General(ctx, fromInternet ? Severity.High : Severity.Medium, $"logon-fail:{e.Source}:{ctx.Now:yyyy-MM-dd}",
                $"Someone is guessing passwords from {e.Source}",
                $"{times.Count} failed {kind} sign-in attempts from {e.Source} ({where}{Workstation(e)}) in the last {FailureWindow.TotalMinutes:0} minutes, most recently as \"{e.User}\".",
                "Repeated failed sign-ins from one address is what password-guessing (brute-force) attacks look like." +
                    (fromInternet ? " This computer is reachable from the internet for sign-ins, which is risky." : ""),
                fromInternet
                    ? "Turn off Remote Desktop or make sure it isn't reachable from the internet (check router port forwarding), and use strong, unique passwords."
                    : "Find which device has that address (your router's device list). If it isn't yours, disconnect it from your network.") with { Remote = e.Source.ToString() };
            yield break;
        }

        // Successful sign-in.
        if (fromInternet)
        {
            yield return General(ctx, Severity.High, $"logon-public:{e.Source}:{e.User}",
                $"{e.User} signed in to this computer from the internet",
                $"A {kind} sign-in as \"{e.User}\" succeeded from {e.Source}{Workstation(e)} at {e.Time:g}.",
                "Sign-ins from the internet mean this computer is exposed to remote access. If it wasn't you, someone has your password and control of this PC.",
                "If this wasn't you: disconnect from the internet, change the account's password from another device, and turn off Remote Desktop. If it was you (e.g. via a VPN or port forward), acknowledge the alert.") with { Remote = e.Source.ToString() };
            yield break;
        }

        if (e.Kind != LogonKind.RemoteDesktop) yield break; // LAN network logons (file shares, Plex, printers) are routine
        var key = $"logon-src:{e.Source}";
        if (!ctx.Baseline.AddListener(key, ctx.Now) || e.Historical || ctx.IsLearning) yield break;

        yield return General(ctx, Severity.Medium, key,
            $"A new device signed in to this computer with Remote Desktop",
            $"\"{e.User}\" signed in with Remote Desktop from {e.Source}{Workstation(e)} on your local network. No device at that address has done this before.",
            "Remote Desktop gives full control of this computer. A new source is expected if you just started using another device; otherwise it may be someone else on your network.",
            "If this was you, nothing to do. If not, sign out that session (Task Manager → Users), change your password, and check which device has that address.") with { Remote = e.Source.ToString() };
    }

    public override void OnTick(DetectionContext ctx)
    {
        foreach (var (source, times) in _failures)
        {
            times.RemoveAll(t => ctx.Now - t > FailureWindow);
            if (times.Count == 0) _failures.Remove(source);
        }
    }

    private static string Workstation(RemoteLogon e) =>
        string.IsNullOrWhiteSpace(e.Workstation) || e.Workstation == "-" ? "" : $", device name \"{e.Workstation}\"";
}
