namespace NetworkWatch.Core;

/// <summary>Static knowledge used by detectors. Names are compared case-insensitively.</summary>
public static class KnownLists
{
    /// <summary>
    /// Built-in Windows programs that attackers abuse to download or run payloads
    /// ("living off the land"). Value: true = high suspicion, false = medium (commonly used legitimately).
    /// </summary>
    public static readonly IReadOnlyDictionary<string, bool> LivingOffTheLand = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
    {
        ["powershell.exe"] = false,
        ["pwsh.exe"] = false,
        ["powershell_ise.exe"] = false,
        ["mshta.exe"] = true,
        ["rundll32.exe"] = true,
        ["regsvr32.exe"] = true,
        ["certutil.exe"] = true,
        ["bitsadmin.exe"] = true,
        ["wscript.exe"] = true,
        ["cscript.exe"] = true,
        ["msbuild.exe"] = true,
        ["installutil.exe"] = true,
        ["regasm.exe"] = true,
        ["regsvcs.exe"] = true,
        ["cmstp.exe"] = true,
        ["odbcconf.exe"] = true,
        ["msxsl.exe"] = true,
        ["hh.exe"] = true,
        ["finger.exe"] = true,
        ["wmic.exe"] = true,
        ["forfiles.exe"] = true,
        ["esentutl.exe"] = true,
        ["expand.exe"] = true,
        ["ieexec.exe"] = true,
        ["msiexec.exe"] = false,
    };

    /// <summary>
    /// Programs that should essentially never launch a script host or download tool. A LOLBin started
    /// by one of these (Office, PDF readers, browsers, mail) is a classic malicious-document/exploit chain.
    /// </summary>
    public static readonly IReadOnlySet<string> SuspiciousParents = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe",
        "acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "sumatrapdf.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe",
        "thunderbird.exe", "olk.exe", "hwp.exe", "wordpad.exe",
    };

    /// <summary>Remote-control / remote-support tools. The #1 tool in tech-support scams.</summary>
    public static readonly IReadOnlySet<string> RemoteAccessTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe",
        "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "connectwisecontrol.client.exe",
        "rustdesk.exe", "srservice.exe", "strwinclt.exe", "srmanager.exe", // Splashtop
        "logmein.exe", "lmiguardiansvc.exe", "logmeinsystray.exe", "gotoassist.exe", "g2ax_comm_customer.exe",
        "ultraviewer_service.exe", "ultraviewer_desktop.exe", "supremo.exe", "supremoservice.exe",
        "rutserv.exe", "rfusclient.exe", // Remote Utilities
        "ateraagent.exe", "client32.exe", // NetSupport
        "aa_v3.exe", "ammyy_admin.exe", "zohoassist.exe", "zaservice.exe", "remotepc.exe", "dwagent.exe",
        "quickassist.exe", "msra.exe", "parsecd.exe", "action1_agent.exe", "simplehelpcustomer.exe",
    };

    /// <summary>
    /// Domains where living-off-the-land binaries talking out is routine (OS updates, certificate
    /// checks, package galleries). Suffix match.
    /// </summary>
    public static readonly IReadOnlyList<string> RoutineMicrosoftDomains =
    [
        "microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com", "msftncsi.com", "live.com",
        "office.com", "office.net", "microsoftonline.com", "msedge.net", "azureedge.net", "azurefd.net", "azure.com",
        "visualstudio.com", "powershellgallery.com", "nuget.org", "digicert.com", "msocsp.com", "verisign.com",
        "globalsign.com", "sectigo.com", "usertrust.com", "lencr.org", "pki.goog", "skype.com", "bing.com", "msn.com",
        "trafficmanager.net", "akamaized.net", "akamaiedge.net", "dotnet.microsoft.com", "aka.ms", "github.com",
        "githubusercontent.com", "chocolatey.org",
    ];

    public static bool IsRoutineDomain(string? domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        foreach (var suffix in RoutineMicrosoftDomains)
            if (domain.Equals(suffix, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    /// <summary>
    /// Folders where legitimate installed software rarely lives but downloaded/dropped
    /// malware often does. Matched against lower-cased paths with '/' separators.
    /// </summary>
    private static readonly string[] SuspiciousFolders =
    [
        "/appdata/local/temp/", "/windows/temp/", "/downloads/", "/$recycle.bin/", "/users/public/",
        "/appdata/roaming/", "/programdata/", "/temp/", "/tmp/", "/desktop/", "/appdata/locallow/",
    ];

    public static bool IsSuspiciousLocation(string? path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var normalized = path.Replace('\\', '/').ToLowerInvariant();
        // ProgramData root files are suspicious; vendor subfolders under ProgramData (e.g. Microsoft Defender) are common.
        foreach (var folder in SuspiciousFolders)
            if (normalized.Contains(folder, StringComparison.Ordinal))
                return true;
        return false;
    }

    public static string FileName(string processName, string? path) =>
        path is not null ? Path.GetFileName(path.Replace('\\', '/')) : processName;
}
