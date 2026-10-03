using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace NetworkWatch.Collectors.Windows;

public sealed record ProcessIdentity(string Name, string? Path, string? CommandLine, string? ParentName = null);

/// <summary>
/// Caches PID → process identity. Entries are seeded from ETW process start/rundown events.
/// Exited processes stay cached for a minute because DNS events arrive seconds late (separate
/// ETW session) and short-lived programs are often gone by then. A new start for the same PID
/// replaces the entry, so PID reuse doesn't misattribute traffic. Thread-safe.
/// </summary>
public sealed partial class ProcessResolver
{
    private static readonly TimeSpan ExitedRetention = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<int, ProcessIdentity> _cache = new();
    private readonly ConcurrentDictionary<int, DateTime> _exited = new();
    private DateTime _lastSweep = DateTime.UtcNow;

    public void OnStart(int pid, string imageFileName, string? commandLine, int parentPid = -1)
    {
        // ETW delivers events a second or two late, so very short-lived processes may already be gone.
        var path = QueryImagePath(pid) ?? PathFromCommandLine(commandLine, imageFileName);
        var parent = parentPid > 0 ? Resolve(parentPid).Name : null;
        _exited.TryRemove(pid, out _);
        _cache[pid] = new ProcessIdentity(path is not null ? System.IO.Path.GetFileName(path) : imageFileName, path,
            string.IsNullOrWhiteSpace(commandLine) ? null : commandLine, parent);
    }

    public void OnStop(int pid)
    {
        _exited[pid] = DateTime.UtcNow;
        Sweep();
    }

    public ProcessIdentity Resolve(int pid, string? etwName = null) =>
        _cache.GetOrAdd(pid, static (p, name) => Query(p, name), etwName);

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        if (now - _lastSweep < TimeSpan.FromSeconds(10)) return;
        _lastSweep = now;
        foreach (var (pid, exitedAt) in _exited)
            if (now - exitedAt > ExitedRetention && _exited.TryRemove(pid, out _))
                _cache.TryRemove(pid, out _);
    }

    private static ProcessIdentity Query(int pid, string? etwName)
    {
        if (pid == 0) return new ProcessIdentity("Idle", null, null);
        if (pid == 4) return new ProcessIdentity("System", null, null);

        var path = QueryImagePath(pid);
        var name = path is not null ? System.IO.Path.GetFileName(path)
                 : !string.IsNullOrEmpty(etwName) ? etwName
                 : $"pid:{pid}";
        return new ProcessIdentity(name, path, null);
    }

    /// <summary>
    /// Extracts the executable path from a command line when it's an absolute path to the same
    /// file name as the image (e.g. <c>"C:\Windows\System32\curl.exe" -s https://…</c>).
    /// </summary>
    internal static string? PathFromCommandLine(string? commandLine, string imageFileName)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var text = commandLine.TrimStart();
        string candidate;
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            if (end < 0) return null;
            candidate = text[1..end];
        }
        else
        {
            var end = text.IndexOf(' ');
            candidate = end < 0 ? text : text[..end];
        }
        candidate = candidate.Replace('/', '\\');
        if (!System.IO.Path.IsPathFullyQualified(candidate)) return null;
        if (!System.IO.Path.HasExtension(candidate)) candidate += ".exe";
        return System.IO.Path.GetFileName(candidate).Equals(imageFileName, StringComparison.OrdinalIgnoreCase) && File.Exists(candidate)
            ? candidate
            : null;
    }

    /// <summary>
    /// QueryFullProcessImageName with PROCESS_QUERY_LIMITED_INFORMATION works for protected
    /// processes too and is much cheaper than Process.MainModule.
    /// </summary>
    public static string? QueryImagePath(int pid)
    {
        if (pid <= 4) return null;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == 0) return null;
        try
        {
            var buffer = new char[1024];
            var size = buffer.Length;
            return QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int pid);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(nint process, uint flags, [Out] char[] buffer, ref int size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
