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
        var path = QueryImagePath(pid);
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
