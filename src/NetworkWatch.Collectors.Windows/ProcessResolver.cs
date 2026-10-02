using System.Collections.Concurrent;
using System.Diagnostics;

namespace NetworkWatch.Collectors.Windows;

public sealed record ProcessIdentity(string Name, string? Path);

/// <summary>
/// Caches PID → process name/path. Entries are seeded from ETW process start/rundown
/// events and invalidated on process stop so PID reuse doesn't misattribute traffic.
/// </summary>
internal sealed class ProcessResolver
{
    private readonly ConcurrentDictionary<int, ProcessIdentity> _cache = new();

    public void OnStart(int pid, string imageFileName) =>
        _cache[pid] = new ProcessIdentity(imageFileName, TryGetPath(pid));

    public void OnStop(int pid) => _cache.TryRemove(pid, out _);

    public ProcessIdentity Resolve(int pid, string? etwName) =>
        _cache.GetOrAdd(pid, static (p, name) => Query(p, name), etwName);

    private static ProcessIdentity Query(int pid, string? etwName)
    {
        if (pid == 0) return new ProcessIdentity("Idle", null);
        if (pid == 4) return new ProcessIdentity("System", null);

        var path = TryGetPath(pid);
        var name = path is not null ? System.IO.Path.GetFileName(path)
                 : !string.IsNullOrEmpty(etwName) ? etwName
                 : TryGetName(pid) ?? $"pid:{pid}";
        return new ProcessIdentity(name, path);
    }

    private static string? TryGetPath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName;
        }
        catch { return null; } // exited, protected, or access denied
    }

    private static string? TryGetName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch { return null; }
    }
}
