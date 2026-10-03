using System.Runtime.InteropServices;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Blocks programs with Windows Firewall rules (INetFwPolicy2 via COM). Every rule we create
/// is in the "NetworkWatch" group so we only ever list or remove our own rules.
/// Requires admin (the service runs as LocalSystem).
/// </summary>
public sealed class WindowsFirewallEnforcer : IEnforcer
{
    public const string Group = "NetworkWatch";
    private const int ActionBlock = 0;
    private const int DirectionIn = 1;
    private const int DirectionOut = 2;
    private const int AllProfiles = 0x7FFFFFFF;

    public void BlockProgram(string processPath)
    {
        var existing = ListRules().Where(r => r.ProcessPath.Equals(processPath, StringComparison.OrdinalIgnoreCase)).ToList();
        dynamic policy = Policy();
        foreach (var (direction, label) in new[] { (DirectionOut, "out"), (DirectionIn, "in") })
        {
            if (existing.Any(r => r.Direction == label)) continue;
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
            rule.Name = $"NetworkWatch block: {Path.GetFileName(processPath)} ({label})";
            rule.Description = $"Created by Network Watch. Blocks all {label}bound traffic for {processPath}.";
            rule.ApplicationName = processPath;
            rule.Action = ActionBlock;
            rule.Direction = direction;
            rule.Profiles = AllProfiles;
            rule.Grouping = Group;
            rule.Enabled = true;
            policy.Rules.Add(rule);
        }
    }

    public int UnblockProgram(string processPath)
    {
        dynamic policy = Policy();
        var removed = 0;
        // Rules.Remove deletes by name; our names are unique per program+direction.
        foreach (var rule in ListRules().Where(r => r.ProcessPath.Equals(processPath, StringComparison.OrdinalIgnoreCase)))
        {
            policy.Rules.Remove(rule.Name);
            removed++;
        }
        return removed;
    }

    public IReadOnlyList<BlockRule> ListRules()
    {
        dynamic policy = Policy();
        var rules = new List<BlockRule>();
        foreach (dynamic rule in policy.Rules)
        {
            try
            {
                if ((string?)rule.Grouping != Group) continue;
                rules.Add(new BlockRule((string)rule.Name, (string?)rule.ApplicationName ?? "",
                    (int)rule.Direction == DirectionIn ? "in" : "out"));
            }
            finally
            {
                Marshal.FinalReleaseComObject(rule);
            }
        }
        return rules;
    }

    private static object Policy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
}
