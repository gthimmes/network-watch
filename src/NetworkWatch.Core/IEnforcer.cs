namespace NetworkWatch.Core;

public sealed record BlockRule(string Name, string ProcessPath, string Direction);

/// <summary>OS-specific network blocking (Windows Firewall today; nftables/pf later).</summary>
public interface IEnforcer
{
    /// <summary>Blocks all inbound and outbound traffic for the program. Idempotent.</summary>
    void BlockProgram(string processPath);

    /// <summary>Removes rules this tool created for the program. Returns the number removed.</summary>
    int UnblockProgram(string processPath);

    /// <summary>Rules created by this tool.</summary>
    IReadOnlyList<BlockRule> ListRules();
}
