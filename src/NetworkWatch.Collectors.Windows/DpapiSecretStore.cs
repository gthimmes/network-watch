using System.Security.Cryptography;
using System.Text;
using NetworkWatch.Core.Intel;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Secrets encrypted with DPAPI for the current account (LocalSystem for the service) and stored in the
/// settings table. The database is readable by local users, but only the service account can decrypt.
/// </summary>
public sealed class DpapiSecretStore(Database database) : ISecretStore
{
    private static readonly byte[] Entropy = "NetworkWatch.Secrets.v1"u8.ToArray();

    public string? Get(string name)
    {
        var stored = database.GetSetting("secret:" + name);
        if (string.IsNullOrEmpty(stored)) return null;
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(stored), Entropy, DataProtectionScope.CurrentUser));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }

    public void Set(string name, string? value) =>
        database.SetSetting("secret:" + name, string.IsNullOrEmpty(value)
            ? ""
            : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.CurrentUser)));
}
