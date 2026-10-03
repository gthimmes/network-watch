using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using NetworkWatch.Core;

namespace NetworkWatch.Collectors.Windows;

/// <summary>
/// Authenticode check via WinVerifyTrust (embedded signatures), falling back to the system
/// catalog database (how most Windows binaries such as svchost.exe and curl.exe are signed).
/// No revocation/network checks. Results are cached per path + last-write time.
/// </summary>
public sealed partial class WindowsSignatureVerifier : ISignatureVerifier
{
    private readonly ConcurrentDictionary<string, (DateTime LastWrite, SignatureInfo Info)> _cache = new(StringComparer.OrdinalIgnoreCase);

    public SignatureInfo Verify(string? path)
    {
        if (string.IsNullOrEmpty(path)) return SignatureInfo.Unknown;
        DateTime lastWrite;
        try { lastWrite = File.GetLastWriteTimeUtc(path); }
        catch (Exception) { return SignatureInfo.Unknown; }
        if (lastWrite.Year < 1700) return SignatureInfo.Unknown; // file not found

        if (_cache.TryGetValue(path, out var cached) && cached.LastWrite == lastWrite)
            return cached.Info;
        var info = VerifyUncached(path);
        _cache[path] = (lastWrite, info);
        return info;
    }

    internal static SignatureInfo VerifyUncached(string path)
    {
        var result = WinVerifyTrustFile(path);
        if (result == 0)
            return new SignatureInfo(SignatureStatus.Signed, EmbeddedSigner(path));

        if ((uint)result is TrustENoSignature or TrustESubjectFormUnknown or TrustEProviderUnknown)
            return IsCatalogSigned(path)
                ? new SignatureInfo(SignatureStatus.Signed, IsUnderWindows(path) ? "Microsoft Windows (catalog)" : "Catalog-signed")
                : new SignatureInfo(SignatureStatus.Unsigned, null);

        return (uint)result is TrustEBadDigest or CertERevoked or TrustEExplicitDistrust or CertEUntrustedRoot
            ? new SignatureInfo(SignatureStatus.Invalid, EmbeddedSigner(path))
            : SignatureInfo.Unknown;
    }

    private static bool IsUnderWindows(string path) =>
        path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\", StringComparison.OrdinalIgnoreCase);

    private static string? EmbeddedSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile reads the Authenticode signer certificate
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            // Organization ("Microsoft Corporation") is more meaningful to people than CN (".NET").
            var organization = cert.SubjectName.EnumerateRelativeDistinguishedNames()
                .FirstOrDefault(rdn => rdn.GetSingleElementType().Value == "2.5.4.10")?.GetSingleElementValue();
            return organization ?? cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (Exception) { return null; }
    }

    // ── WinVerifyTrust ──────────────────────────────────────────────────────

    private const uint TrustENoSignature = 0x800B0100;
    private const uint TrustESubjectFormUnknown = 0x800B0003;
    private const uint TrustEProviderUnknown = 0x800B0001;
    private const uint TrustEBadDigest = 0x80096010;
    private const uint CertERevoked = 0x800B010C;
    private const uint TrustEExplicitDistrust = 0x800B0111;
    private const uint CertEUntrustedRoot = 0x800B0109;

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public nint FilePath;
        public nint File;
        public nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public nint PolicyCallbackData;
        public nint SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public nint FileInfo;
        public uint StateAction;
        public nint StateData;
        public nint UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public nint SignatureSettings;
    }

    private static unsafe int WinVerifyTrustFile(string path)
    {
        fixed (char* pathPtr = path)
        {
            var file = new WinTrustFileInfo { StructSize = (uint)sizeof(WinTrustFileInfo), FilePath = (nint)pathPtr };
            var data = new WinTrustData
            {
                StructSize = (uint)sizeof(WinTrustData),
                UiChoice = 2,          // WTD_UI_NONE
                RevocationChecks = 0,  // WTD_REVOKE_NONE
                UnionChoice = 1,       // WTD_CHOICE_FILE
                FileInfo = (nint)(&file),
                StateAction = 1,       // WTD_STATEACTION_VERIFY
                ProvFlags = 0x1000 | 0x40, // WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(-1, ref action, ref data);
            data.StateAction = 2;      // WTD_STATEACTION_CLOSE
            WinVerifyTrust(-1, ref action, ref data);
            return result;
        }
    }

    [LibraryImport("wintrust.dll")]
    private static partial int WinVerifyTrust(nint hwnd, ref Guid action, ref WinTrustData data);

    // ── Catalog lookup ──────────────────────────────────────────────────────

    private static bool IsCatalogSigned(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return InCatalog(handle.DangerousGetHandle(), "SHA256") || InCatalog(handle.DangerousGetHandle(), "SHA1");
        }
        catch (Exception) { return false; }
    }

    private static bool InCatalog(nint file, string algorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var admin, 0, algorithm, 0, 0)) return false;
        try
        {
            uint size = 0;
            CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, null, 0);
            if (size == 0) return false;
            var hash = new byte[size];
            if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, hash, 0)) return false;
            var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, 0);
            if (catalog == 0) return false;
            CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            return true;
        }
        finally
        {
            CryptCATAdminReleaseContext(admin, 0);
        }
    }

    [LibraryImport("wintrust.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminAcquireContext2(out nint admin, nint subsystem, string hashAlgorithm, nint strongHashPolicy, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminCalcHashFromFileHandle2(nint admin, nint file, ref uint hashSize, [Out] byte[]? hash, uint flags);

    [LibraryImport("wintrust.dll")]
    private static partial nint CryptCATAdminEnumCatalogFromHash(nint admin, byte[] hash, uint hashSize, uint flags, nint previous);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseCatalogContext(nint admin, nint catalog, uint flags);

    [LibraryImport("wintrust.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptCATAdminReleaseContext(nint admin, uint flags);
}
