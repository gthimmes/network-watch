namespace NetworkWatch.Core;

public enum SignatureStatus
{
    /// <summary>Path unknown or could not be checked.</summary>
    Unknown,
    /// <summary>Valid signature (embedded or via an OS catalog).</summary>
    Signed,
    /// <summary>No signature at all.</summary>
    Unsigned,
    /// <summary>Signature present but invalid: tampered, expired untrusted root, revoked.</summary>
    Invalid,
}

public sealed record SignatureInfo(SignatureStatus Status, string? Signer)
{
    public static readonly SignatureInfo Unknown = new(SignatureStatus.Unknown, null);

    public bool IsSigned => Status == SignatureStatus.Signed;
}

/// <summary>OS-specific code-signing check (Authenticode on Windows). Implementations cache by path.</summary>
public interface ISignatureVerifier
{
    SignatureInfo Verify(string? path);
}

public sealed class NullSignatureVerifier : ISignatureVerifier
{
    public SignatureInfo Verify(string? path) => SignatureInfo.Unknown;
}
