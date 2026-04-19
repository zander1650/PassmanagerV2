namespace backend.Models;

public sealed class VaultState
{
    public bool IsInitialized { get; set; }
    public string SaltBase64 { get; set; } = string.Empty;
    public int KdfIterations { get; set; } = 600000;
    public string VerifierNonceBase64 { get; set; } = string.Empty;
    public string VerifierCiphertextBase64 { get; set; } = string.Empty;
    public string VerifierTagBase64 { get; set; } = string.Empty;
    public List<VaultEntry> Entries { get; set; } = new();
}

public sealed class VaultEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string NonceBase64 { get; set; } = string.Empty;
    public string CiphertextBase64 { get; set; } = string.Empty;
    public string TagBase64 { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}

public sealed record VaultStateResponse(bool IsInitialized, int KdfIterations, string SaltBase64);

public sealed record SetupVaultRequest(string MasterPassword);
public sealed record UnlockVaultRequest(string MasterPassword);
public sealed record ResetVaultRequest(string Confirmation);

public sealed record UnlockVaultResponse(bool Ok, string SessionToken, DateTime ExpiresAtUtc);

public sealed record UpsertEntryRequest(string NonceBase64, string CiphertextBase64, string TagBase64);

public sealed record VaultEntryResponse(
    Guid Id,
    string NonceBase64,
    string CiphertextBase64,
    string TagBase64,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc
);
