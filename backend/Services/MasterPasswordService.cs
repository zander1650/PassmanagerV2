using System.Security.Cryptography;
using System.Text;

namespace backend.Services;

public sealed class MasterPasswordService
{
    private const int SaltLengthBytes = 16;
    private const int NonceLengthBytes = 12;
    private const int TagLengthBytes = 16;
    private const int KeyLengthBytes = 32;
    private static readonly byte[] VerificationPlaintext = Encoding.UTF8.GetBytes("vault-unlock-check-v1");

    public string GenerateSaltBase64()
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLengthBytes);
        return Convert.ToBase64String(salt);
    }

    public byte[] DeriveKey(string masterPassword, string saltBase64, int iterations)
    {
        var salt = Convert.FromBase64String(saltBase64);
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(masterPassword),
            salt,
            iterations,
            HashAlgorithmName.SHA512,
            KeyLengthBytes
        );
    }

    public (string nonceBase64, string ciphertextBase64, string tagBase64) CreateVerifier(byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceLengthBytes);
        var ciphertext = new byte[VerificationPlaintext.Length];
        var tag = new byte[TagLengthBytes];

        using var aes = new AesGcm(key, TagLengthBytes);
        aes.Encrypt(nonce, VerificationPlaintext, ciphertext, tag);

        return (
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(ciphertext),
            Convert.ToBase64String(tag)
        );
    }

    public bool VerifyMasterPassword(byte[] key, string nonceBase64, string ciphertextBase64, string tagBase64)
    {
        try
        {
            var nonce = Convert.FromBase64String(nonceBase64);
            var ciphertext = Convert.FromBase64String(ciphertextBase64);
            var tag = Convert.FromBase64String(tagBase64);
            var plaintext = new byte[ciphertext.Length];

            using var aes = new AesGcm(key, TagLengthBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return CryptographicOperations.FixedTimeEquals(plaintext, VerificationPlaintext);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
