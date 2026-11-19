using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Nordray.WhiteRabbit.Infrastructure.Encryption;

public sealed class DataProtectionOptions
{
    /// <summary>
    /// Base64 of 32 random bytes (<c>openssl rand -base64 32</c>). Encrypts the Data Protection key ring at rest in the
    /// database. Supplied from the environment's secret store, never from a config file in the repository, and kept
    /// with the database backup (separately protected): without it the key ring, and with it every stored Bunny API
    /// key, cannot be decrypted.
    /// </summary>
    public string EncryptionKey { get; set; } = "";
}

/// <summary>AES-256-GCM encryption of key-ring entries with <see cref="DataProtectionOptions.EncryptionKey"/>.</summary>
public sealed class KeyRingEncryption
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const byte FormatVersion = 1;

    private readonly byte[] _key;

    public KeyRingEncryption(IOptions<DataProtectionOptions> options)
    {
        var configured = options.Value.EncryptionKey;
        if (string.IsNullOrWhiteSpace(configured))
            throw new InvalidOperationException(
                "DataProtection:EncryptionKey is required (base64 of 32 random bytes, e.g. `openssl rand -base64 32`).");
        try
        {
            _key = Convert.FromBase64String(configured);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("DataProtection:EncryptionKey must be base64.");
        }
        if (_key.Length != 32)
            throw new InvalidOperationException("DataProtection:EncryptionKey must decode to exactly 32 bytes.");
    }

    /// <summary>Returns base64 of version byte, nonce, ciphertext and tag.</summary>
    public string Encrypt(string plainText)
    {
        var plain = Encoding.UTF8.GetBytes(plainText);
        var result = new byte[1 + NonceSize + plain.Length + TagSize];
        result[0] = FormatVersion;
        var nonce = result.AsSpan(1, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plain, result.AsSpan(1 + NonceSize, plain.Length), result.AsSpan(1 + NonceSize + plain.Length, TagSize));
        return Convert.ToBase64String(result);
    }

    /// <exception cref="CryptographicException">The data was not encrypted with this key, or was altered.</exception>
    public string Decrypt(string cipherText)
    {
        var data = Convert.FromBase64String(cipherText);
        if (data.Length < 1 + NonceSize + TagSize || data[0] != FormatVersion)
            throw new CryptographicException("Unrecognised key-ring entry format.");
        var cipherLength = data.Length - 1 - NonceSize - TagSize;
        var plain = new byte[cipherLength];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(data.AsSpan(1, NonceSize), data.AsSpan(1 + NonceSize, cipherLength), data.AsSpan(1 + NonceSize + cipherLength, TagSize), plain);
        return Encoding.UTF8.GetString(plain);
    }
}
