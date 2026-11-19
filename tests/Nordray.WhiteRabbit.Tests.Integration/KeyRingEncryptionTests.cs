using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Infrastructure.Encryption;

namespace Nordray.WhiteRabbit.Tests.Integration;

public class KeyRingEncryptionTests
{
    public static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static KeyRingEncryption Create(string key) => new(Options.Create(new DataProtectionOptions { EncryptionKey = key }));

    [Fact]
    public void EncryptThenDecrypt_RoundTripsAndUsesAFreshNonce()
    {
        var encryption = Create(NewKey());
        var a = encryption.Encrypt("<key>secret material</key>");
        var b = encryption.Encrypt("<key>secret material</key>");

        Assert.NotEqual(a, b);
        Assert.DoesNotContain("secret", a);
        Assert.Equal("<key>secret material</key>", encryption.Decrypt(a));
    }

    [Fact]
    public void Decrypt_WithAnotherKey_Fails() =>
        Assert.ThrowsAny<CryptographicException>(() => Create(NewKey()).Decrypt(Create(NewKey()).Encrypt("x")));

    [Fact]
    public void Decrypt_TamperedData_Fails()
    {
        var encryption = Create(NewKey());
        var bytes = Convert.FromBase64String(encryption.Encrypt("payload"));
        bytes[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => encryption.Decrypt(Convert.ToBase64String(bytes)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base64!")]
    [InlineData("c2hvcnQ=")]
    public void Constructor_RejectsMissingOrMalformedKey(string key) =>
        Assert.Throws<InvalidOperationException>(() => Create(key));
}
