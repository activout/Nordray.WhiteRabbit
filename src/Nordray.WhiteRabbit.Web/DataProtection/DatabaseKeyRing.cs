using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Infrastructure.Encryption;

namespace Nordray.WhiteRabbit.Web.DataProtection;

/// <summary>
/// Keeps ASP.NET Core's Data Protection key ring in the database, so the keys that protect stored Bunny API keys
/// survive container replacement and are covered by the database backup. The framework's interfaces are synchronous;
/// they are called at start-up and when a key is rotated (every 90 days), so blocking here is harmless.
/// </summary>
public sealed class DatabaseKeyRing(IServiceProvider services) : IXmlRepository
{
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var scope = services.CreateScope();
        var keys = scope.ServiceProvider.GetRequiredService<IDataProtectionKeyDao>();
        return keys.ListXmlAsync().GetAwaiter().GetResult().Select(XElement.Parse).ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        using var scope = services.CreateScope();
        var keys = scope.ServiceProvider.GetRequiredService<IDataProtectionKeyDao>();
        keys.InsertAsync(
                string.IsNullOrEmpty(friendlyName) ? Guid.NewGuid().ToString("D") : friendlyName,
                element.ToString(SaveOptions.DisableFormatting),
                DateTime.UtcNow)
            .GetAwaiter().GetResult();
    }
}

/// <summary>Encrypts each key with DataProtection:EncryptionKey (AES-256-GCM) before it is stored.</summary>
public sealed class KeyRingEncryptor(KeyRingEncryption encryption) : IXmlEncryptor
{
    public EncryptedXmlInfo Encrypt(XElement plaintextElement) =>
        new(new XElement("encryptedKey", encryption.Encrypt(plaintextElement.ToString(SaveOptions.DisableFormatting))),
            typeof(KeyRingDecryptor));
}

/// <summary>Created by the framework, from the type name recorded next to each encrypted key.</summary>
public sealed class KeyRingDecryptor(IServiceProvider services) : IXmlDecryptor
{
    public XElement Decrypt(XElement encryptedElement) =>
        XElement.Parse(services.GetRequiredService<KeyRingEncryption>().Decrypt(encryptedElement.Value));
}
