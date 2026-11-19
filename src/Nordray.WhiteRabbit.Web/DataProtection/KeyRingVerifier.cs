using System.Data.Common;
using System.Security.Cryptography;
using System.Xml.Linq;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Infrastructure.Encryption;

namespace Nordray.WhiteRabbit.Web.DataProtection;

/// <summary>
/// Start-up check that the configured DataProtection:EncryptionKey matches the stored key ring. Without it, a wrong
/// (but well-formed) key, or a database restored without its key ring, would start normally, report ready, and make
/// every stored Bunny API key unreadable: users would be asked to re-enter keys that are in fact recoverable.
/// </summary>
public sealed class KeyRingVerifier(DatabaseConnectionFactory connections, KeyRingEncryption encryption)
{
    public async Task VerifyAsync(CancellationToken ct = default)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(ct);

        var entries = await ReadStringsAsync(connection, "SELECT Xml FROM DataProtectionKeys", ct);
        foreach (var xml in entries)
        {
            foreach (var encrypted in XElement.Parse(xml).Descendants().Where(e => e.Name.LocalName == "encryptedKey"))
            {
                try
                {
                    encryption.Decrypt(encrypted.Value);
                }
                catch (Exception ex) when (ex is CryptographicException or FormatException)
                {
                    throw new InvalidOperationException(
                        "DataProtection:EncryptionKey cannot decrypt the Data Protection key ring stored in the database. " +
                        "Use the key this database was created with (it is kept with the database backup). " +
                        "Starting anyway would make every stored bunny.net API key unreadable.", ex);
                }
            }
        }

        if (entries.Count == 0)
        {
            var storedKeys = await ReadStringsAsync(connection, "SELECT COUNT(*) FROM Users WHERE BunnyApiKey IS NOT NULL", ct);
            if (storedKeys.Count == 1 && storedKeys[0] != "0")
                throw new InvalidOperationException(
                    "The database holds protected bunny.net API keys but no Data Protection key ring, so they cannot be read. " +
                    "Restore the DataProtectionKeys table from the same backup as the rest of the database.");
        }
    }

    private static async Task<List<string>> ReadStringsAsync(DbConnection connection, string sql, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync(ct);
        var values = new List<string>();
        while (await reader.ReadAsync(ct))
            values.Add(Convert.ToString(reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture)!);
        return values;
    }
}
