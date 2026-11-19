using Activout.DatabaseClient.Attributes;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

/// <summary>
/// The ASP.NET Core Data Protection key ring. Rows hold XML that the caller has already encrypted.
/// </summary>
public interface IDataProtectionKeyDao
{
    [SqlQuery("SELECT Xml FROM DataProtectionKeys ORDER BY CreatedUtc, FriendlyName")]
    Task<IEnumerable<string>> ListXmlAsync();

    [SqlUpdate("INSERT INTO DataProtectionKeys (FriendlyName, Xml, CreatedUtc) VALUES (@friendlyName, @xml, @createdUtc)")]
    Task InsertAsync([Bind("friendlyName")] string friendlyName, [Bind("xml")] string xml, [Bind("createdUtc")] DateTime createdUtc);
}
