using Activout.DatabaseClient.Attributes;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface ICapabilityDao
{
    /// <summary>Inserts the capability if no capability with that name exists yet.</summary>
    [SqlUpdate("""
        INSERT OR IGNORE INTO Capabilities (Name, DisplayName, Description, CreatedUtc)
        VALUES (@name, @displayName, @description, @now)
        """)]
    Task EnsureAsync(
        [Bind("name")] string name,
        [Bind("displayName")] string displayName,
        [Bind("description")] string description,
        [Bind("now")] DateTime now);

    [SqlQuery("SELECT Name FROM Capabilities ORDER BY Name")]
    Task<IEnumerable<string>> ListNamesAsync();
}
