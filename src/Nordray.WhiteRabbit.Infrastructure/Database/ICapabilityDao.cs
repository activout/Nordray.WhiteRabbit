using Activout.DatabaseClient.Attributes;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface ICapabilityDao
{
    /// <summary>Inserts the capability, or updates its text to the registry's current description.</summary>
    [SqlUpdate("""
        INSERT INTO Capabilities (Name, DisplayName, Description, CreatedUtc)
        VALUES (@name, @displayName, @description, @now)
        ON CONFLICT (Name) DO UPDATE SET DisplayName = excluded.DisplayName, Description = excluded.Description
        """)]
    Task EnsureAsync(
        [Bind("name")] string name,
        [Bind("displayName")] string displayName,
        [Bind("description")] string description,
        [Bind("now")] DateTime now);

    [SqlQuery("SELECT Name FROM Capabilities ORDER BY Name")]
    Task<IEnumerable<string>> ListNamesAsync();
}
