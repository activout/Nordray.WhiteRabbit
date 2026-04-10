using Activout.DatabaseClient.Attributes;
using Nordray.WhiteRabbit.Core.Models;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface IUserRepository
{
    [SqlQuery("SELECT * FROM Users WHERE Email = @email LIMIT 1")]
    Task<User?> FindByEmailAsync([Bind("email")] string email);

    [SqlQuery("SELECT * FROM Users WHERE Subject = @subject LIMIT 1")]
    Task<User?> FindBySubjectAsync([Bind("subject")] string subject);

    [SqlUpdate("INSERT INTO Users (Subject, Email, DisplayName, CreatedUtc, LastLoginUtc) VALUES (@Subject, @Email, @DisplayName, @CreatedUtc, @LastLoginUtc)")]
    Task InsertAsync([BindProperties] User user);

    [SqlUpdate("UPDATE Users SET LastLoginUtc = @lastLoginUtc WHERE Id = @id")]
    Task UpdateLastLoginAsync([Bind("id")] long id, [Bind("lastLoginUtc")] DateTimeOffset lastLoginUtc);

    [SqlUpdate("UPDATE Users SET BunnyApiKey = @apiKey WHERE Id = @id")]
    Task UpdateBunnyApiKeyAsync([Bind("id")] long id, [Bind("apiKey")] string? apiKey);
}
