using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Tests.Integration;

/// <summary>Every DAO against a real migrated libSQL database, through LibSqlGateway.</summary>
public class RepositoryTests
{
    private static readonly DateTime Now = new(2026, 11, 19, 10, 0, 0, 123, DateTimeKind.Utc);

    [Fact]
    public async Task Users_InsertFindAndUpdate()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var users = TestDatabase.Dao<IUserRepository>(connection);

        await users.InsertAsync(new User { Subject = "sub-1", Email = "a@example.com", DisplayName = "A", CreatedUtc = Now, LastLoginUtc = Now });
        var user = await users.FindByEmailAsync("a@example.com");
        Assert.NotNull(user);
        Assert.Equal(Now, user.CreatedUtc);
        Assert.Equal(DateTimeKind.Utc, user.CreatedUtc.Kind);
        Assert.Null(user.BunnyApiKey);

        await users.UpdateBunnyApiKeyAsync(user.Id, "protected-blob");
        await users.UpdateLastLoginAsync(user.Id, Now.AddMinutes(5));
        var updated = await users.FindBySubjectAsync("sub-1");
        Assert.Equal("protected-blob", updated!.BunnyApiKey);
        Assert.Equal(Now.AddMinutes(5), updated.LastLoginUtc);

        Assert.Null(await users.FindByEmailAsync("nobody@example.com"));
    }

    [Fact]
    public async Task LoginCodes_ActiveCountConsumeAndCleanup()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var codes = TestDatabase.Dao<ILoginCodeRepository>(connection);

        await codes.InsertAsync(new LoginCode { Email = "a@example.com", CodeHash = "h1", CodeSalt = "s1", CreatedUtc = Now, ExpiresUtc = Now.AddMinutes(10), RequestIp = "127.0.0.1" });

        var active = await codes.FindActiveByEmailAsync("a@example.com", Now.AddMinutes(1));
        Assert.NotNull(active);
        Assert.Equal("h1", active.CodeHash);
        // Text comparison of the stored timestamps must follow time order.
        Assert.Null(await codes.FindActiveByEmailAsync("a@example.com", Now.AddMinutes(11)));
        Assert.Equal(1, await codes.CountByEmailSinceAsync("a@example.com", Now.AddHours(-1)));
        Assert.Equal(0, await codes.CountByEmailSinceAsync("a@example.com", Now.AddSeconds(1)));

        await codes.IncrementFailedAttemptsAsync(active.Id);
        await codes.MarkConsumedAsync(active.Id, Now.AddMinutes(2));
        Assert.Null(await codes.FindActiveByEmailAsync("a@example.com", Now.AddMinutes(3)));

        Assert.Equal(0, await codes.DeleteExpiredAsync(Now));
        Assert.Equal(1, await codes.DeleteExpiredAsync(Now.AddHours(1)));
    }

    [Fact]
    public async Task CliLoginCodes_ConsumeOnceAndOnlyBeforeExpiry()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var users = TestDatabase.Dao<IUserRepository>(connection);
        await users.InsertAsync(new User { Subject = "sub-1", Email = "a@example.com", CreatedUtc = Now, LastLoginUtc = Now });
        var userId = (await users.FindByEmailAsync("a@example.com"))!.Id;
        var codes = TestDatabase.Dao<ICliLoginCodeDao>(connection);
        await codes.InsertAsync(new CliLoginCode { CodeHash = "h1", CodeChallenge = "c1", UserId = userId, CreatedUtc = Now, ExpiresUtc = Now.AddMinutes(2) });
        await codes.InsertAsync(new CliLoginCode { CodeHash = "h2", CodeChallenge = "c2", UserId = userId, CreatedUtc = Now, ExpiresUtc = Now.AddMinutes(2) });

        var consumed = await codes.ConsumeAsync("h1", Now.AddMinutes(1));
        Assert.Equal(("c1", userId), (consumed!.CodeChallenge, consumed.UserId));
        Assert.Equal(Now.AddMinutes(1), consumed.ConsumedUtc);
        Assert.Null(await codes.ConsumeAsync("h1", Now.AddMinutes(1)));
        Assert.Null(await codes.ConsumeAsync("h2", Now.AddMinutes(2)));
        Assert.Null(await codes.ConsumeAsync("nope", Now));
    }

    [Fact]
    public async Task SecurityEvents_RecordsEvent()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        await TestDatabase.Dao<ISecurityEventDao>(connection).InsertAsync(new SecurityEvent
        {
            OccurredUtc = Now,
            EventType = "proxy.request",
            Outcome = SecurityEvent.Allowed,
            OperationId = "core.statistics.get",
            ClientId = "example-client",
            HttpStatus = 200,
            UpstreamStatus = 200,
        });

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT EventType || '|' || Outcome || '|' || OperationId || '|' || ClientId || '|' || HttpStatus || '|' || UpstreamStatus FROM SecurityEvents";
        Assert.Equal("proxy.request|allowed|core.statistics.get|example-client|200|200", await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task DataProtectionKeys_InsertAndListInOrder()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var keys = TestDatabase.Dao<IDataProtectionKeyDao>(connection);

        await keys.InsertAsync("key-b", "<b/>", Now.AddDays(1));
        await keys.InsertAsync("key-a", "<a/>", Now);

        Assert.Equal(["<a/>", "<b/>"], await keys.ListXmlAsync());
    }
}
