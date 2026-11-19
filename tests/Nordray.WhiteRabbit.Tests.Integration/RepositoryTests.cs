using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Audit;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Infrastructure.Grants;
using Nordray.WhiteRabbit.Proxy;

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
    public async Task Grants_StoreReplaceAndRead()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        await TestDatabase.Dao<IUserRepository>(connection)
            .InsertAsync(new User { Subject = "sub-1", Email = "a@example.com", CreatedUtc = Now, LastLoginUtc = Now });
        await new CapabilitySeeder(TestDatabase.Dao<ICapabilityDao>(connection), new BunnyOperationRegistry()).SeedAsync();
        var grants = new GrantService(TestDatabase.Dao<IGrantDao>(connection));

        Assert.Empty(await grants.GetGrantedCapabilitiesAsync("a@example.com", "example-client"));

        await grants.StoreGrantAsync("a@example.com", "example-client", ["pullzone.read", "statistics.read", "no.such.capability"]);
        Assert.Equal(new HashSet<string> { "pullzone.read", "statistics.read" }, await grants.GetGrantedCapabilitiesAsync("a@example.com", "example-client"));

        // A new grant replaces the old one rather than adding to it.
        await grants.StoreGrantAsync("a@example.com", "example-client", ["statistics.read"]);
        Assert.Equal(new HashSet<string> { "statistics.read" }, await grants.GetGrantedCapabilitiesAsync("a@example.com", "example-client"));

        // Grants are per client.
        Assert.Empty(await grants.GetGrantedCapabilitiesAsync("a@example.com", "other-client"));
    }

    [Fact]
    public async Task Grants_UnknownUser_ThrowsAndWritesNothing()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var grants = new GrantService(TestDatabase.Dao<IGrantDao>(connection));

        await Assert.ThrowsAsync<InvalidOperationException>(() => grants.StoreGrantAsync("nobody@example.com", "example-client", ["statistics.read"]));

        await using var check = db.Factory.Create();
        await check.OpenAsync();
        await using var command = check.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM OAuthClients";
        Assert.Equal(0L, Convert.ToInt64(await command.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task CapabilitySeeder_IsIdempotentAndCoversTheRegistry()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var capabilities = TestDatabase.Dao<ICapabilityDao>(connection);
        var registry = new BunnyOperationRegistry();
        var seeder = new CapabilitySeeder(capabilities, registry);

        await seeder.SeedAsync();
        await seeder.SeedAsync();

        var expected = registry.GetAll().Select(op => op.RequiredCapability).OfType<string>().Distinct().Order(StringComparer.Ordinal);
        Assert.Equal(expected, await capabilities.ListNamesAsync());
    }

    [Fact]
    public async Task Audit_RecordsEvent()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        await new AuditService(TestDatabase.Dao<IAuditDao>(connection)).RecordAsync("core.statistics.get", "a@example.com", "example-client", "allowed", 200);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT ClientId || '|' || OperationId || '|' || Outcome || '|' || HttpStatusCode FROM AuditEvents";
        Assert.Equal("a@example.com/example-client|core.statistics.get|allowed|200", await command.ExecuteScalarAsync());
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
