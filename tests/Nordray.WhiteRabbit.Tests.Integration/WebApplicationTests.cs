using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Nordray.WhiteRabbit.Tests.Integration;

public partial class WebApplicationTests : IAsyncLifetime
{
    private TestDatabase _db = null!;
    private WhiteRabbitFactory _factory = null!;
    private readonly string _encryptionKey = KeyRingEncryptionTests.NewKey();

    public async Task InitializeAsync()
    {
        _db = await TestDatabase.CreateAsync(migrate: false);
        _factory = new WhiteRabbitFactory(_db.ConnectionString, _encryptionKey);
    }

    public async Task DisposeAsync()
    {
        await _factory.DisposeAsync();
        await _db.DisposeAsync();
    }

    // --- Health ---

    [Fact]
    public async Task Health_ReturnsOk()
    {
        var response = await _factory.CreateHttpsClient().GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Ready_AfterStartup_ReturnsOk()
    {
        var response = await _factory.CreateHttpsClient().GetAsync("/ready");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Ready_WithPendingMigration_Returns503WithoutDetails()
    {
        var client = _factory.CreateHttpsClient();
        await client.GetAsync("/health"); // starts the app, which applies the migrations

        await using (var connection = _db.Factory.Create())
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM SchemaMigrations";
            await command.ExecuteNonQueryAsync();
        }

        var response = await client.GetAsync("/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("""{"status":"not_ready","reason":"migrations_pending"}""", await response.Content.ReadAsStringAsync());
    }

    // --- Sign-in allow-list ---

    [Theory]
    [InlineData(WhiteRabbitFactory.AllowedEmail, true)]
    [InlineData("Allowed@Example.com", true)]
    [InlineData("someone@" + WhiteRabbitFactory.AllowedDomain, true)]
    [InlineData("stranger@example.org", false)]
    [InlineData("someone@sub." + WhiteRabbitFactory.AllowedDomain, false)]
    public async Task Login_SendsCodeOnlyToAllowedAddresses_AndAnswersTheSameEitherWay(string email, bool sent)
    {
        var client = _factory.CreateHttpsClient();
        var form = await client.GetStringAsync("/login");
        var token = AntiforgeryToken().Match(form).Groups[1].Value;

        var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = email,
            ["__RequestVerificationToken"] = token,
        }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/LoginVerify", response.Headers.Location!.OriginalString, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(sent, _factory.Emails.Recipients.Contains(email));
    }

    // --- Proxy: audience and client identity ---

    [Fact]
    public async Task Proxy_TokenForConfiguredClient_ReachesTheCapabilityCheck()
    {
        await EnsureUserAsync(WhiteRabbitFactory.AllowedEmail);
        await AssertProxy(WhiteRabbitFactory.Token(), HttpStatusCode.Forbidden, "capability_not_granted");
    }

    [Fact]
    public async Task Proxy_AzpOfConfiguredClient_IsAccepted()
    {
        await EnsureUserAsync(WhiteRabbitFactory.AllowedEmail);
        await AssertProxy(
            WhiteRabbitFactory.Token(audiences: [WhiteRabbitFactory.ProxyClient, "other"], azp: WhiteRabbitFactory.ProxyClient),
            HttpStatusCode.Forbidden, "capability_not_granted");
    }

    [Fact]
    public async Task Proxy_TokenForUserWhoNeverSignedIn_IsForbidden() =>
        await AssertProxy(WhiteRabbitFactory.Token(), HttpStatusCode.Forbidden, "user_not_allowed");

    [Fact]
    public async Task Proxy_TokenForAnotherAudience_IsUnauthorized() =>
        await AssertProxy(WhiteRabbitFactory.Token(audiences: ["some-other-client"]), HttpStatusCode.Unauthorized);

    [Fact]
    public async Task Proxy_SeveralAudiencesWithoutAzp_IsRejected() =>
        await AssertProxy(
            WhiteRabbitFactory.Token(audiences: [WhiteRabbitFactory.ProxyClient, "other"]),
            HttpStatusCode.Forbidden, "proxy_requires_oidc");

    [Fact]
    public async Task Proxy_AzpNotAmongAudiences_IsRejected() =>
        await AssertProxy(
            WhiteRabbitFactory.Token(audiences: [WhiteRabbitFactory.ProxyClient], azp: "other"),
            HttpStatusCode.Forbidden, "proxy_requires_oidc");

    [Fact]
    public async Task Proxy_WrongIssuer_IsUnauthorized() =>
        await AssertProxy(WhiteRabbitFactory.Token(issuer: "https://codebahn.net/api/actions"), HttpStatusCode.Unauthorized);

    [Fact]
    public async Task Proxy_WrongSignature_IsUnauthorized() =>
        await AssertProxy(
            WhiteRabbitFactory.Token(key: new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32))),
            HttpStatusCode.Unauthorized);

    [Fact]
    public async Task Proxy_ExpiredToken_IsUnauthorized() =>
        await AssertProxy(WhiteRabbitFactory.Token(expires: DateTime.UtcNow.AddMinutes(-10)), HttpStatusCode.Unauthorized);

    [Fact]
    public async Task Proxy_UserNotOnAllowList_IsForbidden() =>
        await AssertProxy(WhiteRabbitFactory.Token(email: "stranger@example.org"), HttpStatusCode.Forbidden, "user_not_allowed");

    [Fact]
    public async Task Proxy_UnsupportedOperation_IsNotFound() =>
        await AssertProxy(WhiteRabbitFactory.Token(), HttpStatusCode.NotFound, path: "/proxy/api.bunny.net/no/such/endpoint");

    // --- Data Protection key ring ---

    [Fact]
    public async Task DataProtection_KeysSurviveARestartAndAreEncryptedAtRest()
    {
        var protectedValue = _factory.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("BunnyApiKey.v1").Protect("bunny-api-key");
        await _factory.DisposeAsync();

        await using (var connection = _db.Factory.Create())
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT Xml FROM DataProtectionKeys";
            var xml = (string)(await command.ExecuteScalarAsync())!;
            Assert.Contains("<encryptedSecret decryptorType=\"Nordray.WhiteRabbit.Web.DataProtection.KeyRingDecryptor,", xml);
            Assert.DoesNotContain("<masterKey", xml);
        }

        // Same database and encryption key: the stored value is still readable after a "container replacement".
        _factory = new WhiteRabbitFactory(_db.ConnectionString, _encryptionKey);
        Assert.Equal("bunny-api-key", _factory.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("BunnyApiKey.v1").Unprotect(protectedValue));
        await _factory.DisposeAsync();

        // A different encryption key cannot read the key ring, so the value cannot be unprotected.
        _factory = new WhiteRabbitFactory(_db.ConnectionString, KeyRingEncryptionTests.NewKey());
        Assert.ThrowsAny<CryptographicException>(() => _factory.Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("BunnyApiKey.v1").Unprotect(protectedValue));
    }

    /// <summary>Starts the app (which migrates the database) and creates the user, as a real login would.</summary>
    private async Task<long> EnsureUserAsync(string email)
    {
        await _factory.CreateHttpsClient().GetAsync("/health");
        await using var connection = _db.Factory.Create();
        var users = TestDatabase.Dao<Nordray.WhiteRabbit.Infrastructure.Database.IUserRepository>(connection);
        if (await users.FindByEmailAsync(email) is null)
            await users.InsertAsync(new Nordray.WhiteRabbit.Core.Models.User
            {
                Subject = "subject-" + email, Email = email, CreatedUtc = DateTime.UtcNow, LastLoginUtc = DateTime.UtcNow,
            });
        return (await users.FindByEmailAsync(email))!.Id;
    }

    private async Task AssertProxy(string token, HttpStatusCode expected, string? error = null, string path = "/proxy/api.bunny.net/statistics")
    {
        var client = _factory.CreateHttpsClient();
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.SendAsync(request);
        Assert.Equal(expected, response.StatusCode);
        if (error is not null)
            Assert.Contains($"\"error\":\"{error}\"", await response.Content.ReadAsStringAsync());
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}
