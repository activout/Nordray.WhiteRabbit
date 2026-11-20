using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

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

    [Fact]
    public async Task Login_RateLimitedAllowedAddress_AnswersLikeAnyOther()
    {
        var client = _factory.CreateHttpsClient();
        var statuses = new List<string>();
        for (var i = 0; i < 8; i++)
        {
            var form = await client.GetStringAsync("/login");
            var response = await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Email"] = WhiteRabbitFactory.AllowedEmail,
                ["__RequestVerificationToken"] = AntiforgeryToken().Match(form).Groups[1].Value,
            }));
            statuses.Add($"{(int)response.StatusCode} {response.Headers.Location?.OriginalString.Split('?')[0]}");
        }

        Assert.All(statuses, s => Assert.Equal("302 /LoginVerify", s));
        Assert.True(_factory.Emails.Recipients.Count < 8, "the per-address limit should have stopped some codes");
    }

    [Fact]
    public async Task Login_SecondRequestWithinCooldown_SendsNoSecondCode()
    {
        var client = _factory.CreateHttpsClient();
        await RequestCodeAsync(client, WhiteRabbitFactory.AllowedEmail);
        await RequestCodeAsync(client, WhiteRabbitFactory.AllowedEmail.ToUpperInvariant());

        Assert.Single(_factory.Emails.Recipients);
    }

    // --- Redirects stay on White Rabbit ---

    [Theory]
    [InlineData("//evil.example/x")]
    [InlineData("/\\evil.example/x")]
    [InlineData("https://evil.example/x")]
    public async Task LoginVerify_ForeignReturnUrl_RedirectsHome(string returnUrl)
    {
        var client = _factory.CreateHttpsClient();
        var response = await SignInAsync(client, returnUrl);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location!.OriginalString);
    }

    private async Task RequestCodeAsync(HttpClient client, string email)
    {
        var form = await client.GetStringAsync("/login");
        await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = email,
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(form).Groups[1].Value,
        }));
    }

    /// <summary>Signs in with an emailed code and returns the verify response (the redirect after sign-in).</summary>
    private async Task<HttpResponseMessage> SignInAsync(HttpClient client, string returnUrl)
    {
        await RequestCodeAsync(client, WhiteRabbitFactory.AllowedEmail);
        var form = await client.GetStringAsync("/LoginVerify?email=" + Uri.EscapeDataString(WhiteRabbitFactory.AllowedEmail));
        return await client.PostAsync("/LoginVerify", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = WhiteRabbitFactory.AllowedEmail,
            ["Code"] = _factory.Emails.LastCode(WhiteRabbitFactory.AllowedEmail),
            ["ReturnUrl"] = returnUrl,
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(form).Groups[1].Value,
        }));
    }

    // --- Proxy: only virtual credentials ---

    [Theory]
    [InlineData(null)]
    [InlineData("Bearer eyJhbGciOiJSUzI1NiJ9.e30.x")]
    public async Task Proxy_WithoutVirtualCredential_IsUnauthorized(string? authorization)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/proxy/api.bunny.net/statistics");
        if (authorization is not null) request.Headers.TryAddWithoutValidation("Authorization", authorization);
        var response = await _factory.CreateHttpsClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("\"error\":\"unauthenticated\"", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Proxy_UnsupportedOperation_IsNotFound()
    {
        var response = await _factory.CreateHttpsClient().GetAsync("/proxy/api.bunny.net/no/such/endpoint");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

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

        // A different (well-formed) encryption key cannot read the key ring: start-up refuses instead of serving
        // traffic with every stored Bunny key unreadable.
        _factory = new WhiteRabbitFactory(_db.ConnectionString, KeyRingEncryptionTests.NewKey());
        var error = Assert.ThrowsAny<InvalidOperationException>(() => _factory.Services);
        Assert.Contains("cannot decrypt the Data Protection key ring", error.Message);
    }

    [Fact]
    public async Task Startup_RefusesStoredBunnyKeysWithoutAKeyRing()
    {
        await _factory.CreateHttpsClient().GetAsync("/health");
        await _factory.DisposeAsync();
        await using (var connection = _db.Factory.Create())
        {
            await connection.OpenAsync();
            foreach (var sql in new[]
            {
                "INSERT INTO Users (Subject, Email, CreatedUtc, LastLoginUtc, BunnyApiKey) VALUES ('s', 'a@example.com', '2026-01-01 00:00:00.000', '2026-01-01 00:00:00.000', 'protected')",
                "DELETE FROM DataProtectionKeys",
            })
            {
                await using var command = connection.CreateCommand();
                command.CommandText = sql;
                await command.ExecuteNonQueryAsync();
            }
        }

        _factory = new WhiteRabbitFactory(_db.ConnectionString, _encryptionKey);
        var error = Assert.ThrowsAny<InvalidOperationException>(() => _factory.Services);
        Assert.Contains("no Data Protection key ring", error.Message);
    }

    // --- rabbit CLI browser sign-in ---

    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // RFC 7636 appendix B
    private const string State = "state-0123456789abcdef";

    [Fact]
    public async Task CliLogin_EmailCodeThenConfirm_RedirectsToLoopbackWithACodeTheVerifierRedeems()
    {
        var client = _factory.CreateHttpsClient();
        var start = $"/cli/login?port=53682&state={State}&code_challenge={Challenge}";

        var response = await client.GetAsync(start);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/login", PathOf(response), StringComparison.OrdinalIgnoreCase);
        var returnUrl = System.Web.HttpUtility.ParseQueryString(response.Headers.Location!.Query)["ReturnUrl"];
        Assert.Equal(start, returnUrl);

        // The ordinary email-code sign-in, with the return URL carried through.
        var form = await client.GetStringAsync("/login");
        await client.PostAsync("/login", Form(form, ("Email", WhiteRabbitFactory.AllowedEmail), ("ReturnUrl", returnUrl!)));
        form = await client.GetStringAsync($"/LoginVerify?email={WhiteRabbitFactory.AllowedEmail}");
        response = await client.PostAsync("/LoginVerify", Form(form,
            ("Email", WhiteRabbitFactory.AllowedEmail), ("Code", _factory.Emails.LastCode(WhiteRabbitFactory.AllowedEmail)), ("ReturnUrl", returnUrl!)));
        Assert.Equal(start, response.Headers.Location!.OriginalString);

        // An explicit confirmation (POST with antiforgery) before any code is issued.
        form = await client.GetStringAsync(start);
        Assert.Contains(WhiteRabbitFactory.AllowedEmail, form);
        response = await client.PostAsync(start, Form(form, ("Port", "53682"), ("State", State), ("CodeChallenge", Challenge)));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var callback = response.Headers.Location!;
        Assert.Equal("http://127.0.0.1:53682/callback", callback.GetLeftPart(UriPartial.Path));
        var query = System.Web.HttpUtility.ParseQueryString(callback.Query);
        Assert.Equal(State, query["state"]);

        var exchange = await client.PostAsync("/api/cli/exchange", JsonContent.Create(new { code = query["code"], code_verifier = Verifier }));
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
    }

    [Theory]
    [InlineData("port=80&state=" + State + "&code_challenge=" + Challenge)]
    [InlineData("port=53682&state=short&code_challenge=" + Challenge)]
    [InlineData("port=53682&state=" + State + "&code_challenge=plain")]
    [InlineData("port=53682&state=" + State)]
    public async Task CliLogin_InvalidParameters_IssueNoCode(string query)
    {
        var client = await SignedInClientAsync();
        var page = await client.GetStringAsync("/cli/login?" + query);
        Assert.Contains("not valid", page);
        Assert.DoesNotContain("<form", page);

        // Posting anyway does not redirect anywhere.
        var form = await client.GetStringAsync($"/cli/login?port=53682&state={State}&code_challenge={Challenge}");
        var parsed = System.Web.HttpUtility.ParseQueryString(query);
        var response = await client.PostAsync("/cli/login", Form(form,
            ("Port", parsed["port"] ?? ""), ("State", parsed["state"] ?? ""), ("CodeChallenge", parsed["code_challenge"] ?? "")));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CliLogin_WithoutAntiforgeryToken_IsRefused()
    {
        var client = await SignedInClientAsync();
        var response = await client.PostAsync("/cli/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Port"] = "53682", ["State"] = State, ["CodeChallenge"] = Challenge,
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task CliLogin_BearerTokenDoesNotSignIn()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"/cli/login?port=53682&state={State}&code_challenge={Challenge}");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer wrs_" + new string('A', 43));
        var response = await _factory.CreateHttpsClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/login", PathOf(response), StringComparison.OrdinalIgnoreCase);
    }

    private async Task<HttpClient> SignedInClientAsync()
    {
        var client = _factory.CreateHttpsClient();
        var form = await client.GetStringAsync("/login");
        await client.PostAsync("/login", Form(form, ("Email", WhiteRabbitFactory.AllowedEmail)));
        form = await client.GetStringAsync($"/LoginVerify?email={WhiteRabbitFactory.AllowedEmail}");
        var response = await client.PostAsync("/LoginVerify", Form(form,
            ("Email", WhiteRabbitFactory.AllowedEmail), ("Code", _factory.Emails.LastCode(WhiteRabbitFactory.AllowedEmail))));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    private static string PathOf(HttpResponseMessage response)
    {
        var location = response.Headers.Location!;
        return location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString;
    }

    /// <summary>The form's fields plus the page's antiforgery token.</summary>
    private static FormUrlEncodedContent Form(string page, params (string Name, string Value)[] fields) =>
        new(fields.Select(f => KeyValuePair.Create(f.Name, f.Value))
            .Append(KeyValuePair.Create("__RequestVerificationToken", AntiforgeryToken().Match(page).Groups[1].Value)));

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}
