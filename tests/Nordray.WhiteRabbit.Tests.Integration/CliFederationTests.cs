using System.Data.Common;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;
using RichardSzalay.MockHttp;

namespace Nordray.WhiteRabbit.Tests.Integration;

/// <summary>
/// The rabbit CLI flows end to end: token exchange for humans (Dex) and CI workloads (GitHub, Forgejo), virtual
/// credentials, the Bunny proxy with a fake upstream, binding administration and the audit trail.
/// </summary>
public abstract class CliFederationTests : IAsyncLifetime
{
    protected const string Email = WhiteRabbitFactory.AllowedEmail;
    protected const string RealBunnyKey = "real-bunny-account-key-0123456789";

    protected TestDatabase _db = null!;
    protected WhiteRabbitFactory _factory = null!;
    protected HttpClient _client = null!;
    protected readonly List<HttpRequestMessage> _upstreamRequests = [];
    protected readonly List<string> _upstreamBodies = [];

    /// <summary>What the fake api.bunny.net answers; tests replace it.</summary>
    protected Func<HttpRequestMessage, HttpResponseMessage> _upstream =
        _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"ok":true}""") };

    public async Task InitializeAsync()
    {
        _db = await TestDatabase.CreateAsync(migrate: false);
        _factory = new WhiteRabbitFactory(_db.ConnectionString, KeyRingEncryptionTests.NewKey());
        _factory.Upstream.When("https://api.bunny.net/*").Respond(request =>
        {
            var body = request.Content?.ReadAsStringAsync().GetAwaiter().GetResult() ?? "";
            lock (_upstreamRequests)
            {
                _upstreamRequests.Add(request);
                _upstreamBodies.Add(body);
            }
            return _upstream(request);
        });
        _client = _factory.CreateHttpsClient();
        await _client.GetAsync("/health"); // starts the app and applies migrations
    }

    public async Task DisposeAsync()
    {
        await _factory.DisposeAsync();
        await _db.DisposeAsync();
    }

    // ================================================================ helpers

    protected sealed record BindingBody(
        string Issuer, string Repository, string? RepositoryId, string Ref, string WorkflowRef,
        string? Environment = null, string[]? Events = null, string[]? Capabilities = null);

    protected static BindingBody GitHubBinding(string? environment = null) => new(
        "github", "activout/rabbit-ci-test", "123456", "refs/heads/main",
        "activout/rabbit-ci-test/.github/workflows/rabbit.yml@refs/heads/main",
        environment, Capabilities: ["statistics.read"]);

    protected static BindingBody ForgejoBinding() => new(
        "codebahn", "activout/rabbit-ci-test", null, "refs/heads/main",
        "activout/rabbit-ci-test/.forgejo/workflows/rabbit.yml@refs/heads/main",
        Capabilities: ["statistics.read"]);

    protected static string GitHubToken(Dictionary<string, object>? claims = null) =>
        IdentityTokens.Create(WhiteRabbitFactory.GitHubIssuer, WhiteRabbitFactory.FederationAudience, claims ?? IdentityTokens.GitHubClaims());

    protected static string ForgejoToken(Dictionary<string, object>? claims = null) =>
        IdentityTokens.Create(WhiteRabbitFactory.ForgejoIssuer, WhiteRabbitFactory.FederationAudience, claims ?? IdentityTokens.ForgejoClaims());

    protected static string DexToken(string email, string audience = WhiteRabbitFactory.CliClient, DateTime? issuedAt = null, TimeSpan? lifetime = null) =>
        IdentityTokens.Create(WhiteRabbitFactory.Issuer, audience, new Dictionary<string, object> { ["sub"] = "dex-" + email, ["email"] = email }, issuedAt, lifetime);

    /// <summary>A signed-in human with a stored Bunny key and a session for the rabbit CLI.</summary>
    protected async Task<string> HumanSessionAsync(params string[] grants)
    {
        await CreateUserAsync(Email);
        if (grants.Length > 0) await GrantAsync(Email, WhiteRabbitFactory.CliClient, grants);
        var (status, body) = await ExchangeAsync(DexToken(Email));
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()!;
    }

    protected async Task CreateUserAsync(string email)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserRepository>();
        if (await users.FindByEmailAsync(email) is not null) return;
        await users.InsertAsync(new User { Subject = "subject-" + email, Email = email, CreatedUtc = DateTime.UtcNow, LastLoginUtc = DateTime.UtcNow });
        var user = (await users.FindByEmailAsync(email))!;
        var protector = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("BunnyApiKey.v1");
        await users.UpdateBunnyApiKeyAsync(user.Id, protector.Protect(RealBunnyKey));
    }

    protected async Task GrantAsync(string email, string client, params string[] capabilities)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IGrantService>().StoreGrantAsync(email, client, capabilities);
    }

    protected async Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(string token)
    {
        var response = await _client.PostAsJsonAsync("/api/cli/exchange", new { subject_token = token });
        return (response.StatusCode, await response.Content.ReadFromJsonAsync<JsonElement>());
    }

    protected async Task AssertExchangeDenied(string token, string reason)
    {
        var (status, body) = await ExchangeAsync(token);
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(reason, body.GetProperty("reason").GetString());
        var events = await SecurityEventsAsync();
        Assert.Contains(events, e => (string?)e["EventType"] == "cli.exchange" && (string?)e["Outcome"] == "denied" && (string?)e["Reason"] == reason);
        Assert.Empty(_upstreamRequests);
    }

    protected async Task<(HttpStatusCode Status, JsonElement Body)> CreateBindingAsync(string session, BindingBody body)
    {
        var response = await SendAsync(HttpMethod.Post, "/api/admin/bindings", session, new
        {
            issuer = body.Issuer,
            repository = body.Repository,
            repository_id = body.RepositoryId,
            @ref = body.Ref,
            workflow_ref = body.WorkflowRef,
            environment = body.Environment,
            events = body.Events,
            capabilities = body.Capabilities,
        });
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    protected async Task<string> CredentialAsync(string session, params string[] capabilities)
    {
        var response = await SendAsync(HttpMethod.Post, "/api/cli/credentials", session, capabilities.Length > 0 ? new { capabilities } : null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_key").GetString()!;
    }

    protected async Task<JsonElement> GetJsonAsync(string path, string session)
    {
        var response = await SendAsync(HttpMethod.Get, path, session);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    protected Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string session, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session);
        if (body is not null) request.Content = JsonContent.Create(body);
        return _client.SendAsync(request);
    }

    protected Task<HttpResponseMessage> ProxyAsync(
        string accessKey, string path, string? correlationId = null, Dictionary<string, string>? headers = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("AccessKey", accessKey);
        foreach (var (name, value) in headers ?? [])
            request.Headers.TryAddWithoutValidation(name, value);
        if (correlationId is not null) request.Headers.Add("X-Correlation-ID", correlationId);
        return _client.SendAsync(request);
    }

    protected async Task<List<Dictionary<string, object?>>> SecurityEventsAsync()
    {
        await using var connection = _db.Factory.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM SecurityEvents ORDER BY Id";
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<Dictionary<string, object?>>();
        while (await reader.ReadAsync())
            rows.Add(Enumerable.Range(0, reader.FieldCount).ToDictionary(reader.GetName, i => reader.IsDBNull(i) ? null : reader.GetValue(i)));
        return rows;
    }

    protected async Task AssertNoSecretsInAuditAsync(params string[] secrets)
    {
        foreach (var row in await SecurityEventsAsync())
            foreach (var value in row.Values.OfType<string>())
                foreach (var secret in secrets)
                    Assert.DoesNotContain(secret, value);

        // Nor anywhere else in the database: sessions and keys are stored as hashes only.
        await using var connection = _db.Factory.Create();
        await connection.OpenAsync();
        foreach (var table in new[] { "CliSessions", "VirtualCredentials", "SecurityEvents", "WorkloadBindings" })
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM {table}";
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
                for (var i = 0; i < reader.FieldCount; i++)
                    if (!reader.IsDBNull(i) && reader.GetValue(i) is string value)
                        foreach (var secret in secrets.Where(s => !s.StartsWith("real-", StringComparison.Ordinal)))
                            Assert.DoesNotContain(secret, value);
        }
    }

    protected async Task ExecuteAsync(string sql)
    {
        await using var connection = _db.Factory.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}

public class CliFederationDiscoveryTests : CliFederationTests
{

    [Fact]
    public async Task Config_TellsTheCliItsClientAudienceAndCapabilities()
    {
        var config = await _client.GetFromJsonAsync<JsonElement>("/api/cli/config");
        Assert.Equal(WhiteRabbitFactory.CliClient, config.GetProperty("dex_client_id").GetString());
        Assert.Equal(WhiteRabbitFactory.FederationAudience, config.GetProperty("federation_audience").GetString());
        Assert.Contains(config.GetProperty("capabilities").EnumerateArray(), c => c.GetProperty("name").GetString() == "statistics.read");
    }

    [Fact]
    public async Task Config_DescribesEachCapabilityAsAWhole()
    {
        var config = await _client.GetFromJsonAsync<JsonElement>("/api/cli/config");
        var mcRead = config.GetProperty("capabilities").EnumerateArray().Single(c => c.GetProperty("name").GetString() == "mc.read");
        var description = mcRead.GetProperty("description").GetString()!;
        Assert.Contains("registries", description);
        Assert.Contains("redacted", description);
    }

}

public class CliFederationHumanExchangeTests : CliFederationTests
{

    [Fact]
    public async Task Human_ExchangeDexToken_GetsSessionWithGrantedCapabilities()
    {
        await CreateUserAsync(Email);
        await GrantAsync(Email, WhiteRabbitFactory.CliClient, "statistics.read");

        var (status, body) = await ExchangeAsync(DexToken(Email));

        Assert.Equal(HttpStatusCode.OK, status);
        var token = body.GetProperty("access_token").GetString()!;
        Assert.StartsWith("wrs_", token);
        Assert.Equal("human", body.GetProperty("principal").GetProperty("type").GetString());

        var whoami = await GetJsonAsync("/api/cli/whoami", token);
        Assert.Equal(Email, whoami.GetProperty("email").GetString());
        Assert.Equal(["statistics.read"], whoami.GetProperty("capabilities").EnumerateArray().Select(e => e.GetString()));
    }

    [Theory]
    [InlineData("example-client", "wrong_audience")]
    [InlineData("whiterabbit:test", "wrong_audience")]
    public async Task Human_DexTokenForAnotherAudience_IsDenied(string audience, string reason)
    {
        await CreateUserAsync(Email);
        await AssertExchangeDenied(DexToken(Email, audience: audience), reason);
    }

    [Fact]
    public async Task Human_OldDexToken_IsDeniedEvenIfStillValid() =>
        await AssertExchangeDenied(
            DexToken(Email, issuedAt: DateTime.UtcNow.AddMinutes(-20), lifetime: TimeSpan.FromHours(1)), "token_too_old");

    [Fact]
    public async Task Human_NotOnAllowList_IsDenied()
    {
        await CreateUserAsync("stranger@example.org");
        await AssertExchangeDenied(DexToken("stranger@example.org"), "user_not_allowed");
    }

}

public class CliFederationGitHubWorkloadTests : CliFederationTests
{

    [Fact]
    public async Task GitHub_MatchingBinding_EndToEnd_InjectsOwnerKeyAndAuditsWithoutSecrets()
    {
        var human = await HumanSessionAsync();
        var binding = await CreateBindingAsync(human, GitHubBinding());
        Assert.Equal(HttpStatusCode.Created, binding.Status);

        var (status, body) = await ExchangeAsync(GitHubToken());
        Assert.Equal(HttpStatusCode.OK, status);
        var session = body.GetProperty("access_token").GetString()!;
        var principal = body.GetProperty("principal");
        Assert.Equal("github_workload", principal.GetProperty("type").GetString());
        Assert.Equal("123456", principal.GetProperty("repository_id").GetString());
        Assert.Equal(Email, principal.GetProperty("owner").GetString());

        var key = await CredentialAsync(session);
        Assert.StartsWith("wrk_", key);

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/statistics", correlationId: "corr-123", headers: new()
        {
            ["Cookie"] = "WhiteRabbit.Session=secret",
            ["Proxy-Authorization"] = "Basic c2VjcmV0",
            ["X-Remote-User"] = "victim@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("corr-123", response.Headers.GetValues("X-Correlation-ID").Single());

        // Upstream got the owner's real key, and none of the caller's credentials.
        var upstream = Assert.Single(_upstreamRequests);
        Assert.Equal("https://api.bunny.net/statistics", upstream.RequestUri!.ToString());
        Assert.Equal(RealBunnyKey, upstream.Headers.GetValues("AccessKey").Single());
        foreach (var header in new[] { "Authorization", "Cookie", "Proxy-Authorization", "X-Remote-User" })
            Assert.False(upstream.Headers.Contains(header), header);

        // Every step is audited, attributed to the workload, and no secret appears anywhere in the trail.
        var events = await SecurityEventsAsync();
        var proxy = events.Single(e => (string?)e["EventType"] == "proxy.request");
        Assert.Equal("allowed", proxy["Outcome"]);
        Assert.Equal("github_workload", proxy["PrincipalType"]);
        Assert.Equal("123456", proxy["RepositoryId"]);
        Assert.Equal("4242", proxy["RunId"]);
        Assert.Equal("core.statistics.get", proxy["OperationId"]);
        Assert.Equal(200L, proxy["UpstreamStatus"]);
        Assert.Equal("corr-123", proxy["CorrelationId"]);
        Assert.NotNull(proxy["CredentialId"]);
        Assert.Contains(events, e => (string?)e["EventType"] == "cli.exchange" && (string?)e["Outcome"] == "allowed" && (string?)e["PrincipalType"] == "github_workload");
        Assert.Contains(events, e => (string?)e["EventType"] == "cli.credential");
        Assert.Contains(events, e => (string?)e["EventType"] == "admin.binding.create");
        await AssertNoSecretsInAuditAsync(human, session, key, RealBunnyKey);
    }

    public static TheoryData<string, string> GitHubNegativeCases() => new()
    {
        { "repository_id", "no_matching_binding" },
        { "repository_name", "no_matching_binding" },
        { "ref", "no_matching_binding" },
        { "workflow_ref", "no_matching_binding" },
        { "workflow_ref_other_ref", "workflow_ref_mismatch" },
        { "pull_request", "event_not_allowed" },
        { "pull_request_target", "event_not_allowed" },
        { "event_not_listed", "no_matching_binding" },
        { "pr_ref", "ref_not_allowed" },
        { "environment", "no_matching_binding" },
        { "audience_prod", "wrong_audience" },
        { "audience_dex_client", "wrong_audience" },
        { "unknown_issuer", "untrusted_issuer" },
        { "wrong_key", "invalid_signature" },
        { "expired", "token_expired" },
        { "not_yet_valid", "token_not_yet_valid" },
        { "too_long_lived", "token_lifetime_too_long" },
        // An HMAC token signed with a guessed secret (the classic RSA/HMAC confusion attack).
        { "hs256", "algorithm_not_allowed" },
        // The issuer's real key, but an algorithm outside the RS256-only allow-list.
        { "rs384", "algorithm_not_allowed" },
        { "missing_repository_id", "missing_claims" },
    };

    [Theory]
    [MemberData(nameof(GitHubNegativeCases))]
    public async Task GitHub_ForgedOrOverbroadClaims_AreDeniedAndAudited(string variant, string reason)
    {
        var human = await HumanSessionAsync();
        Assert.Equal(HttpStatusCode.Created, (await CreateBindingAsync(human, GitHubBinding(environment: "production"))).Status);

        var claims = IdentityTokens.GitHubClaims(environment: "production");
        string audience = WhiteRabbitFactory.FederationAudience, issuer = WhiteRabbitFactory.GitHubIssuer;
        DateTime? issuedAt = null;
        TimeSpan? lifetime = null;
        SigningCredentials? credentials = null;
        switch (variant)
        {
            case "repository_id": claims["repository_id"] = "654321"; break;
            case "repository_name": claims = IdentityTokens.GitHubClaims(repository: "activout/other", environment: "production"); claims["repository_id"] = "123456"; break;
            case "ref": claims = IdentityTokens.GitHubClaims(@ref: "refs/heads/feature", environment: "production"); break;
            case "workflow_ref": claims["workflow_ref"] = "activout/rabbit-ci-test/.github/workflows/other.yml@refs/heads/main"; break;
            case "workflow_ref_other_ref": claims["workflow_ref"] = "activout/rabbit-ci-test/.github/workflows/rabbit.yml@refs/heads/feature"; break;
            case "pull_request": claims["event_name"] = "pull_request"; break;
            case "pull_request_target": claims["event_name"] = "pull_request_target"; break;
            case "event_not_listed": claims["event_name"] = "schedule"; break;
            case "pr_ref":
                claims["ref"] = "refs/pull/1/merge";
                claims["workflow_ref"] = "activout/rabbit-ci-test/.github/workflows/rabbit.yml@refs/pull/1/merge";
                break;
            case "environment": claims["environment"] = "staging"; break;
            case "audience_prod": audience = "whiterabbit:prod"; break;
            case "audience_dex_client": audience = WhiteRabbitFactory.CliClient; break;
            case "unknown_issuer": issuer = "https://evil.example"; credentials = new SigningCredentials(WhiteRabbitFactory.IssuerKeys[WhiteRabbitFactory.GitHubIssuer], SecurityAlgorithms.RsaSha256); break;
            case "wrong_key": credentials = new SigningCredentials(new RsaSecurityKey(RSA.Create(2048)) { KeyId = "github-key" }, SecurityAlgorithms.RsaSha256); break;
            case "expired": issuedAt = DateTime.UtcNow.AddMinutes(-30); break;
            case "not_yet_valid": issuedAt = DateTime.UtcNow.AddMinutes(10); break;
            case "too_long_lived": lifetime = TimeSpan.FromHours(12); break;
            case "hs256": credentials = new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)) { KeyId = "github-key" }, SecurityAlgorithms.HmacSha256); break;
            case "rs384": credentials = new SigningCredentials(WhiteRabbitFactory.IssuerKeys[WhiteRabbitFactory.GitHubIssuer], SecurityAlgorithms.RsaSha384); break;
            case "missing_repository_id": claims.Remove("repository_id"); break;
            default: throw new ArgumentException(variant);
        }

        await AssertExchangeDenied(IdentityTokens.Create(issuer, audience, claims, issuedAt, lifetime, credentials), reason);
    }

    [Fact]
    public async Task GitHub_EnvironmentBinding_RequiresThatEnvironment()
    {
        var human = await HumanSessionAsync();
        await CreateBindingAsync(human, GitHubBinding(environment: "production"));

        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(GitHubToken(IdentityTokens.GitHubClaims(environment: "production")))).Status);
        await AssertExchangeDenied(GitHubToken(IdentityTokens.GitHubClaims()), "no_matching_binding");
    }

    [Fact]
    public async Task GitHub_TwoMatchingBindings_AreAmbiguousAndDenied()
    {
        var human = await HumanSessionAsync();
        await CreateBindingAsync(human, GitHubBinding());
        await CreateBindingAsync(human, GitHubBinding());
        await AssertExchangeDenied(GitHubToken(), "ambiguous_binding");
    }

}

public class CliFederationForgejoWorkloadTests : CliFederationTests
{

    [Fact]
    public async Task Forgejo_MatchingBinding_GetsWorkloadSession()
    {
        var human = await HumanSessionAsync();
        Assert.Equal(HttpStatusCode.Created, (await CreateBindingAsync(human, ForgejoBinding())).Status);

        var (status, body) = await ExchangeAsync(ForgejoToken());
        Assert.Equal(HttpStatusCode.OK, status);
        var session = body.GetProperty("access_token").GetString()!;
        Assert.Equal("forgejo_workload", body.GetProperty("principal").GetProperty("type").GetString());

        var response = await ProxyAsync(await CredentialAsync(session), "/proxy/api.bunny.net/statistics");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("pull_request", "event_not_allowed")]
    [InlineData("other_repository", "no_matching_binding")]
    [InlineData("github_issuer_for_forgejo_binding", "no_matching_binding")]
    public async Task Forgejo_Negative(string variant, string reason)
    {
        var human = await HumanSessionAsync();
        await CreateBindingAsync(human, ForgejoBinding());
        var token = variant switch
        {
            "pull_request" => ForgejoToken(IdentityTokens.ForgejoClaims(eventName: "pull_request")),
            "other_repository" => ForgejoToken(IdentityTokens.ForgejoClaims(repository: "activout/other")),
            // Same repository and refs, but signed by GitHub: a binding is for one issuer only.
            "github_issuer_for_forgejo_binding" => IdentityTokens.Create(WhiteRabbitFactory.GitHubIssuer, WhiteRabbitFactory.FederationAudience,
                IdentityTokens.ForgejoClaims().Append(new KeyValuePair<string, object>("repository_id", "1")).ToDictionary()),
            _ => throw new ArgumentException(variant),
        };
        await AssertExchangeDenied(token, reason);
    }

    [Fact]
    public async Task Forgejo_BindingCannotRequireGitHubOnlyClaims()
    {
        var human = await HumanSessionAsync();
        var (status, body) = await CreateBindingAsync(human, ForgejoBinding() with { RepositoryId = "42" });
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_binding", body.GetProperty("error").GetString());
    }

}

public class CliFederationBindingAdministrationTests : CliFederationTests
{

    [Theory]
    [InlineData("pull_request")]
    [InlineData("pull_request_target")]
    public async Task Admin_BindingAllowingPullRequests_IsRejected(string eventName)
    {
        var human = await HumanSessionAsync();
        var (status, _) = await CreateBindingAsync(human, GitHubBinding() with { Events = ["push", eventName] });
        Assert.Equal(HttpStatusCode.BadRequest, status);
    }

    [Fact]
    public async Task Admin_UnknownCapabilityOrIssuer_IsRejected()
    {
        var human = await HumanSessionAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await CreateBindingAsync(human, GitHubBinding() with { Capabilities = ["account.delete"] })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await CreateBindingAsync(human, GitHubBinding() with { Issuer = "gitlab" })).Status);
    }

    [Fact]
    public async Task Admin_WorkloadSessionCannotManageBindings()
    {
        var human = await HumanSessionAsync();
        await CreateBindingAsync(human, GitHubBinding());
        var workload = (await ExchangeAsync(GitHubToken())).Body.GetProperty("access_token").GetString()!;

        Assert.Equal(HttpStatusCode.Forbidden, (await CreateBindingAsync(workload, GitHubBinding())).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(HttpMethod.Get, "/api/admin/bindings", workload)).StatusCode);
    }

    [Fact]
    public async Task Admin_VirtualKeyOrDexTokenOrCookieless_CannotUseCliOrAdminApi()
    {
        var human = await HumanSessionAsync();
        var key = await CredentialAsync(human);

        var withKey = new HttpRequestMessage(HttpMethod.Get, "/api/admin/bindings");
        withKey.Headers.Add("AccessKey", key);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.SendAsync(withKey)).StatusCode);

        var withDex = new HttpRequestMessage(HttpMethod.Get, "/api/cli/whoami");
        withDex.Headers.Authorization = new AuthenticationHeaderValue("Bearer", WhiteRabbitFactory.Token());
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.SendAsync(withDex)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/api/cli/whoami")).StatusCode);
    }

    [Fact]
    public async Task Admin_RevokedBinding_StopsNewSessionsAndExistingKeys()
    {
        var human = await HumanSessionAsync();
        var (_, created) = await CreateBindingAsync(human, GitHubBinding());
        var bindingId = created.GetProperty("id").GetInt64();
        var workload = (await ExchangeAsync(GitHubToken())).Body.GetProperty("access_token").GetString()!;
        var key = await CredentialAsync(workload);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(HttpMethod.Delete, $"/api/admin/bindings/{bindingId}", human)).StatusCode);

        Assert.Equal(HttpStatusCode.Forbidden, (await ProxyAsync(key, "/proxy/api.bunny.net/statistics")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(HttpMethod.Post, "/api/cli/credentials", workload)).StatusCode);
        await AssertExchangeDenied(GitHubToken(), "no_matching_binding");
        Assert.Empty(_upstreamRequests);
    }

    [Fact]
    public async Task Admin_CannotRevokeAnotherTenantsBinding()
    {
        var human = await HumanSessionAsync();
        var (_, created) = await CreateBindingAsync(human, GitHubBinding());
        await CreateUserAsync("other@" + WhiteRabbitFactory.AllowedDomain);
        var other = (await ExchangeAsync(DexToken("other@" + WhiteRabbitFactory.AllowedDomain))).Body.GetProperty("access_token").GetString()!;

        var response = await SendAsync(HttpMethod.Delete, $"/api/admin/bindings/{created.GetProperty("id").GetInt64()}", other);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await ExchangeAsync(GitHubToken())).Status);
    }

}

public class CliFederationCredentialsAndProxyTests : CliFederationTests
{

    [Fact]
    public async Task Credentials_CannotBeBroaderThanTheSession()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var response = await SendAsync(HttpMethod.Post, "/api/cli/credentials", human, new { capabilities = new[] { "statistics.read", "dns.write" } });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("dns.write", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Credentials_NarrowedKey_CannotUseOtherCapabilities()
    {
        var human = await HumanSessionAsync(grants: ["statistics.read", "dns.read"]);
        var key = await CredentialAsync(human, "dns.read");

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/statistics");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("capability_not_granted", await response.Content.ReadAsStringAsync());
        Assert.Empty(_upstreamRequests);
    }

    [Fact]
    public async Task Proxy_RevokedGrant_TakesEffectImmediately()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var key = await CredentialAsync(human);
        await GrantAsync(Email, WhiteRabbitFactory.CliClient, "dns.read"); // replaces the earlier grant

        Assert.Equal(HttpStatusCode.Forbidden, (await ProxyAsync(key, "/proxy/api.bunny.net/statistics")).StatusCode);
    }

    [Fact]
    public async Task Proxy_ExpiredVirtualKey_IsRejected()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var key = await CredentialAsync(human);
        await ExecuteAsync("UPDATE VirtualCredentials SET ExpiresUtc = '2000-01-01 00:00:00.000'");

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/statistics");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("access_key_expired", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Proxy_RealBunnyKeyOrGarbage_IsRefusedAndNeverForwarded()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await ProxyAsync(RealBunnyKey, "/proxy/api.bunny.net/statistics")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ProxyAsync("wrk_" + new string('A', 43), "/proxy/api.bunny.net/statistics")).StatusCode);
        Assert.Empty(_upstreamRequests);
    }

    [Fact]
    public async Task Proxy_SessionTokenIsNotAProxyCredential()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var response = await SendAsync(HttpMethod.Get, "/proxy/api.bunny.net/statistics", human);
        // Only Dex tokens are read from Authorization on proxy routes; a session token is not a credential there.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(_upstreamRequests);
    }

    [Fact]
    public async Task Proxy_UnsupportedOperation_IsNotFoundEvenWithAValidKey_AndAudited()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        Assert.Equal(HttpStatusCode.NotFound, (await ProxyAsync(await CredentialAsync(human), "/proxy/api.bunny.net/apikey?secret=x")).StatusCode);

        var denied = (await SecurityEventsAsync()).Single(e => (string?)e["Reason"] == "unsupported_operation");
        Assert.Equal("proxy.request", denied["EventType"]);
        Assert.Equal("/proxy/api.bunny.net/apikey", denied["Path"]); // never the query string
        Assert.Equal(404L, denied["HttpStatus"]);
        Assert.Empty(_upstreamRequests);
    }

    [Theory]
    [InlineData("/api/cli/revoke", "{\"credential_id\":123}", "application/json", HttpStatusCode.BadRequest)]
    [InlineData("/api/cli/revoke", "{not json", "application/json", HttpStatusCode.BadRequest)]
    [InlineData("/api/cli/revoke", "credential_id=abc", "application/x-www-form-urlencoded", HttpStatusCode.UnsupportedMediaType)]
    [InlineData("/api/cli/credentials", "{\"capabilities\":\"statistics.read\"}", "application/json", HttpStatusCode.BadRequest)]
    [InlineData("/api/cli/credentials", "null", "application/json", HttpStatusCode.BadRequest)]
    public async Task MalformedBodies_AreRejectedNotTreatedAsEmpty(string path, string body, string contentType, HttpStatusCode expected)
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = new StringContent(body, System.Text.Encoding.UTF8, contentType) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", human);

        Assert.Equal(expected, (await _client.SendAsync(request)).StatusCode);

        // Nothing was revoked and no credential was issued.
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Get, "/api/cli/whoami", human)).StatusCode);
        Assert.DoesNotContain(await SecurityEventsAsync(), e => (string?)e["EventType"] is "cli.revoke" or "cli.credential");
    }

    [Fact]
    public async Task Admin_OwnerRemovedFromAllowList_CannotListBindings()
    {
        var human = await HumanSessionAsync();
        await CreateBindingAsync(human, GitHubBinding());
        await ExecuteAsync($"UPDATE Users SET Email = 'gone@example.org' WHERE Email = '{Email}'");

        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(HttpMethod.Get, "/api/admin/bindings", human)).StatusCode);
    }

    [Fact]
    public async Task Revoke_EndsSessionAndItsKeys()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var key = await CredentialAsync(human);

        Assert.Equal(HttpStatusCode.NoContent, (await SendAsync(HttpMethod.Post, "/api/cli/revoke", human)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(HttpMethod.Get, "/api/cli/whoami", human)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ProxyAsync(key, "/proxy/api.bunny.net/statistics")).StatusCode);
    }

    [Fact]
    public async Task Revoke_OneCredential_LeavesTheSession()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        var credential = await (await SendAsync(HttpMethod.Post, "/api/cli/credentials", human)).Content.ReadFromJsonAsync<JsonElement>();

        var response = await SendAsync(HttpMethod.Post, "/api/cli/revoke", human, new { credential_id = credential.GetProperty("credential_id").GetString() });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await ProxyAsync(credential.GetProperty("access_key").GetString()!, "/proxy/api.bunny.net/statistics")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(HttpMethod.Get, "/api/cli/whoami", human)).StatusCode);
    }

    [Fact]
    public async Task OwnerRemovedFromAllowList_LosesWorkloadAccess()
    {
        var human = await HumanSessionAsync();
        await CreateBindingAsync(human, GitHubBinding());
        var key = await CredentialAsync((await ExchangeAsync(GitHubToken())).Body.GetProperty("access_token").GetString()!);

        // Rename the owner to an address outside the allow-list, as if the operator had removed them.
        await ExecuteAsync($"UPDATE Users SET Email = 'gone@example.org' WHERE Email = '{Email}'");

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/statistics");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("user_not_allowed", await response.Content.ReadAsStringAsync());
    }

}

public class CliFederationMagicContainersAndDatabaseTests : CliFederationTests
{

    private const string AppWithSecrets = """
        {"id":"app-1","name":"nordray-access-test","containerTemplates":[
          {"id":"c-api","name":"api","image":"codebahn.net/activout/nordray-access:abc",
           "environmentVariables":[{"name":"NORDRAY_VAULT_STORAGE_PASSWORD","value":"vault-secret-1"},{"name":"MODE","value":"prod"}]},
          {"id":"c-dex","name":"dex","environmentVariables":[{"name":"DEX_CLIENT_SECRET","value":"dex-secret-2"}]}]}
        """;

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };

    [Fact]
    public async Task McAppGet_RedactsEnvironmentValuesButKeepsIds()
    {
        _upstream = _ => Json(AppWithSecrets);
        var key = await CredentialAsync(await HumanSessionAsync(grants: "mc.read"));

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/mc/apps/app-1");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("https://api.bunny.net/mc/apps/app-1", Assert.Single(_upstreamRequests).RequestUri!.ToString());
        Assert.False(_upstreamRequests[0].Headers.Contains("Accept-Encoding"), "redacted routes read the upstream body uncompressed");
        Assert.DoesNotContain("vault-secret-1", body);
        Assert.DoesNotContain("dex-secret-2", body);
        Assert.DoesNotContain("\"prod\"", body);
        var app = JsonDocument.Parse(body).RootElement;
        Assert.Equal("c-api", app.GetProperty("containerTemplates")[0].GetProperty("id").GetString());
        Assert.Equal("NORDRAY_VAULT_STORAGE_PASSWORD", app.GetProperty("containerTemplates")[0].GetProperty("environmentVariables")[0].GetProperty("name").GetString());
        Assert.Equal("[redacted by White Rabbit]", app.GetProperty("containerTemplates")[0].GetProperty("environmentVariables")[0].GetProperty("value").GetString());
    }

    [Fact]
    public async Task McRegistryList_RedactsPasswordFragments()
    {
        _upstream = _ => Json("""{"items":[{"id":7,"hostName":"codebahn.net","isPublic":false,"firstPasswordSymbols":"ab","lastPasswordSymbols":"yz"}]}""");
        var key = await CredentialAsync(await HumanSessionAsync(grants: "mc.read"));

        var body = await (await ProxyAsync(key, "/proxy/api.bunny.net/mc/registries")).Content.ReadAsStringAsync();

        var item = JsonDocument.Parse(body).RootElement.GetProperty("items")[0];
        Assert.Equal(7, item.GetProperty("id").GetInt32());
        Assert.Equal("[redacted by White Rabbit]", item.GetProperty("firstPasswordSymbols").GetString());
        Assert.Equal("[redacted by White Rabbit]", item.GetProperty("lastPasswordSymbols").GetString());
    }

    [Fact]
    public async Task McDeploy_RequiresMcDeploy_ForwardsTheBody_AndRedactsTheAnswer()
    {
        _upstream = _ => Json("""{"id":"c-api","image":"new","environmentVariables":[{"name":"X","value":"secret-3"}]}""");
        var readOnly = await CredentialAsync(await HumanSessionAsync(grants: "mc.read"));
        var patch = """{"image":"codebahn.net/activout/nordray-access:def"}""";

        Assert.Equal(HttpStatusCode.Forbidden, (await SendWithKeyAsync(HttpMethod.Patch, "/proxy/api.bunny.net/mc/apps/app-1/containers/c-api", readOnly, patch)).StatusCode);
        Assert.Empty(_upstreamRequests);

        await GrantAsync(Email, WhiteRabbitFactory.CliClient, "mc.read", "mc.deploy");
        var deployer = await CredentialAsync((await ExchangeAsync(DexToken(Email))).Body.GetProperty("access_token").GetString()!);
        var response = await SendWithKeyAsync(HttpMethod.Patch, "/proxy/api.bunny.net/mc/apps/app-1/containers/c-api", deployer, patch);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(patch, Assert.Single(_upstreamBodies));
        Assert.DoesNotContain("secret-3", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task McRedactedRoute_UnparsableSuccess_IsNotPassedThrough()
    {
        _upstream = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("NORDRAY_VAULT_STORAGE_PASSWORD=vault-secret-1") };
        var key = await CredentialAsync(await HumanSessionAsync(grants: "mc.read"));

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/mc/apps/app-1");

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.DoesNotContain("vault-secret-1", await response.Content.ReadAsStringAsync());
        // Bunny succeeded; the audit says so, and why White Rabbit refused the answer.
        var audit = (await SecurityEventsAsync()).Last(e => (string?)e["EventType"] == "proxy.request");
        Assert.Equal(502L, audit["HttpStatus"]);
        Assert.Equal(200L, audit["UpstreamStatus"]);
        Assert.Equal("response_not_redactable", (string?)audit["Reason"]);
    }

    [Theory]
    [InlineData("""{"imageTag":"def","environmentVariables":[{"name":"X","value":"y"}]}""", "environmentVariables")]
    [InlineData("""{"environmentVariables":[]}""", "environmentVariables")]
    [InlineData("""{"EnvironmentVariables":null}""", "EnvironmentVariables")]
    [InlineData("""{"imageTag":"def","endpoints":[]}""", "endpoints")]
    [InlineData("""{"volumeMounts":[{"name":"v","mountPath":"/"}]}""", "volumeMounts")]
    [InlineData("""{"entryPoint":{"command":"sh"}}""", "entryPoint")]
    public async Task McDeploy_CanChangeOnlyTheImage(string patch, string refusedField)
    {
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.deploy", "mc.env"]));

        var response = await SendWithKeyAsync(HttpMethod.Patch, "/proxy/api.bunny.net/mc/apps/app-1/containers/c-api", key, patch);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("body_field_not_allowed", body.GetProperty("error").GetString());
        Assert.Contains(body.GetProperty("fields").EnumerateArray(), f => f.GetString() == refusedField);
        Assert.Empty(_upstreamRequests);
        var audit = (await SecurityEventsAsync()).Last(e => (string?)e["EventType"] == "proxy.request");
        Assert.Equal("body_field_not_allowed", (string?)audit["Reason"]);
        Assert.Null(audit["UpstreamStatus"]);
    }

    [Fact]
    public async Task McDeploy_ImageFieldsAreForwarded_InAnyCase()
    {
        _upstream = _ => Json("""{"id":"c-api"}""");
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.deploy"]));
        var patch = """{"ImageTag":"def","imageRegistryId":"reg-1","imageNamespace":"activout","imageName":"x","imagePullPolicy":"Always"}""";

        var response = await SendWithKeyAsync(HttpMethod.Patch, "/proxy/api.bunny.net/mc/apps/app-1/containers/c-api", key, patch);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(JsonNode.Parse(patch)!.ToJsonString(), JsonNode.Parse(Assert.Single(_upstreamBodies))!.ToJsonString());
    }

    private const string EnvPath = "/proxy/api.bunny.net/mc/apps/app-1/containers/c-api/env";

    /// <summary>Upstream with one container holding two secrets; PUT env echoes the stored variables back.</summary>
    private void ContainerWithSecretsUpstream() => _upstream = request =>
        request.Method == HttpMethod.Get
            ? Json("""{"id":"c-api","environmentVariables":[{"name":"DB_TOKEN","value":"db-secret-1"},{"name":"MODE","value":"test"}]}""")
            : Json("""{"id":"c-api","environmentVariables":[{"name":"DB_TOKEN","value":"db-secret-1"},{"name":"MODE","value":"prod"},{"name":"NEW","value":"new-secret-2"}]}""");

    [Fact]
    public async Task EnvSet_PlaceholdersKeepTheirCurrentValues_AndTheAnswerIsRedacted()
    {
        ContainerWithSecretsUpstream();
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.read", "mc.env"]));

        // What `bunny apps env set NEW …` sends after reading the (redacted) container through White Rabbit.
        var response = await SendWithKeyAsync(HttpMethod.Put, EnvPath, key,
            """{"DB_TOKEN":"[redacted by White Rabbit]","MODE":"prod","NEW":"new-secret-2"}""");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, _upstreamRequests.Count);
        Assert.Equal(HttpMethod.Get, _upstreamRequests[0].Method);
        Assert.Equal("https://api.bunny.net/mc/apps/app-1/containers/c-api", _upstreamRequests[0].RequestUri!.ToString());
        Assert.Equal(HttpMethod.Put, _upstreamRequests[1].Method);
        Assert.Equal("https://api.bunny.net/mc/apps/app-1/containers/c-api/env", _upstreamRequests[1].RequestUri!.ToString());
        var sent = JsonDocument.Parse(_upstreamBodies[1]).RootElement;
        Assert.Equal("db-secret-1", sent.GetProperty("DB_TOKEN").GetString());
        Assert.Equal("prod", sent.GetProperty("MODE").GetString());
        Assert.Equal("new-secret-2", sent.GetProperty("NEW").GetString());
        Assert.DoesNotContain("db-secret-1", body);
        Assert.DoesNotContain("new-secret-2", body);
    }

    [Fact]
    public async Task EnvSet_WithoutPlaceholders_IsForwardedUnchanged_WithoutReadingFirst()
    {
        ContainerWithSecretsUpstream();
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.env"]));
        var env = """{"MODE":"prod"}""";

        Assert.Equal(HttpStatusCode.OK, (await SendWithKeyAsync(HttpMethod.Put, EnvPath, key, env)).StatusCode);

        Assert.Equal(HttpMethod.Put, Assert.Single(_upstreamRequests).Method);
        Assert.Equal(env, JsonNode.Parse(_upstreamBodies[0])!.ToJsonString());
    }

    [Fact]
    public async Task EnvSet_PlaceholderForAnUnknownVariable_IsRefused()
    {
        ContainerWithSecretsUpstream();
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.env"]));

        var response = await SendWithKeyAsync(HttpMethod.Put, EnvPath, key, """{"OTHER":"[redacted by White Rabbit]"}""");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("redacted_value_unknown", await response.Content.ReadAsStringAsync());
        Assert.Equal(HttpMethod.Get, Assert.Single(_upstreamRequests).Method);
        var audit = (await SecurityEventsAsync()).Last(e => (string?)e["EventType"] == "proxy.request");
        Assert.Equal("redacted_value_unknown", (string?)audit["Reason"]);
        Assert.Null(audit["UpstreamStatus"]);
    }

    [Fact]
    public async Task EnvSet_WhenTheCurrentValuesCannotBeRead_NothingIsWritten()
    {
        _upstream = _ => Json("""{"error":"nope"}""", HttpStatusCode.NotFound);
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.env"]));

        var response = await SendWithKeyAsync(HttpMethod.Put, EnvPath, key, """{"DB_TOKEN":"[redacted by White Rabbit]"}""");

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.DoesNotContain(_upstreamRequests, r => r.Method == HttpMethod.Put);
    }

    [Theory]
    [InlineData("""["A","B"]""")]
    [InlineData("""{"A":1}""")]
    [InlineData("""{"A":{"value":"x"}}""")]
    [InlineData("not json")]
    public async Task EnvSet_BodyMustBeAnObjectOfStrings(string body)
    {
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.env"]));

        var response = await SendWithKeyAsync(HttpMethod.Put, EnvPath, key, body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_upstreamRequests);
    }

    [Fact]
    public async Task AppCreate_AnswerIsRedacted()
    {
        _upstream = _ => Json("""{"id":"app-9","containerTemplates":[{"id":"c","environmentVariables":[{"name":"K","value":"create-secret-4"}]}]}""", HttpStatusCode.Created);
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.manage"]));

        var response = await SendWithKeyAsync(HttpMethod.Post, "/proxy/api.bunny.net/mc/apps", key, """{"name":"preview-42"}""");

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("create-secret-4", body);
        Assert.Contains("app-9", body);
    }

    [Theory]
    [InlineData("GET", "/proxy/api.bunny.net/database/v2/databases", "db.read")]
    [InlineData("GET", "/proxy/api.bunny.net/database/v1/config", "db.read")]
    [InlineData("POST", "/proxy/api.bunny.net/database/v2/databases", "db.manage")]
    [InlineData("PUT", "/proxy/api.bunny.net/database/v2/databases/db-1/auth/generate", "db.token")]
    [InlineData("GET", "/proxy/api.bunny.net/mc/apps", "mc.read")]
    [InlineData("POST", "/proxy/api.bunny.net/mc/apps/app-1/restart", "mc.deploy")]
    [InlineData("PUT", "/proxy/api.bunny.net/mc/apps/app-1/containers/c-api/env", "mc.env")]
    [InlineData("POST", "/proxy/api.bunny.net/mc/apps", "mc.manage")]
    [InlineData("DELETE", "/proxy/api.bunny.net/mc/apps/app-1", "mc.manage")]
    [InlineData("DELETE", "/proxy/api.bunny.net/database/v2/databases/db-1", "db.manage")]
    public async Task NewOperations_NeedTheirOwnCapability(string method, string path, string capability)
    {
        var others = new[] { "db.read", "db.manage", "db.token", "mc.read", "mc.deploy", "mc.env", "mc.manage" }.Where(c => c != capability).ToArray();
        var without = await CredentialAsync(await HumanSessionAsync(grants: others));
        Assert.Equal(HttpStatusCode.Forbidden, (await SendWithKeyAsync(new HttpMethod(method), path, without, method is "GET" or "DELETE" ? null : "{}")).StatusCode);

        await GrantAsync(Email, WhiteRabbitFactory.CliClient, capability);
        var with = await CredentialAsync((await ExchangeAsync(DexToken(Email))).Body.GetProperty("access_token").GetString()!);
        Assert.Equal(HttpStatusCode.OK, (await SendWithKeyAsync(new HttpMethod(method), path, with, method is "GET" or "DELETE" ? null : "{}")).StatusCode);
    }

    [Theory]
    [InlineData("GET", "/proxy/api.bunny.net/mc/log/forwarding")]
    [InlineData("GET", "/proxy/api.bunny.net/mc/registries/7")]
    [InlineData("DELETE", "/proxy/api.bunny.net/mc/registries/7")]
    [InlineData("DELETE", "/proxy/api.bunny.net/mc/apps/app-1/volumes/v-1")]
    [InlineData("POST", "/proxy/api.bunny.net/database/v1/groups/g-1/auth/generate")]
    public async Task DeliberatelyUnsupportedOperations_AreNotFound(string method, string path)
    {
        var key = await CredentialAsync(await HumanSessionAsync(grants: ["mc.read", "mc.deploy", "mc.env", "mc.manage", "db.read", "db.manage", "db.token"]));
        Assert.Equal(HttpStatusCode.NotFound, (await SendWithKeyAsync(new HttpMethod(method), path, key, method is "GET" or "DELETE" ? null : "{}")).StatusCode);
        Assert.Empty(_upstreamRequests);
    }

    private Task<HttpResponseMessage> SendWithKeyAsync(HttpMethod method, string path, string accessKey, string? jsonBody)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("AccessKey", accessKey);
        if (jsonBody is not null) request.Content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "application/json");
        return _client.SendAsync(request);
    }

}

public class CliFederationDexPkceTests : CliFederationTests
{

    [Theory]
    [InlineData("client_id=rabbit-cli&response_type=code&redirect_uri=http://127.0.0.1:5000/callback", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=code&code_challenge=abc&code_challenge_method=plain", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=token&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", HttpStatusCode.Redirect)]
    [InlineData("client_id=example-client&response_type=code", HttpStatusCode.Redirect)]
    // Repeated parameters: White Rabbit and Dex could read different values, so they are refused outright.
    [InlineData("client_id=rabbit-cli&client_id=example-client&response_type=code", HttpStatusCode.BadRequest)]
    [InlineData("client_id=example-client&client_id=rabbit-cli&response_type=code", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&code_challenge_method=plain", HttpStatusCode.BadRequest)]
    public async Task DexAuth_RabbitCliRequiresPkceS256(string query, HttpStatusCode expected)
    {
        var response = await _client.GetAsync("/auth?" + query);
        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.Redirect)
            Assert.StartsWith("/login", response.Headers.Location!.OriginalString); // reaches the normal login
    }

}
