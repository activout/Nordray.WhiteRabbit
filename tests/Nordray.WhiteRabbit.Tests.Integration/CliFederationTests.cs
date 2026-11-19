using System.Data.Common;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
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
public class CliFederationTests : IAsyncLifetime
{
    private const string Email = WhiteRabbitFactory.AllowedEmail;
    private const string RealBunnyKey = "real-bunny-account-key-0123456789";

    private TestDatabase _db = null!;
    private WhiteRabbitFactory _factory = null!;
    private HttpClient _client = null!;
    private readonly List<HttpRequestMessage> _upstreamRequests = [];

    public async Task InitializeAsync()
    {
        _db = await TestDatabase.CreateAsync(migrate: false);
        _factory = new WhiteRabbitFactory(_db.ConnectionString, KeyRingEncryptionTests.NewKey());
        _factory.Upstream.When("https://api.bunny.net/*").Respond(request =>
        {
            lock (_upstreamRequests) _upstreamRequests.Add(request);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"ok":true}""") };
        });
        _client = _factory.CreateHttpsClient();
        await _client.GetAsync("/health"); // starts the app and applies migrations
    }

    public async Task DisposeAsync()
    {
        await _factory.DisposeAsync();
        await _db.DisposeAsync();
    }

    // ================================================================ discovery

    [Fact]
    public async Task Config_TellsTheCliItsClientAudienceAndCapabilities()
    {
        var config = await _client.GetFromJsonAsync<JsonElement>("/api/cli/config");
        Assert.Equal(WhiteRabbitFactory.CliClient, config.GetProperty("dex_client_id").GetString());
        Assert.Equal(WhiteRabbitFactory.FederationAudience, config.GetProperty("federation_audience").GetString());
        Assert.Contains(config.GetProperty("capabilities").EnumerateArray(), c => c.GetProperty("name").GetString() == "statistics.read");
    }

    // ================================================================ human (Dex) exchange

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

    // ================================================================ GitHub workload

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

        var response = await ProxyAsync(key, "/proxy/api.bunny.net/statistics", correlationId: "corr-123");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("corr-123", response.Headers.GetValues("X-Correlation-ID").Single());

        // Upstream got the owner's real key, and none of the caller's credentials.
        var upstream = Assert.Single(_upstreamRequests);
        Assert.Equal("https://api.bunny.net/statistics", upstream.RequestUri!.ToString());
        Assert.Equal(RealBunnyKey, upstream.Headers.GetValues("AccessKey").Single());
        Assert.False(upstream.Headers.Contains("Authorization"));

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

    // ================================================================ Forgejo workload

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

    // ================================================================ binding administration

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

    // ================================================================ credentials and proxy

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
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(_upstreamRequests);
    }

    [Fact]
    public async Task Proxy_UnsupportedOperation_IsNotFoundEvenWithAValidKey()
    {
        var human = await HumanSessionAsync(grants: "statistics.read");
        Assert.Equal(HttpStatusCode.NotFound, (await ProxyAsync(await CredentialAsync(human), "/proxy/api.bunny.net/apikey")).StatusCode);
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

    // ================================================================ Dex PKCE

    [Theory]
    [InlineData("client_id=rabbit-cli&response_type=code&redirect_uri=http://127.0.0.1:5000/callback", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=code&code_challenge=abc&code_challenge_method=plain", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=token&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", HttpStatusCode.BadRequest)]
    [InlineData("client_id=rabbit-cli&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", HttpStatusCode.Redirect)]
    [InlineData("client_id=example-client&response_type=code", HttpStatusCode.Redirect)]
    public async Task DexAuth_RabbitCliRequiresPkceS256(string query, HttpStatusCode expected)
    {
        var response = await _client.GetAsync("/auth?" + query);
        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.Redirect)
            Assert.StartsWith("/login", response.Headers.Location!.OriginalString); // reaches the normal login
    }

    // ================================================================ helpers

    private sealed record BindingBody(
        string Issuer, string Repository, string? RepositoryId, string Ref, string WorkflowRef,
        string? Environment = null, string[]? Events = null, string[]? Capabilities = null);

    private static BindingBody GitHubBinding(string? environment = null) => new(
        "github", "activout/rabbit-ci-test", "123456", "refs/heads/main",
        "activout/rabbit-ci-test/.github/workflows/rabbit.yml@refs/heads/main",
        environment, Capabilities: ["statistics.read"]);

    private static BindingBody ForgejoBinding() => new(
        "codebahn", "activout/rabbit-ci-test", null, "refs/heads/main",
        "activout/rabbit-ci-test/.forgejo/workflows/rabbit.yml@refs/heads/main",
        Capabilities: ["statistics.read"]);

    private static string GitHubToken(Dictionary<string, object>? claims = null) =>
        IdentityTokens.Create(WhiteRabbitFactory.GitHubIssuer, WhiteRabbitFactory.FederationAudience, claims ?? IdentityTokens.GitHubClaims());

    private static string ForgejoToken(Dictionary<string, object>? claims = null) =>
        IdentityTokens.Create(WhiteRabbitFactory.ForgejoIssuer, WhiteRabbitFactory.FederationAudience, claims ?? IdentityTokens.ForgejoClaims());

    private static string DexToken(string email, string audience = WhiteRabbitFactory.CliClient, DateTime? issuedAt = null, TimeSpan? lifetime = null) =>
        IdentityTokens.Create(WhiteRabbitFactory.Issuer, audience, new Dictionary<string, object> { ["sub"] = "dex-" + email, ["email"] = email }, issuedAt, lifetime);

    /// <summary>A signed-in human with a stored Bunny key and a session for the rabbit CLI.</summary>
    private async Task<string> HumanSessionAsync(params string[] grants)
    {
        await CreateUserAsync(Email);
        if (grants.Length > 0) await GrantAsync(Email, WhiteRabbitFactory.CliClient, grants);
        var (status, body) = await ExchangeAsync(DexToken(Email));
        Assert.Equal(HttpStatusCode.OK, status);
        return body.GetProperty("access_token").GetString()!;
    }

    private async Task CreateUserAsync(string email)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserRepository>();
        if (await users.FindByEmailAsync(email) is not null) return;
        await users.InsertAsync(new User { Subject = "subject-" + email, Email = email, CreatedUtc = DateTime.UtcNow, LastLoginUtc = DateTime.UtcNow });
        var user = (await users.FindByEmailAsync(email))!;
        var protector = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("BunnyApiKey.v1");
        await users.UpdateBunnyApiKeyAsync(user.Id, protector.Protect(RealBunnyKey));
    }

    private async Task GrantAsync(string email, string client, params string[] capabilities)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IGrantService>().StoreGrantAsync(email, client, capabilities);
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(string token)
    {
        var response = await _client.PostAsJsonAsync("/api/cli/exchange", new { subject_token = token });
        return (response.StatusCode, await response.Content.ReadFromJsonAsync<JsonElement>());
    }

    private async Task AssertExchangeDenied(string token, string reason)
    {
        var (status, body) = await ExchangeAsync(token);
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal(reason, body.GetProperty("reason").GetString());
        var events = await SecurityEventsAsync();
        Assert.Contains(events, e => (string?)e["EventType"] == "cli.exchange" && (string?)e["Outcome"] == "denied" && (string?)e["Reason"] == reason);
        Assert.Empty(_upstreamRequests);
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> CreateBindingAsync(string session, BindingBody body)
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

    private async Task<string> CredentialAsync(string session, params string[] capabilities)
    {
        var response = await SendAsync(HttpMethod.Post, "/api/cli/credentials", session, capabilities.Length > 0 ? new { capabilities } : null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_key").GetString()!;
    }

    private async Task<JsonElement> GetJsonAsync(string path, string session)
    {
        var response = await SendAsync(HttpMethod.Get, path, session);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string session, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session);
        if (body is not null) request.Content = JsonContent.Create(body);
        return _client.SendAsync(request);
    }

    private Task<HttpResponseMessage> ProxyAsync(string accessKey, string path, string? correlationId = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("AccessKey", accessKey);
        if (correlationId is not null) request.Headers.Add("X-Correlation-ID", correlationId);
        return _client.SendAsync(request);
    }

    private async Task<List<Dictionary<string, object?>>> SecurityEventsAsync()
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

    private async Task AssertNoSecretsInAuditAsync(params string[] secrets)
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

    private async Task ExecuteAsync(string sql)
    {
        await using var connection = _db.Factory.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
