using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Web.Cli;
using RichardSzalay.MockHttp;
using Yarp.ReverseProxy.Forwarder;

namespace Nordray.WhiteRabbit.Tests.Integration;

/// <summary>
/// The real application with a temporary libSQL database, fake CI issuer metadata, and an email sender that records
/// codes instead of sending them.
/// </summary>
public sealed class WhiteRabbitFactory(string connectionString, string encryptionKey) : WebApplicationFactory<Program>
{
    public const string AllowedEmail = "allowed@example.com";
    public const string AllowedDomain = "team.example.com";
    public const string FederationAudience = "whiterabbit:test";
    public const string GitHubIssuer = "https://token.actions.githubusercontent.com";
    public const string ForgejoIssuer = "https://codebahn.net/api/actions";

    public RecordingEmailService Emails { get; } = new();

    /// <summary>Stands in for api.bunny.net: every forwarded request ends here, never on the network.</summary>
    public MockHttpMessageHandler Upstream { get; } = new();

    /// <summary>RS256 keys of the GitHub and Forgejo issuers, published through fake discovery metadata.</summary>
    public static readonly IReadOnlyDictionary<string, RsaSecurityKey> IssuerKeys = new Dictionary<string, RsaSecurityKey>
    {
        [GitHubIssuer] = NewRsaKey("github-key"),
        [ForgejoIssuer] = NewRsaKey("forgejo-key"),
    };

    private static RsaSecurityKey NewRsaKey(string kid) =>
        new(System.Security.Cryptography.RSA.Create(2048)) { KeyId = kid };

    /// <summary>Extra settings applied after the defaults, e.g. shorter lifetimes.</summary>
    public Dictionary<string, string> Settings { get; } = [];

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        // Each host would otherwise watch the appsettings files; on macOS that costs ~100 ms per test.
        builder.UseSetting("hostBuilder:reloadConfigOnChange", "false");
        builder.UseSetting("Database:ConnectionString", connectionString);
        builder.UseSetting("DataProtection:EncryptionKey", encryptionKey);
        builder.UseSetting("Access:AllowedEmails:0", AllowedEmail);
        builder.UseSetting("Access:AllowedDomains:0", AllowedDomain);
        builder.UseSetting("Federation:Audience", FederationAudience);
        builder.UseSetting("Federation:Issuers:0:Name", "github");
        builder.UseSetting("Federation:Issuers:0:Kind", "GitHub");
        builder.UseSetting("Federation:Issuers:0:Url", GitHubIssuer);
        builder.UseSetting("Federation:Issuers:1:Name", "codebahn");
        builder.UseSetting("Federation:Issuers:1:Kind", "Forgejo");
        builder.UseSetting("Federation:Issuers:1:Url", ForgejoIssuer);
        foreach (var (key, value) in Settings)
            builder.UseSetting(key, value);

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEmailService>();
            services.AddSingleton<IEmailService>(Emails);
            services.RemoveAll<IOidcMetadataProvider>();
            services.AddSingleton<IOidcMetadataProvider>(new StaticMetadataProvider());
            services.RemoveAll<IForwarderHttpClientFactory>();
            services.AddSingleton<IForwarderHttpClientFactory>(new MockForwarderClientFactory(Upstream));
        });
    }

    public HttpClient CreateHttpsClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });

}

/// <summary>Signs CI identity tokens the way the real issuers do (RS256, kid in the header).</summary>
public static class IdentityTokens
{
    public static string Create(
        string issuer,
        string audience,
        IDictionary<string, object> claims,
        DateTime? issuedAt = null,
        TimeSpan? lifetime = null,
        SigningCredentials? credentials = null)
    {
        var iat = issuedAt ?? DateTime.UtcNow.AddSeconds(-5);
        var payload = new Dictionary<string, object>(claims) { ["aud"] = audience };
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Claims = payload,
            IssuedAt = iat,
            NotBefore = iat,
            Expires = iat + (lifetime ?? TimeSpan.FromMinutes(10)),
            SigningCredentials = credentials ?? new SigningCredentials(WhiteRabbitFactory.IssuerKeys[issuer], SecurityAlgorithms.RsaSha256),
        });
    }

    public static Dictionary<string, object> GitHubClaims(
        string repository = "activout/rabbit-ci-test",
        string repositoryId = "123456",
        string @ref = "refs/heads/main",
        string eventName = "push",
        string? environment = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = $"repo:{repository}:ref:{@ref}",
            ["repository"] = repository,
            ["repository_id"] = repositoryId,
            ["repository_owner"] = repository.Split('/')[0],
            ["repository_owner_id"] = "999",
            ["ref"] = @ref,
            ["workflow_ref"] = $"{repository}/.github/workflows/rabbit.yml@{@ref}",
            ["job_workflow_ref"] = $"{repository}/.github/workflows/rabbit.yml@{@ref}",
            ["event_name"] = eventName,
            ["run_id"] = "4242",
            ["run_attempt"] = "1",
            ["sha"] = "0123456789abcdef0123456789abcdef01234567",
            ["actor"] = "someone",
        };
        if (environment is not null) claims["environment"] = environment;
        return claims;
    }

    public static Dictionary<string, object> ForgejoClaims(
        string repository = "activout/rabbit-ci-test",
        string @ref = "refs/heads/main",
        string eventName = "push") => new()
    {
        ["sub"] = $"repo:{repository}:ref:{@ref}",
        ["repository"] = repository,
        ["repository_owner"] = repository.Split('/')[0],
        ["ref"] = @ref,
        ["ref_protected"] = "false",
        ["ref_type"] = "branch",
        ["workflow"] = "rabbit.yml",
        ["workflow_ref"] = $"{repository}/.forgejo/workflows/rabbit.yml@{@ref}",
        ["event_name"] = eventName,
        ["run_id"] = "11791",
        ["run_attempt"] = "1",
        ["run_number"] = "1",
        ["sha"] = "0123456789abcdef0123456789abcdef01234567",
        ["actor"] = "someone",
    };
}

public sealed class StaticMetadataProvider : IOidcMetadataProvider
{
    public Task<OpenIdConnectConfiguration> GetAsync(string issuerUrl, CancellationToken ct)
    {
        if (!WhiteRabbitFactory.IssuerKeys.TryGetValue(issuerUrl, out var key))
            throw new InvalidOperationException("Unexpected metadata request for " + issuerUrl);
        var configuration = new OpenIdConnectConfiguration { Issuer = issuerUrl };
        configuration.SigningKeys.Add(key);
        return Task.FromResult(configuration);
    }

    public void RequestRefresh(string issuerUrl) { }
}

public sealed class MockForwarderClientFactory(MockHttpMessageHandler handler) : IForwarderHttpClientFactory
{
    private readonly HttpMessageInvoker _client = new(handler, disposeHandler: false);

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => _client;
}

public sealed class RecordingEmailService : IEmailService
{
    private readonly List<(string To, string Code)> _sent = [];

    public IReadOnlyList<string> Recipients
    {
        get { lock (_sent) return _sent.Select(s => s.To).ToList(); }
    }

    public string LastCode(string toEmail)
    {
        lock (_sent) return _sent.Last(s => s.To == toEmail).Code;
    }

    public Task SendLoginCodeAsync(string toEmail, string code, CancellationToken ct = default)
    {
        lock (_sent) _sent.Add((toEmail, code));
        return Task.CompletedTask;
    }
}
