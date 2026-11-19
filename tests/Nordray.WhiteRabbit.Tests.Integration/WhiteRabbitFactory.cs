using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Nordray.WhiteRabbit.Core.Services;

namespace Nordray.WhiteRabbit.Tests.Integration;

/// <summary>
/// The real application with a temporary libSQL database, a fixed signing key standing in for Dex,
/// and an email sender that records codes instead of sending them.
/// </summary>
public sealed class WhiteRabbitFactory(string connectionString, string encryptionKey) : WebApplicationFactory<Program>
{
    public const string Issuer = "https://whiterabbit.test.invalid";
    public const string AllowedEmail = "allowed@example.com";
    public const string AllowedDomain = "team.example.com";
    public const string ProxyClient = "example-client";

    public static readonly SymmetricSecurityKey SigningKey = new(Convert.FromBase64String("q83vEjRWeJBYd0Q8t3z5uM8yQ2pJ0lV1n9cX6kHrT2E="));

    public RecordingEmailService Emails { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Database:ConnectionString", connectionString);
        builder.UseSetting("DataProtection:EncryptionKey", encryptionKey);
        builder.UseSetting("Access:AllowedEmails:0", AllowedEmail);
        builder.UseSetting("Access:AllowedDomains:0", AllowedDomain);
        builder.UseSetting("Proxy:AllowedClientIds:0", ProxyClient);
        builder.UseSetting("Dex:IssuerUrl", Issuer);
        builder.UseSetting("Dex:InternalAddress", "http://127.0.0.1:9");

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IEmailService>();
            services.AddSingleton<IEmailService>(Emails);
            services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
                configuration.SigningKeys.Add(SigningKey);
                options.Configuration = configuration;
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
                options.TokenValidationParameters.ValidIssuer = Issuer;
                options.TokenValidationParameters.IssuerSigningKey = SigningKey;
            });
        });
    }

    public HttpClient CreateHttpsClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false });

    public static string Token(
        string email = AllowedEmail,
        string[]? audiences = null,
        string? azp = null,
        string issuer = Issuer,
        DateTime? expires = null,
        SecurityKey? key = null)
    {
        var claims = new Dictionary<string, object> { ["email"] = email, ["sub"] = "subject-1" };
        var aud = audiences ?? [ProxyClient];
        claims["aud"] = aud.Length == 1 ? aud[0] : aud;
        if (azp is not null) claims["azp"] = azp;
        var notBefore = (expires ?? DateTime.UtcNow.AddMinutes(10)).AddMinutes(-20);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Claims = claims,
            NotBefore = notBefore,
            IssuedAt = notBefore,
            Expires = expires ?? DateTime.UtcNow.AddMinutes(10),
            SigningCredentials = new SigningCredentials(key ?? SigningKey, SecurityAlgorithms.HmacSha256),
        });
    }
}

public sealed class RecordingEmailService : IEmailService
{
    private readonly List<string> _recipients = [];

    public IReadOnlyList<string> Recipients
    {
        get { lock (_recipients) return _recipients.ToList(); }
    }

    public Task SendLoginCodeAsync(string toEmail, string code, CancellationToken ct = default)
    {
        lock (_recipients) _recipients.Add(toEmail);
        return Task.CompletedTask;
    }
}
