using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Nordray.WhiteRabbit.Core.Federation;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>Issuer metadata (signing keys) by issuer URL. Replaced in tests.</summary>
public interface IOidcMetadataProvider
{
    Task<OpenIdConnectConfiguration> GetAsync(string issuerUrl, CancellationToken ct);
    void RequestRefresh(string issuerUrl);
}

/// <summary>
/// Discovery and JWKS from <c>{issuer}/.well-known/openid-configuration</c>, cached and refreshed by
/// <see cref="ConfigurationManager{T}"/>. Only issuers White Rabbit is configured to trust are ever fetched.
/// </summary>
public sealed class OidcMetadataProvider(IHttpClientFactory httpClients, IHostEnvironment environment) : IOidcMetadataProvider
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _managers = new(StringComparer.Ordinal);

    public Task<OpenIdConnectConfiguration> GetAsync(string issuerUrl, CancellationToken ct) => Manager(issuerUrl).GetConfigurationAsync(ct);

    public void RequestRefresh(string issuerUrl) => Manager(issuerUrl).RequestRefresh();

    private ConfigurationManager<OpenIdConnectConfiguration> Manager(string issuerUrl) =>
        _managers.GetOrAdd(issuerUrl, url => new ConfigurationManager<OpenIdConnectConfiguration>(
            url.TrimEnd('/') + "/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            // Development may use a local http:// issuer; everything else must be HTTPS.
            new HttpDocumentRetriever(httpClients.CreateClient("oidc-metadata")) { RequireHttps = !environment.IsDevelopment() }));
}

/// <summary>A validated token: who issued it and its claims.</summary>
public sealed record ValidatedToken(string IssuerUrl, TrustedIssuer Workload, JsonWebToken Token);

/// <summary>
/// Validates CI identity tokens presented to <c>/api/cli/exchange</c>: they must come from a trusted issuer and be
/// for this environment's federation audience. Signature (RS256 only), issuer, audience, expiry and not-before are
/// always verified, and the tokens must be short-lived.
/// </summary>
public sealed class IdentityTokenValidator(
    IOidcMetadataProvider metadata,
    IOptions<FederationOptions> federation)
{
    private static readonly string[] AllowedAlgorithms = [SecurityAlgorithms.RsaSha256];
    private readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };

    public sealed record Result(ValidatedToken? Token, string? DenialReason, string? UnverifiedIssuer);

    public async Task<Result> ValidateAsync(string token, CancellationToken ct)
    {
        if (!_handler.CanReadToken(token))
            return new Result(null, "malformed_token", null);
        string issuer, algorithm;
        try
        {
            var unverified = new JsonWebToken(token);
            issuer = unverified.Issuer;
            algorithm = unverified.Alg;
        }
        catch (ArgumentException) { return new Result(null, "malformed_token", null); }

        // Checked explicitly first (ValidAlgorithms below is the second guard): every trusted issuer signs with RS256,
        // so anything else, including "none" and HMAC, is refused before any key is looked up.
        if (!AllowedAlgorithms.Contains(algorithm, StringComparer.Ordinal))
            return new Result(null, "algorithm_not_allowed", issuer);

        var workload = federation.Value.Issuers.FirstOrDefault(i => string.Equals(i.Url, issuer, StringComparison.Ordinal));
        if (workload is null || string.IsNullOrEmpty(federation.Value.Audience))
            return new Result(null, "untrusted_issuer", issuer);

        var validation = await ValidateWithIssuerAsync(token, issuer, federation.Value.Audience, ct);
        if (!validation.IsValid)
            return new Result(null, Reason(validation.Exception), issuer);

        var jwt = (JsonWebToken)validation.SecurityToken;
        // CI tokens are meant to live minutes; refuse long-lived ones even if correctly signed.
        if (jwt.IssuedAt == DateTime.MinValue || jwt.ValidTo - jwt.IssuedAt > federation.Value.MaxTokenLifetime)
            return new Result(null, "token_lifetime_too_long", issuer);
        return new Result(new ValidatedToken(issuer, workload, jwt), null, issuer);
    }

    private async Task<TokenValidationResult> ValidateWithIssuerAsync(string token, string issuer, string audience, CancellationToken ct)
    {
        TokenValidationResult result = null!;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            OpenIdConnectConfiguration config;
            try { config = await metadata.GetAsync(issuer, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new TokenValidationResult { IsValid = false, Exception = new SecurityTokenException("issuer_metadata_unavailable", ex) };
            }

            result = await _handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKeys = config.SigningKeys,
                ValidAlgorithms = AllowedAlgorithms,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromMinutes(1),
            });
            // Keys rotate: on an unknown key, refresh the metadata once and retry.
            if (result.IsValid || result.Exception is not SecurityTokenSignatureKeyNotFoundException || attempt == 1)
                break;
            metadata.RequestRefresh(issuer);
        }
        return result;
    }

    private static string Reason(Exception? ex) => ex switch
    {
        SecurityTokenException { Message: "issuer_metadata_unavailable" } => "issuer_metadata_unavailable",
        SecurityTokenExpiredException => "token_expired",
        SecurityTokenNotYetValidException => "token_not_yet_valid",
        SecurityTokenInvalidAudienceException => "wrong_audience",
        SecurityTokenInvalidIssuerException => "untrusted_issuer",
        SecurityTokenInvalidAlgorithmException => "algorithm_not_allowed",
        SecurityTokenSignatureKeyNotFoundException => "invalid_signature",
        SecurityTokenInvalidSignatureException => "invalid_signature",
        SecurityTokenNoExpirationException => "token_without_expiry",
        _ => "invalid_token",
    };

    /// <summary>Reads the verified CI claims. GitHub and Forgejo use the same claim names where both have them.</summary>
    public static WorkloadIdentity ToWorkloadIdentity(ValidatedToken validated)
    {
        var t = validated.Token;
        string? Claim(string name) => t.TryGetPayloadValue<string>(name, out var v) && !string.IsNullOrEmpty(v) ? v : null;
        var issuer = validated.Workload;
        var github = issuer.Kind == IssuerKind.GitHub;
        return new WorkloadIdentity
        {
            IssuerName = issuer.Name,
            IssuerKind = issuer.Kind,
            IssuerUrl = validated.IssuerUrl,
            Subject = t.Subject ?? "",
            Repository = Claim("repository"),
            RepositoryOwner = Claim("repository_owner"),
            // Forgejo has none of these; never read them from a Forgejo token even if present.
            RepositoryId = github ? Claim("repository_id") : null,
            RepositoryOwnerId = github ? Claim("repository_owner_id") : null,
            JobWorkflowRef = github ? Claim("job_workflow_ref") : null,
            Environment = github ? Claim("environment") : null,
            Ref = Claim("ref"),
            WorkflowRef = Claim("workflow_ref"),
            EventName = Claim("event_name"),
            RunId = Claim("run_id"),
            RunAttempt = Claim("run_attempt"),
            Sha = Claim("sha"),
            Actor = Claim("actor"),
        };
    }
}
