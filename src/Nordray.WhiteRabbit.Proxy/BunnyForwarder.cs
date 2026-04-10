using System.Net.Security;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Yarp.ReverseProxy.Forwarder;

namespace Nordray.WhiteRabbit.Proxy;

/// <summary>
/// Direct HTTP forwarder for validated bunny.net API requests.
/// Mounted at /proxy/api.bunny.net/{**path}.
///
/// Per-request flow:
///   1. Look up operation in registry → 404 if not found
///   2. Require authentication → 401 if missing
///   3. Check capability grant for JWT clients → 403 if not granted
///   4. Strip inbound credential headers
///   5. Inject the user's own bunny.net API key
///   6. Forward via IHttpForwarder, rewriting the path
/// </summary>
public static class BunnyForwarder
{
    // Trust only ISRG Root X1 for outbound connections to api.bunny.net.
    // This rejects any intercepting proxy that presents its own CA certificate.
    private static readonly X509Certificate2 IsrgRootX1 = LoadIsrgRootX1();

    private static readonly HttpMessageInvoker HttpClient = new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = ValidateAgainstIsrgRootX1,
        },
    });

    private static X509Certificate2 LoadIsrgRootX1()
    {
        var asm = Assembly.GetExecutingAssembly();
        var resourceName = asm.GetManifestResourceNames()
            .Single(n => n.EndsWith("isrg-root-x1.pem", StringComparison.Ordinal));
        using var stream = asm.GetManifestResourceStream(resourceName)!;
        using var reader = new StreamReader(stream);
        var pem = reader.ReadToEnd();
        return X509Certificate2.CreateFromPem(pem);
    }

    private static bool ValidateAgainstIsrgRootX1(
        object? sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is not X509Certificate2 cert) return false;

        using var customChain = new X509Chain();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(IsrgRootX1);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return customChain.Build(cert);
    }

    public static async Task HandleAsync(
        HttpContext ctx,
        IHttpForwarder forwarder,
        BunnyOperationRegistry registry,
        IUserRepository users,
        IGrantService grants)
    {
        var pathSuffix = ctx.Request.RouteValues["path"] as string ?? "";
        var fullIncomingPath = "/proxy/api.bunny.net/" + pathSuffix;

        var op = registry.FindByRequest(ctx.Request.Method, fullIncomingPath);
        if (op is null)
        {
            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (ctx.User.Identity?.IsAuthenticated != true)
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var email = ctx.User.FindFirstValue(ClaimTypes.Email);

        // Capability check for JWT clients (azp = authorized party = the OIDC client_id).
        // Cookie-authenticated users (direct browser access) are the account owners and
        // bypass this check — they still need a valid API key below.
        if (!op.RequiresAuthenticationOnly)
        {
            var clientId = ctx.User.FindFirstValue("azp");
            if (clientId is not null && email is not null)
            {
                var granted = await grants.GetGrantedCapabilitiesAsync(email, clientId);
                if (!granted.Contains(op.RequiredCapability!))
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync(
                        $$$"""{"error":"capability_not_granted","required":"{{{op.RequiredCapability}}}"}""");
                    return;
                }
            }
        }

        // Security boundary: strip inbound credential and identity headers
        ctx.Request.Headers.Remove("AccessKey");
        ctx.Request.Headers.Remove("Authorization");
        ctx.Request.Headers.Remove("X-Remote-User");
        ctx.Request.Headers.Remove("X-Remote-Groups");
        ctx.Request.Headers.Remove("X-Remote-Extra");

        // Inject the user's own bunny.net API key
        if (op.CredentialKind == BunnyCredentialKind.AccountApiKey)
        {
            var user = email is not null ? await users.FindByEmailAsync(email) : null;
            if (string.IsNullOrEmpty(user?.BunnyApiKey))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(
                    """{"error":"bunny_api_key_not_configured","detail":"Go to /settings to add your bunny.net API key."}""");
                return;
            }

            ctx.Request.Headers["AccessKey"] = user.BunnyApiKey;
        }

        var error = await forwarder.SendAsync(
            ctx,
            "https://api.bunny.net",
            HttpClient,
            ForwarderRequestConfig.Empty,
            new PathRewriteTransformer(pathSuffix));

        if (error != ForwarderError.None && !ctx.Response.HasStarted)
            ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
    }

    private sealed class PathRewriteTransformer(string pathSuffix) : HttpTransformer
    {
        public override async ValueTask TransformRequestAsync(
            HttpContext httpContext,
            HttpRequestMessage proxyRequest,
            string destinationPrefix,
            CancellationToken cancellationToken)
        {
            await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);
            var query = httpContext.Request.QueryString.Value ?? "";
            proxyRequest.RequestUri = new Uri($"https://api.bunny.net/{pathSuffix}{query}");
        }
    }
}
