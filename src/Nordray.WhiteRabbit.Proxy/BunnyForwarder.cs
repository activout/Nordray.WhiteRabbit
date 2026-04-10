using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Yarp.ReverseProxy.Forwarder;

namespace Nordray.WhiteRabbit.Proxy;

/// <summary>
/// Direct HTTP forwarder for validated bunny.net API requests.
/// Mounted at /proxy/api.bunny.net/{**path} — requests are validated against the
/// operation registry and the user's own bunny.net API key is injected per-request.
/// </summary>
public static class BunnyForwarder
{
    private static readonly HttpMessageInvoker HttpClient = new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    });

    public static async Task HandleAsync(
        HttpContext ctx,
        IHttpForwarder forwarder,
        BunnyOperationRegistry registry,
        IUserRepository users)
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

        // TODO: capability check against grant table

        // Security boundary: strip any inbound credential or identity headers
        ctx.Request.Headers.Remove("AccessKey");
        ctx.Request.Headers.Remove("Authorization");
        ctx.Request.Headers.Remove("X-Remote-User");
        ctx.Request.Headers.Remove("X-Remote-Groups");
        ctx.Request.Headers.Remove("X-Remote-Extra");

        // Inject the user's own bunny.net credential
        if (op.CredentialKind == BunnyCredentialKind.AccountApiKey)
        {
            var email = ctx.User.FindFirstValue(ClaimTypes.Email);
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

    /// <summary>
    /// Rewrites the outgoing URI from /proxy/api.bunny.net/{path} to https://api.bunny.net/{path}.
    /// </summary>
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
