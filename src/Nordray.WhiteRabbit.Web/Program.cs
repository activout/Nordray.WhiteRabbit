using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Nordray.WhiteRabbit.AuthProxy;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Proxy;
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// Secrets are never stored in appsettings files. All sensitive values must be
// supplied as WhiteRabbit_* environment variables (__ maps to : in config hierarchy).
// Example: WhiteRabbit_Mailjet__ApiKey=xxx  →  Mailjet:ApiKey
builder.Configuration.AddEnvironmentVariables(prefix: "WhiteRabbit_");

var configuration = builder.Configuration;

// --- Infrastructure (DB, email, login codes, grants, audit) ---
builder.Services.AddInfrastructure(configuration);

// Create the registry before DI is built so we can use it to generate YARP routes.
var bunnyRegistry = new BunnyOperationRegistry();
builder.Services.AddSingleton(bunnyRegistry);

// --- Capability seeder (scoped — uses IDbConnection) ---
builder.Services.AddScoped<CapabilitySeeder>();

// --- Authentication ---
// Cookie for White Rabbit UI; JWT Bearer for OIDC clients calling the proxy.
// A policy scheme selects the right handler based on the presence of Authorization header.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "SmartScheme";
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddPolicyScheme("SmartScheme", "Cookie or Bearer", options =>
{
    options.ForwardDefaultSelector = ctx =>
        ctx.Request.Headers.ContainsKey("Authorization")
            ? JwtBearerDefaults.AuthenticationScheme
            : CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/login";
    options.Cookie.Name = "WhiteRabbit.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    // Dex is the token authority. White Rabbit proxies its well-known endpoints
    // so the issuer URL is White Rabbit's own address in production.
    options.Authority = configuration["Dex:IssuerUrl"];
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.TokenValidationParameters = new()
    {
        ValidateAudience = false, // Audience varies per client; issuer + signature are sufficient
    };
});

builder.Services.AddAuthorization();

// --- Rate limiting ---
builder.Services.AddRateLimiter(opts =>
{
    opts.AddFixedWindowLimiter("login", o =>
    {
        o.PermitLimit = 20;
        o.Window = TimeSpan.FromHours(1);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 0;
    });

    // Stricter limit on code verification to prevent brute-force of 6-digit codes.
    opts.AddFixedWindowLimiter("login-verify", o =>
    {
        o.PermitLimit = 10;
        o.Window = TimeSpan.FromMinutes(15);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 0;
    });

    opts.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// --- YARP routes and clusters ---

var dexAddress = configuration["Dex:InternalAddress"] ?? "http://dex:5556";

var dexRoutes = new List<RouteConfig>
{
    new() { RouteId = "dex-auth",      ClusterId = "dex", Match = new RouteMatch { Path = "/auth/{**catch}" } },
    new() { RouteId = "dex-discovery", ClusterId = "dex", Match = new RouteMatch { Path = "/.well-known/openid-configuration" } },
    new() { RouteId = "dex-token",     ClusterId = "dex", Match = new RouteMatch { Path = "/token" } },
    new() { RouteId = "dex-keys",      ClusterId = "dex", Match = new RouteMatch { Path = "/keys" } },
    new() { RouteId = "dex-userinfo",  ClusterId = "dex", Match = new RouteMatch { Path = "/userinfo" } },
    new() { RouteId = "dex-callback",  ClusterId = "dex", Match = new RouteMatch { Path = "/callback/{**catch}" } },
};

// One YARP route per registered bunny operation. Metadata carries the capability
// and credential requirements so the proxy pipeline can enforce them without
// re-doing the registry lookup at request time.
var bunnyRoutes = bunnyRegistry.GetAll().Select(op => new RouteConfig
{
    RouteId = $"bunny.{op.OperationId}",
    ClusterId = "bunny",
    Match = new RouteMatch
    {
        Path = op.IncomingPathTemplate,
        Methods = [op.IncomingMethod],
    },
    Metadata = new Dictionary<string, string>
    {
        ["Capability"]   = op.RequiredCapability ?? "",
        ["AuthOnly"]     = op.RequiresAuthenticationOnly ? "true" : "false",
        ["CredentialKind"] = op.CredentialKind.ToString(),
    },
}).ToList();

var dexCluster = new ClusterConfig
{
    ClusterId = "dex",
    Destinations = new Dictionary<string, DestinationConfig>
    {
        ["primary"] = new() { Address = dexAddress },
    },
};

var bunnyCluster = new ClusterConfig
{
    ClusterId = "bunny",
    Destinations = new Dictionary<string, DestinationConfig>
    {
        ["primary"] = new() { Address = "https://api.bunny.net" },
    },
};

builder.Services.AddReverseProxy()
    .LoadFromMemory([.. dexRoutes, .. bunnyRoutes], [dexCluster, bunnyCluster])
    .AddTransforms(ctx =>
    {
        // Dex: inject X-Remote-User for the authproxy connector.
        // The connector requires it on both /auth/* and /callback/* requests.
        if (ctx.Route.RouteId is "dex-auth" or "dex-callback")
        {
            ctx.AddRequestTransform(transform =>
            {
                var email = DexAuthProxyMiddleware.GetRemoteUser(transform.HttpContext)
                         ?? transform.HttpContext.User.FindFirstValue(ClaimTypes.Email);
                if (email is not null)
                    transform.ProxyRequest.Headers.TryAddWithoutValidation("X-Remote-User", email);
                return ValueTask.CompletedTask;
            });
        }

        // Bunny: strip /proxy/api.bunny.net prefix, remove inbound credential and
        // identity headers, set Host, and inject the user's AccessKey that the
        // pipeline middleware stored in Items.
        if (ctx.Route.RouteId.StartsWith("bunny.", StringComparison.Ordinal))
        {
            ctx.AddPathRemovePrefix("/proxy/api.bunny.net");
            ctx.AddRequestHeaderRemove("AccessKey");
            ctx.AddRequestHeaderRemove("Authorization");
            ctx.AddRequestHeaderRemove("X-Remote-User");
            ctx.AddRequestHeaderRemove("X-Remote-Groups");
            ctx.AddRequestHeaderRemove("X-Remote-Extra");
            ctx.AddRequestTransform(transform =>
            {
                transform.ProxyRequest.Headers.Host = "api.bunny.net";
                if (transform.HttpContext.Items["bunny.access-key"] is string apiKey)
                    transform.ProxyRequest.Headers.TryAddWithoutValidation("AccessKey", apiKey);
                return ValueTask.CompletedTask;
            });
        }
    });

// Replace the default YARP HTTP client factory so outbound bunny connections
// are pinned to ISRG Root X1 (the certificate chain used by api.bunny.net).
builder.Services.AddSingleton<IForwarderHttpClientFactory, BunnyHttpClientFactory>();

// --- UI ---
builder.Services.AddRazorPages();

// -----------------------------------------------------------------------
var app = builder.Build();
// -----------------------------------------------------------------------

// Create a named data protector for encrypting/decrypting stored bunny API keys.
// The purpose string is versioned so it can be rotated in the future.
var bunnyKeyProtector = app.Services
    .GetRequiredService<IDataProtectionProvider>()
    .CreateProtector("BunnyApiKey.v1");

// Ensure database schema exists and capabilities are seeded before serving requests
await app.Services.GetRequiredService<DatabaseInitializer>().InitializeAsync();
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<CapabilitySeeder>().SeedAsync();
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// DexAuthProxyMiddleware intercepts /auth/* (but not /auth/email/* which are White Rabbit endpoints)
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/auth", StringComparison.OrdinalIgnoreCase)
        && !ctx.Request.Path.StartsWithSegments("/auth/email", StringComparison.OrdinalIgnoreCase),
    branch => branch.UseMiddleware<DexAuthProxyMiddleware>());

// --- Health endpoints ---
app.MapGet("/.well-known/health", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/.well-known/ready", (DatabaseInitializer _) => Results.Ok(new { status = "ready" }));

// --- Razor Pages ---
app.MapRazorPages();

// --- YARP (Dex + Bunny proxy) ---
// The pipeline middleware enforces auth, OIDC client requirement, capability grants,
// and credential injection for bunny routes before YARP forwards the request.
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (ctx, next) =>
    {
        var route = ctx.Features.Get<IReverseProxyFeature>()?.Route;
        if (route?.Config.RouteId.StartsWith("bunny.", StringComparison.Ordinal) == true)
        {
            var metadata = route.Config.Metadata!;
            var audit = ctx.RequestServices.GetRequiredService<IAuditService>();
            var operationId = route.Config.RouteId["bunny.".Length..];

            // 1. Require authentication
            if (ctx.User.Identity?.IsAuthenticated != true)
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await audit.RecordAsync(operationId, null, null, "denied_unauthenticated", 401);
                return;
            }

            // 2. The proxy is only accessible via OIDC client tokens.
            //    Prefer azp (authorized party); fall back to aud (audience) which Dex
            //    sets to the client_id when there is only one audience.
            //    Cookie-session users have neither claim and are redirected to use a
            //    registered OIDC client instead.
            var clientId = ctx.User.FindFirstValue("azp")
                        ?? ctx.User.FindFirstValue("aud");
            if (clientId is null)
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(
                    """{"error":"proxy_requires_oidc","detail":"The proxy is only accessible via OIDC client tokens. Use a registered client application."}""");
                await audit.RecordAsync(operationId, ctx.User.FindFirstValue(ClaimTypes.Email), null, "denied_no_oidc_client", 403);
                return;
            }

            var email = ctx.User.FindFirstValue(ClaimTypes.Email);

            // 3. Capability check — every JWT client must have an explicit grant.
            if (metadata["AuthOnly"] != "true")
            {
                var capability = metadata["Capability"];
                var grants = ctx.RequestServices.GetRequiredService<IGrantService>();
                var granted = await grants.GetGrantedCapabilitiesAsync(email ?? "", clientId);
                if (!granted.Contains(capability))
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync(
                        $$"""{"error":"capability_not_granted","required":"{{capability}}"}""");
                    await audit.RecordAsync(operationId, email, clientId, "denied_capability", 403);
                    return;
                }
            }

            // 4. Inject the user's own bunny.net API key via Items so the transform
            //    can add it to the proxy request after header copying.
            if (metadata["CredentialKind"] == "AccountApiKey")
            {
                var users = ctx.RequestServices.GetRequiredService<IUserRepository>();
                var user = email is not null ? await users.FindByEmailAsync(email) : null;
                if (string.IsNullOrEmpty(user?.BunnyApiKey))
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync(
                        """{"error":"bunny_api_key_not_configured","detail":"Go to /settings to add your bunny.net API key."}""");
                    await audit.RecordAsync(operationId, email, clientId, "denied_no_api_key", 403);
                    return;
                }

                // Decrypt the stored API key. If decryption fails the key was stored
                // as plaintext before encryption was introduced — treat as missing.
                string plaintextKey;
                try
                {
                    plaintextKey = bunnyKeyProtector.Unprotect(user.BunnyApiKey);
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync(
                        """{"error":"bunny_api_key_not_configured","detail":"Your API key needs to be re-entered. Go to /settings to update it."}""");
                    await audit.RecordAsync(operationId, email, clientId, "denied_key_decryption_failed", 403);
                    return;
                }
                ctx.Items["bunny.access-key"] = plaintextKey;
            }

            await next();
            await audit.RecordAsync(operationId, email, clientId, "allowed", ctx.Response.StatusCode);
            return;
        }

        await next();
    });
});

app.Run();
