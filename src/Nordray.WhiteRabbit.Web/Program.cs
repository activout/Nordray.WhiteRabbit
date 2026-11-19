using System.Data.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.RateLimiting;
using Nordray.WhiteRabbit.AuthProxy;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Infrastructure.Encryption;
using Nordray.WhiteRabbit.Proxy;
using Nordray.WhiteRabbit.Web;
using Nordray.WhiteRabbit.Web.Cli;
using Nordray.WhiteRabbit.Web.Proxy;
using Nordray.WhiteRabbit.Web.DataProtection;
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

// --- Capability seeder (scoped — uses the request-scoped connection) ---
builder.Services.AddScoped<CapabilitySeeder>();

// --- Data Protection ---
// The key ring protects the stored Bunny API keys, so it lives in the database (encrypted with
// DataProtection:EncryptionKey) instead of the container's file system, which is lost on replacement.
// The application name is fixed so keys stay valid when the content root or container path changes.
builder.Services.AddDataProtection().SetApplicationName("Nordray.WhiteRabbit");
builder.Services.AddOptions<KeyManagementOptions>().Configure<IServiceProvider>((keys, services) =>
{
    keys.XmlRepository = new DatabaseKeyRing(services);
    keys.XmlEncryptor = new KeyRingEncryptor(services.GetRequiredService<KeyRingEncryption>());
});

// --- Proxy clients ---
// OIDC client IDs whose Dex tokens the Bunny proxy accepts. Empty means none: tokens must name an
// explicitly configured audience.
var proxyClients = new ProxyClientOptions(
    configuration.GetSection("Proxy:AllowedClientIds").Get<string[]>() ?? []);
builder.Services.AddSingleton(proxyClients);

// --- rabbit CLI: sessions, CI federation, virtual credentials ---
builder.Services.Configure<CliOptions>(configuration.GetSection("Cli"));
builder.Services.Configure<FederationOptions>(configuration.GetSection("Federation"));
builder.Services.AddHttpClient("oidc-metadata", c => c.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddSingleton<IOidcMetadataProvider, OidcMetadataProvider>();
builder.Services.AddSingleton<IdentityTokenValidator>();
builder.Services.AddScoped<CliPrincipalResolver>();
builder.Services.AddScoped<SecurityAudit>();
builder.Services.AddSingleton<BunnyProxyGate>();
builder.Services.AddHttpContextAccessor();

// --- Authentication ---
// Cookie for the White Rabbit UI; JWT Bearer for Dex tokens of OIDC clients calling the proxy; CliSession for
// White Rabbit session tokens (wrs_…) on the CLI and admin API. A policy scheme picks one per request.
// Virtual credentials (AccessKey: wrk_…) are not an authentication scheme: only BunnyProxyGate accepts them.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "SmartScheme";
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddPolicyScheme("SmartScheme", "Cookie or Bearer", options =>
{
    options.ForwardDefaultSelector = ctx =>
        CliSessionAuthenticationHandler.Carries(ctx.Request) ? CliSessionAuthenticationHandler.SchemeName
        : ctx.Request.Headers.ContainsKey("Authorization") ? JwtBearerDefaults.AuthenticationScheme
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
    // Removing an address from the sign-in allow-list ends its existing sessions on their next request.
    options.Events.OnValidatePrincipal = async ctx =>
    {
        var policy = ctx.HttpContext.RequestServices.GetRequiredService<SignInPolicy>();
        if (!policy.IsAllowed(ctx.Principal?.FindFirstValue(ClaimTypes.Email)))
        {
            ctx.RejectPrincipal();
            await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    };
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    // Dex is the token authority. White Rabbit proxies its well-known endpoints
    // so the issuer URL is White Rabbit's own address in production.
    options.Authority = configuration["Dex:IssuerUrl"];
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.TokenValidationParameters = new()
    {
        // The token must be issued to one of the configured proxy clients. Issuer and signature come from
        // the Authority's metadata; GitHub, Forgejo or other-environment tokens fail on issuer or signature.
        ValidateAudience = true,
        ValidateIssuer = true,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        AudienceValidator = (audiences, _, _) => audiences.Any(proxyClients.AllowedClientIds.Contains),
    };
})
.AddScheme<AuthenticationSchemeOptions, CliSessionAuthenticationHandler>(CliSessionAuthenticationHandler.SchemeName, null);

builder.Services.AddAuthorization(options =>
{
    // The CLI API accepts only White Rabbit session tokens: never cookies, Dex tokens or virtual credentials.
    options.AddPolicy(CliEndpoints.SessionPolicy, policy => policy
        .AddAuthenticationSchemes(CliSessionAuthenticationHandler.SchemeName)
        .RequireAuthenticatedUser());
    // Binding administration additionally requires an interactive human session; CI sessions are refused.
    options.AddPolicy(CliEndpoints.HumanPolicy, policy => policy
        .AddAuthenticationSchemes(CliSessionAuthenticationHandler.SchemeName)
        .RequireAuthenticatedUser()
        .RequireClaim(CliSessionAuthenticationHandler.PrincipalTypeClaim, Nordray.WhiteRabbit.Core.Models.PrincipalTypes.Human));
});

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

    // Token exchange and the CLI API, per client address.
    opts.AddPolicy(CliEndpoints.ExchangeRateLimit, ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    opts.AddPolicy(CliEndpoints.ApiRateLimit, ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 300, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));

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
                if (transform.HttpContext.Items[BunnyProxyGate.AccessKeyItem] is string apiKey)
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

// Fail fast on a missing or malformed DataProtection:EncryptionKey, before anything is written.
app.Services.GetRequiredService<KeyRingEncryption>();

var signInPolicy = app.Services.GetRequiredService<SignInPolicy>();
if (!signInPolicy.AllowsAnyone)
    app.Logger.LogWarning("Access:AllowedEmails and Access:AllowedDomains are empty: nobody can sign in.");
if (proxyClients.AllowedClientIds.Count == 0)
    app.Logger.LogWarning("Proxy:AllowedClientIds is empty: the Bunny proxy accepts no bearer tokens.");


// Ensure database schema exists and capabilities are seeded before serving requests
await app.Services.GetRequiredService<DatabaseInitializer>().InitializeAsync();
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<CapabilitySeeder>().SeedAsync();
}

app.UseCorrelationId();
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
// /health: the process is running. /ready: the database answers and every shipped migration is applied.
// Neither exposes connection details or exception messages.
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/ready", async (DbConnection connection, ILogger<DatabaseMigrator> logger, CancellationToken ct) =>
{
    try
    {
        var pending = await new DatabaseMigrator(connection, logger).PendingVersionsAsync(ct);
        return pending.Count == 0
            ? Results.Ok(new { status = "ready" })
            : Results.Json(new { status = "not_ready", reason = "migrations_pending" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
        logger.LogWarning(ex, "Readiness check failed");
        return Results.Json(new { status = "not_ready", reason = "database_unavailable" }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

// --- rabbit CLI and binding administration API ---
app.MapCliEndpoints();

// --- Razor Pages ---
app.MapRazorPages();

// --- YARP (Dex + Bunny proxy) ---
// BunnyProxyGate enforces authentication (virtual credential or Dex token), the sign-in allow-list, capability
// grants and server-side credential injection for bunny routes before YARP forwards the request.
var bunnyGate = app.Services.GetRequiredService<BunnyProxyGate>();
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (ctx, next) =>
    {
        var route = ctx.Features.Get<IReverseProxyFeature>()?.Route;
        if (route?.Config.RouteId.StartsWith("bunny.", StringComparison.Ordinal) == true)
        {
            await bunnyGate.InvokeAsync(ctx, () => next(), route);
            return;
        }

        await next();
    });
});

app.Run();

/// <summary>Exposed for WebApplicationFactory in the integration tests.</summary>
public partial class Program;
