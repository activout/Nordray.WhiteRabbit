using System.Security.Claims;
using Nordray.WhiteRabbit.Core.Access;

namespace Nordray.WhiteRabbit.Tests.Unit;

public class OidcClientIdentityTests
{
    private static readonly IReadOnlySet<string> Allowed = new HashSet<string> { "rabbit-cli", "example-client" };

    private static ClaimsPrincipal Principal(string? azp, params string[] audiences)
    {
        var claims = audiences.Select(a => new Claim("aud", a)).ToList();
        if (azp is not null) claims.Add(new Claim("azp", azp));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
    }

    [Fact]
    public void SingleAllowedAudience_IsTheClient() =>
        Assert.Equal("rabbit-cli", OidcClientIdentity.Resolve(Principal(null, "rabbit-cli"), Allowed));

    [Fact]
    public void AzpAmongAudiences_WinsOverOtherAudiences() =>
        Assert.Equal("example-client", OidcClientIdentity.Resolve(Principal("example-client", "rabbit-cli", "example-client"), Allowed));

    [Fact]
    public void AzpNotAmongAudiences_IsRejected() =>
        Assert.Null(OidcClientIdentity.Resolve(Principal("rabbit-cli", "example-client"), Allowed));

    [Fact]
    public void SeveralAudiencesWithoutAzp_IsRejected() =>
        Assert.Null(OidcClientIdentity.Resolve(Principal(null, "rabbit-cli", "example-client"), Allowed));

    [Fact]
    public void ClientNotConfigured_IsRejected() =>
        Assert.Null(OidcClientIdentity.Resolve(Principal(null, "someone-else"), Allowed));

    [Fact]
    public void NoAudience_IsRejected() =>
        Assert.Null(OidcClientIdentity.Resolve(Principal(null), Allowed));
}
