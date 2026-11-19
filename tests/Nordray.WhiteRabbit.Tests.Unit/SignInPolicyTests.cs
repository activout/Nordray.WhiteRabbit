using Nordray.WhiteRabbit.Core.Access;

namespace Nordray.WhiteRabbit.Tests.Unit;

public class SignInPolicyTests
{
    private static SignInPolicy Policy(string[]? emails = null, string[]? domains = null) =>
        new(new AccessOptions { AllowedEmails = [.. emails ?? []], AllowedDomains = [.. domains ?? []] });

    [Fact]
    public void EmptyLists_AllowNobody()
    {
        var policy = Policy();
        Assert.False(policy.AllowsAnyone);
        Assert.False(policy.IsAllowed("anyone@example.com"));
    }

    [Theory]
    [InlineData("a@example.com", true)]
    [InlineData(" A@Example.COM ", true)]
    [InlineData("b@example.com", false)]
    [InlineData("a@example.com.evil.org", false)]
    public void Emails_MatchExactlyIgnoringCase(string email, bool allowed) =>
        Assert.Equal(allowed, Policy(emails: ["a@example.com"]).IsAllowed(email));

    [Theory]
    [InlineData("anyone@team.example", true)]
    [InlineData("anyone@TEAM.example", true)]
    [InlineData("anyone@sub.team.example", false)]
    [InlineData("anyone@evilteam.example", false)]
    [InlineData("team.example@evil.org", false)]
    public void Domains_MatchTheWholeDomainOnly(string email, bool allowed) =>
        Assert.Equal(allowed, Policy(domains: ["@team.example"]).IsAllowed(email));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("no-at-sign")]
    [InlineData("@example.com")]
    [InlineData("a@")]
    [InlineData("a@b@example.com")]
    public void MalformedAddresses_AreNeverAllowed(string? email) =>
        Assert.False(Policy(emails: ["a@example.com"], domains: ["example.com"]).IsAllowed(email));
}
