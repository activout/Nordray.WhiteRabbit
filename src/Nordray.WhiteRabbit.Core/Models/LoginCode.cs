namespace Nordray.WhiteRabbit.Core.Models;

public sealed class LoginCode
{
    public long Id { get; init; }
    public string Email { get; init; } = "";
    public string CodeHash { get; init; } = "";
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset ExpiresUtc { get; init; }
    public DateTimeOffset? ConsumedUtc { get; init; }
    public string RequestIp { get; init; } = "";
}
