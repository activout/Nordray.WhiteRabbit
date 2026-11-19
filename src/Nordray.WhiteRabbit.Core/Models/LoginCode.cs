namespace Nordray.WhiteRabbit.Core.Models;

/// <remarks>All timestamps are UTC <see cref="DateTime"/> values, stored as sortable text.</remarks>
public sealed class LoginCode
{
    public long Id { get; init; }
    public string Email { get; init; } = "";
    public string CodeHash { get; init; } = "";
    public DateTime CreatedUtc { get; init; }
    public DateTime ExpiresUtc { get; init; }
    public DateTime? ConsumedUtc { get; init; }
    public string RequestIp { get; init; } = "";
    public string CodeSalt { get; init; } = "";
    public int FailedAttempts { get; init; }
}
