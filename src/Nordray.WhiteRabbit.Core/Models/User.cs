namespace Nordray.WhiteRabbit.Core.Models;

public sealed class User
{
    public long Id { get; init; }
    public string Subject { get; init; } = "";
    public string Email { get; init; } = "";
    public string? DisplayName { get; init; }
    public DateTimeOffset CreatedUtc { get; init; }
    public DateTimeOffset LastLoginUtc { get; init; }
    /// <summary>
    /// The user's own bunny.net account API key. Stored per-user; injected into
    /// proxied requests as the AccessKey header. Null until the user configures it.
    /// </summary>
    public string? BunnyApiKey { get; init; }
}
