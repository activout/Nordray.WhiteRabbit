namespace Nordray.WhiteRabbit.Core.Models;

/// <remarks>All timestamps are UTC <see cref="DateTime"/> values, stored as sortable text.</remarks>
public sealed class User
{
    public long Id { get; init; }
    public string Subject { get; init; } = "";
    public string Email { get; init; } = "";
    public string? DisplayName { get; init; }
    public DateTime CreatedUtc { get; init; }
    public DateTime LastLoginUtc { get; init; }
    /// <summary>
    /// The user's own bunny.net account API key. Stored per-user; injected into
    /// proxied requests as the AccessKey header. Null until the user configures it.
    /// </summary>
    public string? BunnyApiKey { get; init; }
}
