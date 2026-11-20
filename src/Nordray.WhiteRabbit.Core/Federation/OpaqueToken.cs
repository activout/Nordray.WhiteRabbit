using System.Security.Cryptography;
using System.Text;

namespace Nordray.WhiteRabbit.Core.Federation;

/// <summary>
/// Unpredictable bearer secrets. Only <see cref="Hash"/> is ever stored; the prefix makes a leaked value easy to
/// recognise in logs and secret scanners.
/// </summary>
public static class OpaqueToken
{
    /// <summary>White Rabbit CLI session token, sent as <c>Authorization: Bearer</c>.</summary>
    public const string SessionPrefix = "wrs_";

    /// <summary>Virtual Bunny credential, sent as <c>AccessKey</c> to White Rabbit's proxy only.</summary>
    public const string VirtualKeyPrefix = "wrk_";

    /// <summary>One-time CLI login code, handed to the CLI's loopback listener by <c>/cli/login</c>.</summary>
    public const string LoginCodePrefix = "wrc_";

    /// <summary>The prefix followed by 256 random bits, base64url without padding.</summary>
    public static string Generate(string prefix)
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return prefix + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Lower-case hex SHA-256 of the whole token, prefix included.</summary>
    public static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    /// <summary>A cheap shape check before any database lookup: right prefix, right length, base64url only.</summary>
    public static bool LooksLike(string? token, string prefix) =>
        token is not null
        && token.Length == prefix.Length + 43
        && token.StartsWith(prefix, StringComparison.Ordinal)
        && token.AsSpan(prefix.Length).IndexOfAnyExcept(Base64UrlChars) < 0;

    private static readonly System.Buffers.SearchValues<char> Base64UrlChars =
        System.Buffers.SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
}
