using System.Security.Cryptography;
using System.Text;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>PKCE S256 (RFC 7636) for the CLI login: the challenge is base64url(SHA-256(verifier)), 43 characters.</summary>
public static class Pkce
{
    public static bool IsChallenge(string? value) => IsBase64Url(value, 43, 43);

    public static bool Matches(string? verifier, string challenge)
    {
        // RFC 7636: 43–128 characters. The CLI sends base64url, a subset of the allowed alphabet.
        if (!IsBase64Url(verifier, 43, 128)) return false;
        var actual = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier!)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(challenge));
    }

    public static bool IsBase64Url(string? value, int min, int max) =>
        value is not null && value.Length >= min && value.Length <= max
        && value.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');
}
