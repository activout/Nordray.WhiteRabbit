using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;

// Namespace deliberately uses "LoginCodes" (plural) to avoid clash with the
// Nordray.WhiteRabbit.Core.Models.LoginCode class name.
namespace Nordray.WhiteRabbit.Infrastructure.LoginCodes;

public sealed class LoginCodeService(
    ILoginCodeRepository loginCodes,
    IEmailService emailService,
    IOptions<LoginCodeOptions> options) : ILoginCodeService
{
    // Codes are locked out after this many consecutive failed verification attempts.
    private const int MaxFailedAttempts = 5;

    public async Task GenerateAndSendAsync(string email, string requestIp, CancellationToken ct = default)
    {
        var opts = options.Value;
        var now = DateTimeOffset.UtcNow;

        var recentCount = await loginCodes.CountByEmailSinceAsync(email, now.AddHours(-1));
        if (recentCount >= opts.MaxCodesPerEmailPerHour)
            throw new RateLimitExceededException(
                "Too many login code requests for this address. Please wait before trying again.");

        var salt = GenerateSalt();
        var code = GenerateCode();
        var hash = HashCode(salt, code);

        await loginCodes.InsertAsync(new LoginCode
        {
            Email = email,
            CodeHash = hash,
            CodeSalt = salt,
            CreatedUtc = now,
            ExpiresUtc = now.AddMinutes(opts.ExpiryMinutes),
            RequestIp = requestIp,
        });

        await emailService.SendLoginCodeAsync(email, code, ct);
    }

    public async Task<bool> VerifyAsync(string email, string code, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var active = await loginCodes.FindActiveByEmailAsync(email, now);
        if (active is null) return false;

        // Lock the code after too many wrong guesses to prevent brute-force.
        if (active.FailedAttempts >= MaxFailedAttempts) return false;

        var hash = HashCode(active.CodeSalt, code);
        if (!string.Equals(active.CodeHash, hash, StringComparison.Ordinal))
        {
            await loginCodes.IncrementFailedAttemptsAsync(active.Id);
            return false;
        }

        await loginCodes.MarkConsumedAsync(active.Id, now);
        return true;
    }

    private static string GenerateSalt()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static string GenerateCode()
    {
        var bytes = new byte[4];
        RandomNumberGenerator.Fill(bytes);
        var value = BitConverter.ToUInt32(bytes) % 1_000_000;
        return value.ToString("D6");
    }

    private static string HashCode(string salt, string code)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(salt + code));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
