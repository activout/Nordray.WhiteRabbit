using Activout.DatabaseClient.Attributes;
using Nordray.WhiteRabbit.Core.Models;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface ILoginCodeRepository
{
    [SqlUpdate("INSERT INTO LoginCodes (Email, CodeHash, CodeSalt, CreatedUtc, ExpiresUtc, RequestIp) VALUES (@Email, @CodeHash, @CodeSalt, @CreatedUtc, @ExpiresUtc, @RequestIp)")]
    Task InsertAsync([BindProperties] LoginCode code);

    [SqlQuery("SELECT * FROM LoginCodes WHERE Email = @email AND ConsumedUtc IS NULL AND ExpiresUtc > @now ORDER BY CreatedUtc DESC LIMIT 1")]
    Task<LoginCode?> FindActiveByEmailAsync([Bind("email")] string email, [Bind("now")] DateTime now);

    [SqlUpdate("UPDATE LoginCodes SET ConsumedUtc = @consumedUtc WHERE Id = @id")]
    Task MarkConsumedAsync([Bind("id")] long id, [Bind("consumedUtc")] DateTime consumedUtc);

    [SqlUpdate("UPDATE LoginCodes SET FailedAttempts = FailedAttempts + 1 WHERE Id = @id")]
    Task IncrementFailedAttemptsAsync([Bind("id")] long id);

    [SqlQuery("SELECT COUNT(*) FROM LoginCodes WHERE Email = @email AND CreatedUtc > @since")]
    Task<long> CountByEmailSinceAsync([Bind("email")] string email, [Bind("since")] DateTime since);

    [SqlUpdate("DELETE FROM LoginCodes WHERE ExpiresUtc < @cutoff OR (ConsumedUtc IS NOT NULL AND ConsumedUtc < @cutoff)")]
    Task<int> DeleteExpiredAsync([Bind("cutoff")] DateTime cutoff);
}
