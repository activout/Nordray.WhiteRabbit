using Activout.DatabaseClient.Attributes;
using Nordray.WhiteRabbit.Core.Models;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface ILoginCodeRepository
{
    [SqlUpdate("INSERT INTO LoginCodes (Email, CodeHash, CreatedUtc, ExpiresUtc, RequestIp) VALUES (@Email, @CodeHash, @CreatedUtc, @ExpiresUtc, @RequestIp)")]
    Task InsertAsync([BindProperties] LoginCode code);

    [SqlQuery("SELECT * FROM LoginCodes WHERE Email = @email AND ConsumedUtc IS NULL AND ExpiresUtc > @now ORDER BY CreatedUtc DESC LIMIT 1")]
    Task<LoginCode?> FindActiveByEmailAsync([Bind("email")] string email, [Bind("now")] DateTimeOffset now);

    [SqlUpdate("UPDATE LoginCodes SET ConsumedUtc = @consumedUtc WHERE Id = @id")]
    Task MarkConsumedAsync([Bind("id")] long id, [Bind("consumedUtc")] DateTimeOffset consumedUtc);

    [SqlQuery("SELECT COUNT(*) FROM LoginCodes WHERE Email = @email AND CreatedUtc > @since")]
    Task<long> CountByEmailSinceAsync([Bind("email")] string email, [Bind("since")] DateTimeOffset since);
}
