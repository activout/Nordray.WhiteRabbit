using Activout.DatabaseClient.Attributes;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface IAuditDao
{
    [SqlUpdate("""
        INSERT INTO AuditEvents (OccurredUtc, ClientId, OperationId, Outcome, HttpStatusCode)
        VALUES (@occurredUtc, @clientId, @operationId, @outcome, @httpStatusCode)
        """)]
    Task InsertAsync(
        [Bind("occurredUtc")] DateTime occurredUtc,
        [Bind("clientId")] string? clientId,
        [Bind("operationId")] string operationId,
        [Bind("outcome")] string outcome,
        [Bind("httpStatusCode")] int httpStatusCode);
}
