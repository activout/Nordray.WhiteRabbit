using System.Data;
using Dapper;
using Nordray.WhiteRabbit.Core.Services;

namespace Nordray.WhiteRabbit.Infrastructure.Audit;

public sealed class AuditService(IDbConnection db) : IAuditService
{
    public async Task RecordAsync(
        string operationId,
        string? email,
        string? clientId,
        string outcome,
        int httpStatusCode,
        CancellationToken ct = default)
    {
        await db.ExecuteAsync("""
            INSERT INTO AuditEvents (OccurredUtc, ClientId, OperationId, Outcome, HttpStatusCode)
            VALUES (@occurredUtc, @clientId, @operationId, @outcome, @httpStatusCode)
            """,
            new
            {
                occurredUtc = DateTimeOffset.UtcNow.ToString("O"),
                clientId = email is not null ? $"{email}/{clientId}" : clientId,
                operationId,
                outcome,
                httpStatusCode,
            });
    }
}
