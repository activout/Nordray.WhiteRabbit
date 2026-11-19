using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Infrastructure.Audit;

public sealed class AuditService(IAuditDao audit) : IAuditService
{
    public Task RecordAsync(
        string operationId,
        string? email,
        string? clientId,
        string outcome,
        int httpStatusCode,
        CancellationToken ct = default) =>
        audit.InsertAsync(
            DateTime.UtcNow,
            email is not null ? $"{email}/{clientId}" : clientId,
            operationId,
            outcome,
            httpStatusCode);
}
