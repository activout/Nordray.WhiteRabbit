namespace Nordray.WhiteRabbit.Core.Services;

public interface IEmailService
{
    Task SendLoginCodeAsync(string toEmail, string code, CancellationToken ct = default);
}
