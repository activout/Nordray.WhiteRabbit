using System.Net.Mail;
using Mailjet.Client;
using Mailjet.Client.TransactionalEmails;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Core.Services;

namespace Nordray.WhiteRabbit.Infrastructure.Email;

public sealed class MailjetEmailService(
    IOptions<MailjetOptions> options,
    ILogger<MailjetEmailService> logger) : IEmailService
{
    public async Task SendLoginCodeAsync(string toEmail, string code, CancellationToken ct = default)
    {
        var opts = options.Value;

        if (!string.IsNullOrEmpty(opts.ApiKey))
        {
            await SendViaMailjetAsync(opts, toEmail, code);
            return;
        }

        if (!string.IsNullOrEmpty(opts.SmtpHost))
        {
            await SendViaSmtpAsync(opts, toEmail, code, ct);
            return;
        }

        // Last resort: log the code so development is never completely blocked
        logger.LogInformation(
            "No email transport configured. Login code for {Email}: {Code}", toEmail, code);
    }

    private static async Task SendViaMailjetAsync(MailjetOptions opts, string toEmail, string code)
    {
        var client = new MailjetClient(opts.ApiKey, opts.SecretKey);

        var email = new TransactionalEmailBuilder()
            .WithFrom(new SendContact(opts.FromEmail, opts.FromName))
            .WithSubject("Your White Rabbit login code")
            .WithTextPart(
                $"Your login code is: {code}\n\n" +
                "This code expires in 10 minutes. Do not share it with anyone.")
            .WithTo(new SendContact(toEmail))
            .Build();

        await client.SendTransactionalEmailAsync(email);
    }

    private async Task SendViaSmtpAsync(MailjetOptions opts, string toEmail, string code, CancellationToken ct)
    {
        using var smtp = new SmtpClient(opts.SmtpHost, opts.SmtpPort);
        smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
        smtp.EnableSsl = false;

        var from = string.IsNullOrEmpty(opts.FromEmail)
            ? "noreply@whiterabbit.local"
            : opts.FromEmail;

        using var message = new MailMessage(from, toEmail)
        {
            Subject = "Your White Rabbit login code",
            Body =
                $"Your login code is: {code}\n\n" +
                "This code expires in 10 minutes. Do not share it with anyone.",
        };

        await smtp.SendMailAsync(message, ct);
        logger.LogInformation("Login code sent via SMTP to {Email}", toEmail);
    }
}
