namespace Nordray.WhiteRabbit.Infrastructure.Email;

public sealed class MailjetOptions
{
    public string ApiKey { get; set; } = "";
    public string SecretKey { get; set; } = "";
    public string FromEmail { get; set; } = "";
    public string FromName { get; set; } = "White Rabbit";

    // Dev/test only: when set, emails are delivered via SMTP (e.g. Mailpit) instead of the Mailjet API.
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 1025;
}
