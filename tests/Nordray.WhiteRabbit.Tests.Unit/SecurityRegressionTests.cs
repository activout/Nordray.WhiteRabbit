using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Nordray.WhiteRabbit.Infrastructure.Email;
using Nordray.WhiteRabbit.Proxy;

namespace Nordray.WhiteRabbit.Tests.Unit;

public class SecurityRegressionTests
{
    [Theory]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch)]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors)]
    [InlineData(SslPolicyErrors.RemoteCertificateNotAvailable)]
    public void BunnyTls_RefusesAnythingButAChainError(SslPolicyErrors errors)
    {
        using var rsa = RSA.Create(2048);
        using var cert = new CertificateRequest("CN=not-bunny.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.False(BunnyHttpClientFactory.ValidateAgainstIsrgRootX1(null, cert, null, errors));
    }

    [Fact]
    public async Task Email_WithoutTransportOutsideDevelopment_FailsInsteadOfLoggingTheCode()
    {
        var environment = new Mock<IHostEnvironment>();
        environment.SetupGet(e => e.EnvironmentName).Returns("Production");
        var service = new MailjetEmailService(
            Options.Create(new MailjetOptions()), environment.Object, NullLogger<MailjetEmailService>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.SendLoginCodeAsync("a@example.com", "123456"));
    }
}
