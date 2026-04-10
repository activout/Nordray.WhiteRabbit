using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Yarp.ReverseProxy.Forwarder;

namespace Nordray.WhiteRabbit.Proxy;

/// <summary>
/// Replaces YARP's default IForwarderHttpClientFactory to pin outbound connections
/// to the bunny cluster against ISRG Root X1 (Let's Encrypt's root CA).
/// All other clusters (e.g. dex) get a standard handler.
/// </summary>
public sealed class BunnyHttpClientFactory : IForwarderHttpClientFactory
{
    private static readonly X509Certificate2 IsrgRootX1 = LoadIsrgRootX1();

    private static readonly HttpMessageInvoker BunnyClient = new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = ValidateAgainstIsrgRootX1,
        },
    });

    private static readonly HttpMessageInvoker DefaultClient = new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(15),
    });

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
        => context.ClusterId == "bunny" ? BunnyClient : DefaultClient;

    private static X509Certificate2 LoadIsrgRootX1()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames()
            .Single(n => n.EndsWith("isrg-root-x1.pem", StringComparison.Ordinal));
        using var stream = asm.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return X509Certificate2.CreateFromPem(reader.ReadToEnd());
    }

    private static bool ValidateAgainstIsrgRootX1(
        object? sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        if (certificate is not X509Certificate2 cert) return false;
        using var customChain = new X509Chain();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(IsrgRootX1);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return customChain.Build(cert);
    }
}
