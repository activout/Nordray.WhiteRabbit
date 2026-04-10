using Nordray.WhiteRabbit.Bunny;

namespace Nordray.WhiteRabbit.Tests.Unit;

public class BunnyOperationRegistryTests
{
    private readonly BunnyOperationRegistry _registry = new();

    [Fact]
    public void FindByRequest_KnownOperation_ReturnsOperation()
    {
        var op = _registry.FindByRequest("GET", "/proxy/api.bunny.net/region");

        Assert.NotNull(op);
        Assert.Equal("core.region.list", op.OperationId);
    }

    [Fact]
    public void FindByRequest_UnknownOperation_ReturnsNull()
    {
        var op = _registry.FindByRequest("GET", "/proxy/api.bunny.net/unknown/endpoint");

        Assert.Null(op);
    }

    [Fact]
    public void FindByRequest_IsCaseInsensitiveOnMethod()
    {
        var op = _registry.FindByRequest("get", "/proxy/api.bunny.net/region");

        Assert.NotNull(op);
    }

    [Fact]
    public void FindByRequest_WrongMethod_ReturnsNull()
    {
        var op = _registry.FindByRequest("DELETE", "/proxy/api.bunny.net/region");

        Assert.Null(op);
    }

    [Fact]
    public void FindByRequest_PathParameter_Matches()
    {
        var op = _registry.FindByRequest("GET", "/proxy/api.bunny.net/pullzone/42");

        Assert.NotNull(op);
        Assert.Equal("core.pullzone.get", op.OperationId);
    }

    [Fact]
    public void FindByRequest_PathParameter_DoesNotMatchParent()
    {
        // GET /pullzone (no id) should match the list operation, not the get-by-id
        var op = _registry.FindByRequest("GET", "/proxy/api.bunny.net/pullzone");

        Assert.NotNull(op);
        Assert.Equal("core.pullzone.list", op.OperationId);
    }

    [Theory]
    [InlineData("GET",    "/proxy/api.bunny.net/region",      true,  null)]
    [InlineData("GET",    "/proxy/api.bunny.net/pullzone",     false, "pullzone.read")]
    [InlineData("POST",   "/proxy/api.bunny.net/pullzone",     false, "pullzone.write")]
    [InlineData("GET",    "/proxy/api.bunny.net/shield/zones", false, "shield.read")]
    public void FindByRequest_OperationHasCorrectAuthModel(
        string method, string path, bool expectedAuthOnly, string? expectedCapability)
    {
        var op = _registry.FindByRequest(method, path);

        Assert.NotNull(op);
        Assert.Equal(expectedAuthOnly, op.RequiresAuthenticationOnly);
        Assert.Equal(expectedCapability, op.RequiredCapability);
    }

    [Fact]
    public void AllOperations_HaveEitherCapabilityOrAuthOnly()
    {
        foreach (var op in _registry.GetAll())
        {
            var hasCapability = !string.IsNullOrEmpty(op.RequiredCapability);
            var isAuthOnly = op.RequiresAuthenticationOnly;
            Assert.True(hasCapability || isAuthOnly,
                $"Operation {op.OperationId} must have either RequiredCapability or RequiresAuthenticationOnly=true");
        }
    }

    [Fact]
    public void AllOperations_DestinationBaseUrl_IsApiDotBunnyDotNet()
    {
        foreach (var op in _registry.GetAll())
        {
            Assert.True(op.DestinationBaseUrl.StartsWith("https://api.bunny.net", StringComparison.Ordinal),
                $"Operation {op.OperationId} must target https://api.bunny.net only");
        }
    }

    [Fact]
    public void AllOperations_IncomingPath_StartsWithProxyPrefix()
    {
        foreach (var op in _registry.GetAll())
        {
            Assert.True(op.IncomingPathTemplate.StartsWith("/proxy/api.bunny.net/", StringComparison.Ordinal),
                $"Operation {op.OperationId} incoming path must be under /proxy/api.bunny.net/");
        }
    }

    [Fact]
    public void AllOperations_HaveStableUniqueOperationIds()
    {
        var ids = _registry.GetAll().Select(op => op.OperationId).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }
}
