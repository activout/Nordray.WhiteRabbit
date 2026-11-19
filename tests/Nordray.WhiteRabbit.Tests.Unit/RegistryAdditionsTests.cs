using System.Text.Json;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Proxy;

namespace Nordray.WhiteRabbit.Tests.Unit;

public class RegistryAdditionsTests
{
    private readonly BunnyOperationRegistry _registry = new();

    [Theory]
    [InlineData("GET", "/proxy/api.bunny.net/mc/apps", "mc.app.list")]
    [InlineData("GET", "/proxy/api.bunny.net/mc/apps/abc", "mc.app.get")]
    [InlineData("PATCH", "/proxy/api.bunny.net/mc/apps/abc/containers/def", "mc.container.update")]
    [InlineData("GET", "/proxy/api.bunny.net/mc/registries", "mc.registry.list")]
    [InlineData("GET", "/proxy/api.bunny.net/database/v2/databases", "db.database.list")]
    [InlineData("POST", "/proxy/api.bunny.net/database/v2/databases", "db.database.create")]
    [InlineData("PUT", "/proxy/api.bunny.net/database/v2/databases/x/auth/generate", "db.token.generate")]
    [InlineData("PUT", "/proxy/api.bunny.net/mc/apps/abc/containers/def/env", "mc.container.env.set")]
    [InlineData("POST", "/proxy/api.bunny.net/mc/apps", "mc.app.create")]
    [InlineData("DELETE", "/proxy/api.bunny.net/mc/apps/abc", "mc.app.delete")]
    [InlineData("DELETE", "/proxy/api.bunny.net/database/v2/databases/x", "db.database.delete")]
    [InlineData("POST", "/proxy/api.bunny.net/database/v1/live/live_db", "db.live.metrics")]
    [InlineData("GET", "/proxy/api.bunny.net/user", "core.user.get")]
    public void PathsBunnyCliSends_AreRegistered(string method, string path, string operationId) =>
        Assert.Equal(operationId, _registry.FindByRequest(method, path)?.OperationId);

    [Fact]
    public void NewOperations_AllNeedTheAccountKeyAndACapability()
    {
        foreach (var op in _registry.GetAll().Where(o => o.OperationId.StartsWith("mc.", StringComparison.Ordinal) || o.OperationId.StartsWith("db.", StringComparison.Ordinal)))
        {
            Assert.Equal(Core.BunnyCredentialKind.AccountApiKey, op.CredentialKind);
            Assert.False(op.RequiresAuthenticationOnly, op.OperationId);
            Assert.Contains(op.RequiredCapability, new[] { "mc.read", "mc.deploy", "mc.env", "mc.manage", "db.read", "db.manage", "db.token" });
        }
    }

    [Fact]
    public void DestructiveOperations_AreOnlyTheManageOnes()
    {
        var deletes = _registry.GetAll()
            .Where(o => o.IncomingMethod == "DELETE" && (o.OperationId.StartsWith("mc.", StringComparison.Ordinal) || o.OperationId.StartsWith("db.", StringComparison.Ordinal)))
            .Select(o => (o.OperationId, o.RequiredCapability)).OrderBy(o => o.OperationId).ToList();
        Assert.Equal([("db.database.delete", "db.manage"), ("mc.app.delete", "mc.manage")], deletes);
        Assert.DoesNotContain(_registry.GetAll(), o => o.IncomingPathTemplate.Contains("/log/forwarding", StringComparison.Ordinal));
        // The only token-issuing operation is the explicit db.token one.
        Assert.Equal(["db.token.generate"], _registry.GetAll().Where(o => o.IncomingPathTemplate.Contains("/auth/", StringComparison.Ordinal)).Select(o => o.OperationId));
    }

    [Fact]
    public void DatabaseStatus_IsARead_ThatOnlyNamesDatabases()
    {
        var op = _registry.GetAll().Single(o => o.OperationId == "db.live.metrics");
        Assert.Equal("db.read", op.RequiredCapability);
        Assert.Equal(["db_ids"], op.AllowedBodyFields);
    }

    [Fact]
    public void User_NeedsAccountRead()
    {
        var op = _registry.GetAll().Single(o => o.OperationId == "core.user.get");
        Assert.Equal("account.read", op.RequiredCapability);
        Assert.Equal(Core.BunnyCredentialKind.AccountApiKey, op.CredentialKind);
        Assert.Empty(op.RedactJsonFields);
    }

    [Fact]
    public void SettingTheEnvironment_RestoresRedactedValues_AndRedactsTheAnswer()
    {
        var env = Assert.Single(_registry.GetAll(), o => o.IncomingPathTemplate.EndsWith("/env", StringComparison.Ordinal));
        Assert.Equal("mc.env", env.RequiredCapability);
        Assert.Equal("/mc/apps/{appId}/containers/{containerId}", env.RestoreRedactedEnvironmentFrom);
        Assert.Contains("environmentVariables[].value", env.RedactJsonFields);
    }

    [Fact]
    public void EveryResponseWithEnvironmentValues_IsRedacted()
    {
        foreach (var id in new[] { "mc.app.get", "mc.app.create", "mc.container.get", "mc.container.update", "mc.container.env.set" })
            Assert.NotEmpty(_registry.GetAll().Single(o => o.OperationId == id).RedactJsonFields);
    }

    [Fact]
    public void EveryCapability_HasExactlyOneDescription_AndNoneIsUnused()
    {
        var used = _registry.GetAll().Where(o => o.RequiredCapability is not null).Select(o => o.RequiredCapability!).Distinct().Order(StringComparer.Ordinal);
        var described = _registry.GetCapabilities().Select(c => c.Name).Order(StringComparer.Ordinal);
        Assert.Equal(used, described);
        Assert.All(_registry.GetCapabilities(), c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Title), c.Name);
            Assert.False(string.IsNullOrWhiteSpace(c.Description), c.Name);
        });
    }

    [Theory]
    [InlineData("mc.read", "registries")]
    [InlineData("mc.read", "redacted")]
    [InlineData("db.read", "every Bunny Database database")]
    [InlineData("db.read", "limits")]
    [InlineData("mc.manage", "delete any app")]
    [InlineData("db.manage", "delete any database")]
    public void CapabilityDescriptions_CoverEveryOperation(string capability, string phrase) =>
        Assert.Contains(phrase, _registry.GetCapabilities().Single(c => c.Name == capability).Description);

    [Fact]
    public void ContainerUpdate_AllowsOnlyImageFields()
    {
        var update = _registry.GetAll().Single(o => o.OperationId == "mc.container.update");
        Assert.NotNull(update.AllowedBodyFields);
        Assert.All(update.AllowedBodyFields!, f => Assert.StartsWith("image", f));
    }

    [Fact]
    public void OperationIdsAreUnique() =>
        Assert.Equal(_registry.GetAll().Count, _registry.GetAll().Select(o => o.OperationId).Distinct().Count());

    [Fact]
    public void Redaction_ReplacesNestedArrayValues_AndKeepsEverythingElse()
    {
        var json = """{"containerTemplates":[{"id":"c1","environmentVariables":[{"name":"A","value":"s1"},{"name":"B","value":"s2"}]},{"id":"c2"}],"name":"app"}""";
        var result = JsonDocument.Parse(JsonRedaction.Redact(json, ["containerTemplates[].environmentVariables[].value"])!).RootElement;

        var first = result.GetProperty("containerTemplates")[0];
        Assert.Equal("c1", first.GetProperty("id").GetString());
        Assert.All(first.GetProperty("environmentVariables").EnumerateArray(), e =>
        {
            Assert.Equal(JsonRedaction.Placeholder, e.GetProperty("value").GetString());
            Assert.StartsWith("", e.GetProperty("name").GetString());
        });
        Assert.Equal("app", result.GetProperty("name").GetString());
    }

    [Fact]
    public void Redaction_IsCaseInsensitiveAndIgnoresMissingFields()
    {
        var json = """{"EnvironmentVariables":[{"Name":"A","Value":"s1"}],"other":1}""";
        var redacted = JsonRedaction.Redact(json, ["environmentVariables[].value", "missing[].field"])!;
        Assert.DoesNotContain("s1", redacted);
        Assert.Contains("\"other\":1", redacted);
    }

    [Fact]
    public void Redaction_OfNonJson_ReturnsNull() =>
        Assert.Null(JsonRedaction.Redact("A=secret", ["value"]));

    [Fact]
    public void EveryRedactionPath_IsWellFormed()
    {
        foreach (var path in _registry.GetAll().SelectMany(o => o.RedactJsonFields))
            Assert.Matches(@"^[A-Za-z]+(\[\])?(\.[A-Za-z]+(\[\])?)*$", path);
    }
}
