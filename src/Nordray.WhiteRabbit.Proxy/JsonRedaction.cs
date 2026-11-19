using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nordray.WhiteRabbit.Proxy;

/// <summary>
/// Replaces fields of a JSON document that callers must not see, e.g. container environment variable values in a
/// Magic Containers app. Paths use <c>.</c> between properties and <c>[]</c> for every element of an array.
/// Fields that are absent are ignored; only present string, number or boolean values are replaced.
/// </summary>
public static class JsonRedaction
{
    public const string Placeholder = "[redacted by White Rabbit]";

    /// <summary>The redacted document, or null when the input is not JSON (the caller then fails closed).</summary>
    public static string? Redact(string json, IReadOnlyList<string> paths)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }
        if (root is null) return null;
        foreach (var path in paths)
            Apply(root, Parse(path), 0);
        return root.ToJsonString();
    }

    private static List<(string Name, bool Each)> Parse(string path) =>
        path.Split('.').Select(s => s.EndsWith("[]", StringComparison.Ordinal) ? (s[..^2], true) : (s, false)).ToList();

    private static void Apply(JsonNode? node, List<(string Name, bool Each)> segments, int index)
    {
        if (node is not JsonObject obj) return;
        var (name, each) = segments[index];
        // Bunny's APIs are not consistent about casing; match the property name case-insensitively.
        var key = obj.Select(p => p.Key).FirstOrDefault(k => string.Equals(k, name, StringComparison.OrdinalIgnoreCase));
        if (key is null) return;
        var last = index == segments.Count - 1;

        if (each)
        {
            if (obj[key] is not JsonArray array) return;
            for (var i = 0; i < array.Count; i++)
            {
                if (last) array[i] = Placeholder;
                else Apply(array[i], segments, index + 1);
            }
            return;
        }

        if (last)
        {
            if (obj[key] is JsonValue) obj[key] = Placeholder;
            return;
        }
        Apply(obj[key], segments, index + 1);
    }
}
