namespace ThreatIntelligenceNewsFunction.Models;

public sealed record ThreatIntelligenceResponse(
    int Days,
    DateTimeOffset FromUtc,
    DateTimeOffset ToUtc,
    DateTimeOffset GeneratedAtUtc,
    IReadOnlyList<CveItem> Cves,
    IReadOnlyList<NewsItem> News,
    IReadOnlyList<string> Warnings);

public sealed record CveItem(
    string Id,
    DateTimeOffset? PublishedUtc,
    DateTimeOffset? LastModifiedUtc,
    string? Severity,
    double? CvssScore,
    string Description,
    string Url);

public sealed record NewsItem(
    string Source,
    string Title,
    string Url,
    DateTimeOffset? PublishedUtc,
    string? Summary);

public sealed record NewsFeedDefinition(string Name, string Url);
