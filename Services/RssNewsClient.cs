using System.Net;
using System.Xml.Linq;
using Microsoft.Extensions.Configuration;
using ThreatIntelligenceNewsFunction.Models;

namespace ThreatIntelligenceNewsFunction.Services;

public sealed class RssNewsClient
{
    private static readonly HttpClient HttpClient = CreateHttpClient();
    private readonly IConfiguration _configuration;

    public RssNewsClient(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<(IReadOnlyList<NewsItem> News, IReadOnlyList<string> Warnings)> GetNewsAsync(DateTimeOffset fromUtc, DateTimeOffset toUtc, CancellationToken cancellationToken)
    {
        var news = new List<NewsItem>();
        var warnings = new List<string>();

        foreach (var feed in GetConfiguredFeeds())
        {
            try
            {
                using var stream = await HttpClient.GetStreamAsync(feed.Url, cancellationToken);
                var document = await XDocument.LoadAsync(stream, LoadOptions.None, cancellationToken);
                news.AddRange(ParseFeed(document, feed, fromUtc, toUtc));
            }
            catch (Exception ex)
            {
                warnings.Add($"Could not read feed '{feed.Name}' ({feed.Url}): {ex.Message}");
            }
        }

        return (news.OrderByDescending(n => n.PublishedUtc).ThenBy(n => n.Source).ToList(), warnings);
    }

    private IReadOnlyList<NewsFeedDefinition> GetConfiguredFeeds()
    {
        var feeds = _configuration.GetSection("CyberSecurityNewsFeeds")
            .GetChildren()
            .Select(section => new NewsFeedDefinition(
                section["Name"] ?? section.Key,
                section["Url"] ?? string.Empty))
            .Where(feed => !string.IsNullOrWhiteSpace(feed.Url))
            .ToList();

        if (feeds.Count > 0)
        {
            return feeds;
        }

        return new List<NewsFeedDefinition>
        {
            new("KrebsOnSecurity", "https://krebsonsecurity.com/feed/"),
            new("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
            new("BleepingComputer", "https://www.bleepingcomputer.com/feed/")
        };
    }

    private static IEnumerable<NewsItem> ParseFeed(XDocument document, NewsFeedDefinition feed, DateTimeOffset fromUtc, DateTimeOffset toUtc)
    {
        var root = document.Root;
        if (root is null)
        {
            yield break;
        }

        var itemElements = root.Name.LocalName.Equals("feed", StringComparison.OrdinalIgnoreCase)
            ? root.Elements().Where(e => e.Name.LocalName.Equals("entry", StringComparison.OrdinalIgnoreCase))
            : root.Descendants().Where(e => e.Name.LocalName.Equals("item", StringComparison.OrdinalIgnoreCase));

        foreach (var item in itemElements)
        {
            var published = ParseDate(GetChildValue(item, "pubDate") ?? GetChildValue(item, "published") ?? GetChildValue(item, "updated"));
            if (published.HasValue)
            {
                var publishedUtc = published.Value.ToUniversalTime();
                if (publishedUtc < fromUtc || publishedUtc > toUtc)
                {
                    continue;
                }

                published = publishedUtc;
            }

            var title = WebUtility.HtmlDecode(GetChildValue(item, "title") ?? string.Empty).Trim();
            var url = GetRssLink(item) ?? GetAtomLink(item) ?? string.Empty;
            var summary = WebUtility.HtmlDecode(GetChildValue(item, "description") ?? GetChildValue(item, "summary") ?? GetChildValue(item, "content"));

            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(url))
            {
                continue;
            }

            yield return new NewsItem(
                Source: feed.Name,
                Title: title,
                Url: url,
                PublishedUtc: published,
                Summary: string.IsNullOrWhiteSpace(summary) ? null : summary.Trim());
        }
    }

    private static string? GetChildValue(XElement element, string localName)
        => element.Elements().FirstOrDefault(e => e.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))?.Value;

    private static string? GetRssLink(XElement item)
        => GetChildValue(item, "link")?.Trim();

    private static string? GetAtomLink(XElement item)
    {
        var link = item.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("link", StringComparison.OrdinalIgnoreCase));
        return link?.Attribute("href")?.Value?.Trim() ?? link?.Value?.Trim();
    }

    private static DateTimeOffset? ParseDate(string? value)
        => DateTimeOffset.TryParse(value, out var result) ? result : null;

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("ThreatIntelligenceNewsFunction/1.0");
        return client;
    }
}
