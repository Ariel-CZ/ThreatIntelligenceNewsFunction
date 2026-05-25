using Microsoft.Extensions.Logging;
using ThreatIntelligenceNewsFunction.Models;

namespace ThreatIntelligenceNewsFunction.Services;

public sealed class ThreatIntelligenceAggregator
{
    private readonly NvdCveClient _nvdCveClient;
    private readonly RssNewsClient _rssNewsClient;
    private readonly ILogger<ThreatIntelligenceAggregator> _logger;

    public ThreatIntelligenceAggregator(
        NvdCveClient nvdCveClient,
        RssNewsClient rssNewsClient,
        ILogger<ThreatIntelligenceAggregator> logger)
    {
        _nvdCveClient = nvdCveClient;
        _rssNewsClient = rssNewsClient;
        _logger = logger;
    }

    public async Task<ThreatIntelligenceResponse> GetThreatIntelligenceAsync(int days, CancellationToken cancellationToken)
    {
        var toUtc = DateTimeOffset.UtcNow;
        var fromUtc = toUtc.AddDays(-days);
        var warnings = new List<string>();

        IReadOnlyList<CveItem> cves = Array.Empty<CveItem>();
        try
        {
            cves = await _nvdCveClient.GetCvesAsync(fromUtc, toUtc, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read NVD CVE API.");
            warnings.Add($"Could not read NVD CVE API: {ex.Message}");
        }

        IReadOnlyList<NewsItem> news = Array.Empty<NewsItem>();
        try
        {
            var newsResult = await _rssNewsClient.GetNewsAsync(fromUtc, toUtc, cancellationToken);
            news = newsResult.News;
            warnings.AddRange(newsResult.Warnings);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read RSS news feeds.");
            warnings.Add($"Could not read RSS news feeds: {ex.Message}");
        }

        return new ThreatIntelligenceResponse(
            Days: days,
            FromUtc: fromUtc,
            ToUtc: toUtc,
            GeneratedAtUtc: DateTimeOffset.UtcNow,
            Cves: cves.OrderByDescending(c => c.PublishedUtc).ToList(),
            News: news.OrderByDescending(n => n.PublishedUtc).ToList(),
            Warnings: warnings);
    }
}
