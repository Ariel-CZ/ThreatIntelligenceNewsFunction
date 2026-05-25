using System.Net.Http.Json;
using System.Text.Json.Serialization;
using ThreatIntelligenceNewsFunction.Models;

namespace ThreatIntelligenceNewsFunction.Services;

public sealed class NvdCveClient
{
    private static readonly HttpClient HttpClient = CreateHttpClient();

    public async Task<IReadOnlyList<CveItem>> GetCvesAsync(DateTimeOffset fromUtc, DateTimeOffset toUtc, CancellationToken cancellationToken)
    {
        var start = Uri.EscapeDataString(fromUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fff"));
        var end = Uri.EscapeDataString(toUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fff"));
        var requestUrl = $"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=50";

        var response = await HttpClient.GetFromJsonAsync<NvdResponse>(requestUrl, cancellationToken);
        if (response?.Vulnerabilities is null)
        {
            return Array.Empty<CveItem>();
        }

        return response.Vulnerabilities
            .Select(ToCveItem)
            .Where(c => !string.IsNullOrWhiteSpace(c.Id))
            .OrderByDescending(c => c.PublishedUtc)
            .ToList();
    }

    private static CveItem ToCveItem(NvdVulnerability vulnerability)
    {
        var cve = vulnerability.Cve;
        var description = cve?.Descriptions?.FirstOrDefault(d => string.Equals(d.Lang, "en", StringComparison.OrdinalIgnoreCase))?.Value ?? string.Empty;

        var severity = cve?.Metrics?.CvssMetricV31?.FirstOrDefault()?.CvssData?.BaseSeverity
            ?? cve?.Metrics?.CvssMetricV30?.FirstOrDefault()?.CvssData?.BaseSeverity
            ?? cve?.Metrics?.CvssMetricV2?.FirstOrDefault()?.BaseSeverity;

        var score = cve?.Metrics?.CvssMetricV31?.FirstOrDefault()?.CvssData?.BaseScore
            ?? cve?.Metrics?.CvssMetricV30?.FirstOrDefault()?.CvssData?.BaseScore
            ?? cve?.Metrics?.CvssMetricV2?.FirstOrDefault()?.CvssData?.BaseScore;

        var id = cve?.Id ?? string.Empty;
        return new CveItem(
            Id: id,
            PublishedUtc: ParseDate(cve?.Published),
            LastModifiedUtc: ParseDate(cve?.LastModified),
            Severity: severity,
            CvssScore: score,
            Description: description,
            Url: string.IsNullOrWhiteSpace(id) ? string.Empty : $"https://nvd.nist.gov/vuln/detail/{id}");
    }

    private static DateTimeOffset? ParseDate(string? value)
        => DateTimeOffset.TryParse(value, out var result) ? result.ToUniversalTime() : null;

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("ThreatIntelligenceNewsFunction/1.0");
        return client;
    }

    private sealed class NvdResponse
    {
        [JsonPropertyName("vulnerabilities")]
        public List<NvdVulnerability>? Vulnerabilities { get; set; }
    }

    private sealed class NvdVulnerability
    {
        [JsonPropertyName("cve")]
        public NvdCve? Cve { get; set; }
    }

    private sealed class NvdCve
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("published")]
        public string? Published { get; set; }

        [JsonPropertyName("lastModified")]
        public string? LastModified { get; set; }

        [JsonPropertyName("descriptions")]
        public List<NvdDescription>? Descriptions { get; set; }

        [JsonPropertyName("metrics")]
        public NvdMetrics? Metrics { get; set; }
    }

    private sealed class NvdDescription
    {
        [JsonPropertyName("lang")]
        public string? Lang { get; set; }

        [JsonPropertyName("value")]
        public string? Value { get; set; }
    }

    private sealed class NvdMetrics
    {
        [JsonPropertyName("cvssMetricV31")]
        public List<NvdCvssMetric>? CvssMetricV31 { get; set; }

        [JsonPropertyName("cvssMetricV30")]
        public List<NvdCvssMetric>? CvssMetricV30 { get; set; }

        [JsonPropertyName("cvssMetricV2")]
        public List<NvdCvssMetricV2>? CvssMetricV2 { get; set; }
    }

    private sealed class NvdCvssMetric
    {
        [JsonPropertyName("cvssData")]
        public NvdCvssData? CvssData { get; set; }
    }

    private sealed class NvdCvssMetricV2
    {
        [JsonPropertyName("cvssData")]
        public NvdCvssData? CvssData { get; set; }

        [JsonPropertyName("baseSeverity")]
        public string? BaseSeverity { get; set; }
    }

    private sealed class NvdCvssData
    {
        [JsonPropertyName("baseSeverity")]
        public string? BaseSeverity { get; set; }

        [JsonPropertyName("baseScore")]
        public double? BaseScore { get; set; }
    }
}
