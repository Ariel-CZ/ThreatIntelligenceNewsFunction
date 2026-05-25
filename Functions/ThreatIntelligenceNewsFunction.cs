using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using ThreatIntelligenceNewsFunction.Services;

namespace ThreatIntelligenceNewsFunction.Functions;

public sealed class ThreatIntelligenceNewsFunction
{
    private readonly ThreatIntelligenceAggregator _aggregator;

    public ThreatIntelligenceNewsFunction(ThreatIntelligenceAggregator aggregator)
    {
        _aggregator = aggregator;
    }

    [Function("threatintelligencenews")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = "threatintelligencenews")] HttpRequestData request,
        CancellationToken cancellationToken)
    {
        var days = GetDays(request.Url);
        if (days < 1 || days > 120)
        {
            var badResponse = request.CreateResponse(HttpStatusCode.BadRequest);
            await badResponse.WriteAsJsonAsync(new { error = "The 'days' query parameter must be between 1 and 120." }, cancellationToken);
            return badResponse;
        }

        var result = await _aggregator.GetThreatIntelligenceAsync(days, cancellationToken);
        var response = request.CreateResponse(HttpStatusCode.OK);
        await response.WriteAsJsonAsync(result, cancellationToken);
        return response;
    }

    private static int GetDays(Uri requestUri)
    {
        var query = requestUri.Query.TrimStart('?');
        if (string.IsNullOrWhiteSpace(query))
        {
            return 7;
        }

        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var pair = part.Split('=', 2);
            var key = WebUtility.UrlDecode(pair[0]);
            if (!string.Equals(key, "days", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = pair.Length > 1 ? WebUtility.UrlDecode(pair[1]) : string.Empty;
            return int.TryParse(value, out var days) ? days : 7;
        }

        return 7;
    }
}
