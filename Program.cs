using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ThreatIntelligenceNewsFunction.Services;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices(services =>
    {
        services.AddSingleton<NvdCveClient>();
        services.AddSingleton<RssNewsClient>();
        services.AddSingleton<ThreatIntelligenceAggregator>();
    })
    .Build();

host.Run();
