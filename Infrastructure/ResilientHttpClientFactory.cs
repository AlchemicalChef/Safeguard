using Polly;
using Safeguard.Models;

namespace Safeguard.Infrastructure;

/// <summary>
/// Factory for creating HttpClient instances with resilience policies.
/// </summary>
public class ResilientHttpClientFactory
{
    private readonly ResilienceConfiguration _config;
    private readonly ResiliencePipeline<HttpResponseMessage> _pipeline;

    public ResilientHttpClientFactory(ResilienceConfiguration? config = null)
    {
        _config = config ?? new ResilienceConfiguration();
        _pipeline = GraphResiliencePipeline.CreateForHttp(_config);
    }

    /// <summary>
    /// Creates a new HttpClient with resilience handler.
    /// </summary>
    public HttpClient CreateClient()
    {
        var handler = new ResilienceHandler(_pipeline)
        {
            InnerHandler = new HttpClientHandler()
        };

        return new HttpClient(handler)
        {
            // Set to infinite - let Polly handle all timeouts
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    /// <summary>
    /// Creates a new HttpClient with resilience handler and custom inner handler.
    /// </summary>
    public HttpClient CreateClient(HttpMessageHandler innerHandler)
    {
        var handler = new ResilienceHandler(_pipeline)
        {
            InnerHandler = innerHandler
        };

        return new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }
}

/// <summary>
/// Delegating handler that applies resilience pipeline to HTTP requests.
/// </summary>
public class ResilienceHandler : DelegatingHandler
{
    private readonly ResiliencePipeline<HttpResponseMessage> _pipeline;

    public ResilienceHandler(ResiliencePipeline<HttpResponseMessage> pipeline)
    {
        _pipeline = pipeline;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        return await _pipeline.ExecuteAsync(
            async ct => await base.SendAsync(request, ct),
            cancellationToken);
    }
}
