using System.Net;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;
using Polly.Timeout;
using Safeguard.Models;

namespace Safeguard.Infrastructure;

/// <summary>
/// Builds Polly resilience pipelines for HTTP and Graph API operations.
/// </summary>
public static class GraphResiliencePipeline
{
    /// <summary>
    /// Creates a resilience pipeline for HttpClient operations.
    /// Includes rate limiting retry, transient fault retry, circuit breaker, and timeout.
    /// </summary>
    public static ResiliencePipeline<HttpResponseMessage> CreateForHttp(ResilienceConfiguration config)
    {
        return new ResiliencePipelineBuilder<HttpResponseMessage>()
            // 1. Rate limiting handler - respects Retry-After header
            .AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                Name = "RateLimitRetry",
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .HandleResult(r => r.StatusCode == HttpStatusCode.TooManyRequests),
                MaxRetryAttempts = config.Retry.MaxRetryAttempts,
                DelayGenerator = GetRateLimitDelayGenerator(config)
            })
            // 2. Transient fault retry with exponential backoff + jitter
            .AddRetry(new RetryStrategyOptions<HttpResponseMessage>
            {
                Name = "TransientRetry",
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .HandleResult(ShouldRetryTransient)
                    .Handle<HttpRequestException>()
                    .Handle<TaskCanceledException>(ex => !ex.CancellationToken.IsCancellationRequested),
                MaxRetryAttempts = config.Retry.MaxRetryAttempts,
                BackoffType = config.Retry.UseExponentialBackoff
                    ? DelayBackoffType.Exponential
                    : DelayBackoffType.Linear,
                Delay = TimeSpan.FromSeconds(config.Retry.BaseDelaySeconds),
                MaxDelay = TimeSpan.FromSeconds(config.Retry.MaxDelaySeconds),
                UseJitter = true
            })
            // 3. Circuit breaker
            .AddCircuitBreaker(new CircuitBreakerStrategyOptions<HttpResponseMessage>
            {
                Name = "GraphCircuitBreaker",
                ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                    .HandleResult(r => (int)r.StatusCode >= 500)
                    .Handle<HttpRequestException>()
                    .Handle<TaskCanceledException>(ex => !ex.CancellationToken.IsCancellationRequested),
                FailureRatio = config.CircuitBreaker.FailureRatio,
                MinimumThroughput = config.CircuitBreaker.FailureThreshold,
                SamplingDuration = TimeSpan.FromSeconds(config.CircuitBreaker.SamplingDurationSeconds),
                BreakDuration = TimeSpan.FromSeconds(config.CircuitBreaker.BreakDurationSeconds)
            })
            // 4. Overall timeout
            .AddTimeout(TimeSpan.FromSeconds(config.Timeout.DefaultTimeoutSeconds))
            .Build();
    }

    private static Func<RetryDelayGeneratorArguments<HttpResponseMessage>, ValueTask<TimeSpan?>>
        GetRateLimitDelayGenerator(ResilienceConfiguration config)
    {
        return args =>
        {
            var response = args.Outcome.Result;
            if (response == null)
            {
                return ValueTask.FromResult<TimeSpan?>(
                    TimeSpan.FromSeconds(config.RateLimiting.DefaultRetryAfterSeconds));
            }

            // Try to get Retry-After header
            if (response.Headers.RetryAfter?.Delta is TimeSpan delta)
            {
                var clampedDelay = TimeSpan.FromSeconds(
                    Math.Min(delta.TotalSeconds, config.RateLimiting.MaxRetryAfterSeconds));
                return ValueTask.FromResult<TimeSpan?>(clampedDelay);
            }

            if (response.Headers.RetryAfter?.Date is DateTimeOffset date)
            {
                var delay = date - DateTimeOffset.UtcNow;
                if (delay > TimeSpan.Zero)
                {
                    var clampedDelay = TimeSpan.FromSeconds(
                        Math.Min(delay.TotalSeconds, config.RateLimiting.MaxRetryAfterSeconds));
                    return ValueTask.FromResult<TimeSpan?>(clampedDelay);
                }
            }

            return ValueTask.FromResult<TimeSpan?>(
                TimeSpan.FromSeconds(config.RateLimiting.DefaultRetryAfterSeconds));
        };
    }

    private static bool ShouldRetryTransient(HttpResponseMessage response)
    {
        // Don't retry rate limiting in the transient handler
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
            return false;

        // Retry on 5xx server errors and 408 Request Timeout
        var statusCode = (int)response.StatusCode;
        return statusCode is >= 500 and <= 599 or 408;
    }
}
