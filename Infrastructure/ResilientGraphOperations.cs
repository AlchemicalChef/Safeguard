using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Graph.Models.ODataErrors;
using Polly;
using Polly.CircuitBreaker;
using Polly.Retry;
using Polly.Timeout;
using Safeguard.Exceptions;
using Safeguard.Models;

namespace Safeguard.Infrastructure;

/// <summary>
/// Wraps Microsoft Graph SDK operations with resilience policies.
/// </summary>
public class ResilientGraphOperations
{
    private readonly ResilienceConfiguration _config;
    private readonly ResiliencePipeline _pipeline;
    private readonly ILogger _logger;

    /// <summary>
    /// Fired when a request is throttled (429). Provides retry-after seconds and operation name.
    /// </summary>
    public event Action<int, string>? OnThrottled;

    /// <summary>
    /// Fired when a retry is attempted. Provides attempt number, delay, and operation name.
    /// </summary>
    public event Action<int, TimeSpan, string>? OnRetry;

    /// <summary>
    /// Fired when the circuit breaker opens due to repeated failures. Provides operation name.
    /// </summary>
    public event Action<string>? OnCircuitOpened;

    /// <summary>
    /// Fired when the circuit breaker closes after recovery. Provides operation name.
    /// </summary>
    public event Action<string>? OnCircuitClosed;

    public ResilientGraphOperations(ResilienceConfiguration? config = null, ILogger? logger = null)
    {
        _config = config ?? new ResilienceConfiguration();
        _logger = logger ?? NullLogger.Instance;
        _pipeline = BuildPipeline();
    }

    private const string OperationNameKey = "OperationName";

    /// <summary>
    /// Executes a Graph API operation with resilience policies.
    /// </summary>
    public async Task<T?> ExecuteAsync<T>(
        Func<Task<T?>> operation,
        string operationName,
        CancellationToken cancellationToken = default)
    {
        var context = ResilienceContextPool.Shared.Get(cancellationToken);
        context.Properties.Set(new ResiliencePropertyKey<string>(OperationNameKey), operationName);

        try
        {
            return await _pipeline.ExecuteAsync(async ctx =>
            {
                try
                {
                    return await operation();
                }
                catch (ODataError odataEx)
                {
                    throw MapODataException(odataEx, operationName);
                }
            }, context);
        }
        catch (BrokenCircuitException ex)
        {
            _logger.LogError(ex, "Circuit breaker open for {Operation}", operationName);
            throw new EntraConnectionException(
                "Service temporarily unavailable due to repeated failures. Please try again later.",
                ConnectionFailureType.CircuitBreakerOpen,
                innerException: ex);
        }
        catch (TimeoutRejectedException ex)
        {
            _logger.LogError(ex, "Timeout for {Operation}", operationName);
            throw new EntraConnectionException(
                $"Operation '{operationName}' timed out.",
                ConnectionFailureType.Timeout,
                innerException: ex);
        }
        finally
        {
            ResilienceContextPool.Shared.Return(context);
        }
    }

    /// <summary>
    /// Executes a Graph API operation that doesn't return a value with resilience policies.
    /// </summary>
    public async Task ExecuteAsync(
        Func<Task> operation,
        string operationName,
        CancellationToken cancellationToken = default)
    {
        var context = ResilienceContextPool.Shared.Get(cancellationToken);
        context.Properties.Set(new ResiliencePropertyKey<string>(OperationNameKey), operationName);

        try
        {
            await _pipeline.ExecuteAsync(async ctx =>
            {
                try
                {
                    await operation();
                }
                catch (ODataError odataEx)
                {
                    throw MapODataException(odataEx, operationName);
                }
            }, context);
        }
        catch (BrokenCircuitException ex)
        {
            _logger.LogError(ex, "Circuit breaker open for {Operation}", operationName);
            throw new EntraConnectionException(
                "Service temporarily unavailable due to repeated failures. Please try again later.",
                ConnectionFailureType.CircuitBreakerOpen,
                innerException: ex);
        }
        catch (TimeoutRejectedException ex)
        {
            _logger.LogError(ex, "Timeout for {Operation}", operationName);
            throw new EntraConnectionException(
                $"Operation '{operationName}' timed out.",
                ConnectionFailureType.Timeout,
                innerException: ex);
        }
        finally
        {
            ResilienceContextPool.Shared.Return(context);
        }
    }

    private static string GetOperationName(ResilienceContext context)
    {
        return context.Properties.TryGetValue(new ResiliencePropertyKey<string>(OperationNameKey), out var name)
            ? name
            : "Unknown";
    }

    private ResiliencePipeline BuildPipeline()
    {
        return new ResiliencePipelineBuilder()
            // 1. Rate limiting retry
            .AddRetry(new RetryStrategyOptions
            {
                Name = "GraphRateLimitRetry",
                ShouldHandle = new PredicateBuilder().Handle<GraphThrottledException>(),
                MaxRetryAttempts = _config.Retry.MaxRetryAttempts,
                DelayGenerator = args =>
                {
                    if (args.Outcome.Exception is GraphThrottledException throttled)
                    {
                        var opName = GetOperationName(args.Context);
                        _logger.LogWarning("Throttled during {Operation}, waiting {RetryAfter}s",
                            opName, throttled.RetryAfterSeconds);
                        OnThrottled?.Invoke(throttled.RetryAfterSeconds, opName);
                        return ValueTask.FromResult<TimeSpan?>(
                            TimeSpan.FromSeconds(throttled.RetryAfterSeconds));
                    }
                    return ValueTask.FromResult<TimeSpan?>(
                        TimeSpan.FromSeconds(_config.RateLimiting.DefaultRetryAfterSeconds));
                }
            })
            // 2. Transient fault retry
            .AddRetry(new RetryStrategyOptions
            {
                Name = "GraphTransientRetry",
                ShouldHandle = new PredicateBuilder()
                    .Handle<GraphTransientException>()
                    .Handle<HttpRequestException>()
                    .Handle<TaskCanceledException>(ex => !ex.CancellationToken.IsCancellationRequested),
                MaxRetryAttempts = _config.Retry.MaxRetryAttempts,
                BackoffType = _config.Retry.UseExponentialBackoff
                    ? DelayBackoffType.Exponential
                    : DelayBackoffType.Linear,
                Delay = TimeSpan.FromSeconds(_config.Retry.BaseDelaySeconds),
                MaxDelay = TimeSpan.FromSeconds(_config.Retry.MaxDelaySeconds),
                UseJitter = true,
                OnRetry = args =>
                {
                    var opName = GetOperationName(args.Context);
                    var delay = args.RetryDelay;
                    _logger.LogDebug("Retry {Attempt} for {Operation}, delay {DelayMs}ms",
                        args.AttemptNumber, opName, delay.TotalMilliseconds);
                    OnRetry?.Invoke(args.AttemptNumber, delay, opName);
                    return ValueTask.CompletedTask;
                }
            })
            // 3. Circuit breaker
            .AddCircuitBreaker(new CircuitBreakerStrategyOptions
            {
                Name = "GraphCircuitBreaker",
                ShouldHandle = new PredicateBuilder()
                    .Handle<GraphTransientException>()
                    .Handle<HttpRequestException>(),
                FailureRatio = _config.CircuitBreaker.FailureRatio,
                MinimumThroughput = _config.CircuitBreaker.FailureThreshold,
                SamplingDuration = TimeSpan.FromSeconds(_config.CircuitBreaker.SamplingDurationSeconds),
                BreakDuration = TimeSpan.FromSeconds(_config.CircuitBreaker.BreakDurationSeconds),
                OnOpened = args =>
                {
                    var opName = GetOperationName(args.Context);
                    _logger.LogWarning("Circuit breaker opened for {Operation}", opName);
                    OnCircuitOpened?.Invoke(opName);
                    return ValueTask.CompletedTask;
                },
                OnClosed = args =>
                {
                    var opName = GetOperationName(args.Context);
                    _logger.LogInformation("Circuit breaker closed for {Operation}", opName);
                    OnCircuitClosed?.Invoke(opName);
                    return ValueTask.CompletedTask;
                }
            })
            // 4. Timeout
            .AddTimeout(TimeSpan.FromSeconds(_config.Timeout.DefaultTimeoutSeconds))
            .Build();
    }

    private Exception MapODataException(ODataError odataEx, string operationName)
    {
        var errorCode = odataEx.Error?.Code ?? "";
        var statusCode = odataEx.ResponseStatusCode;

        // Rate limiting
        if (statusCode == 429 || errorCode == "TooManyRequests")
        {
            var retryAfter = ExtractRetryAfter(odataEx);
            return new GraphThrottledException(operationName, retryAfter, odataEx);
        }

        // Transient errors that should be retried
        if (statusCode >= 500 || IsTransientErrorCode(errorCode))
        {
            return new GraphTransientException(operationName, odataEx);
        }

        // Non-retryable - wrap in GraphApiException for proper error reporting
        return GraphApiException.FromODataError(odataEx, operationName);
    }

    private int ExtractRetryAfter(ODataError error)
    {
        if (error.Error?.AdditionalData?.TryGetValue("retry-after", out var retryValue) == true)
        {
            if (retryValue is string retryStr && int.TryParse(retryStr, out var seconds))
            {
                return Math.Min(seconds, _config.RateLimiting.MaxRetryAfterSeconds);
            }
        }
        return _config.RateLimiting.DefaultRetryAfterSeconds;
    }

    private static bool IsTransientErrorCode(string errorCode) =>
        errorCode is "ServiceNotAvailable" or "InternalServerError"
            or "BadGateway" or "GatewayTimeout" or "ServiceUnavailable";
}

/// <summary>
/// Internal exception for throttling errors - triggers retry with specific delay.
/// </summary>
internal class GraphThrottledException : Exception
{
    public string Operation { get; }
    public int RetryAfterSeconds { get; }

    public GraphThrottledException(string operation, int retryAfterSeconds, Exception? inner = null)
        : base($"Graph API throttled for '{operation}'", inner)
    {
        Operation = operation;
        RetryAfterSeconds = retryAfterSeconds;
    }
}

/// <summary>
/// Internal exception for transient errors - triggers retry with backoff.
/// </summary>
internal class GraphTransientException : Exception
{
    public string Operation { get; }

    public GraphTransientException(string operation, Exception? inner = null)
        : base($"Transient Graph API error for '{operation}'", inner)
    {
        Operation = operation;
    }
}
