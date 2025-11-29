namespace Safeguard.Models;

/// <summary>
/// Configuration for resilience policies (retry, circuit breaker, timeout).
/// </summary>
public class ResilienceConfiguration
{
    public RetrySettings Retry { get; set; } = new();
    public CircuitBreakerSettings CircuitBreaker { get; set; } = new();
    public TimeoutSettings Timeout { get; set; } = new();
    public RateLimitingSettings RateLimiting { get; set; } = new();
}

/// <summary>
/// Configuration for retry behavior.
/// </summary>
public class RetrySettings
{
    /// <summary>
    /// Maximum number of retry attempts before giving up.
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 5;

    /// <summary>
    /// Base delay in seconds between retry attempts.
    /// </summary>
    public int BaseDelaySeconds { get; set; } = 1;

    /// <summary>
    /// Maximum delay in seconds between retry attempts (caps exponential backoff).
    /// </summary>
    public int MaxDelaySeconds { get; set; } = 30;

    /// <summary>
    /// Whether to use exponential backoff (true) or linear backoff (false).
    /// </summary>
    public bool UseExponentialBackoff { get; set; } = true;
}

/// <summary>
/// Configuration for circuit breaker behavior.
/// </summary>
public class CircuitBreakerSettings
{
    /// <summary>
    /// Number of failures required to trip the circuit breaker.
    /// </summary>
    public int FailureThreshold { get; set; } = 5;

    /// <summary>
    /// Duration of the sampling window in seconds for calculating failure ratio.
    /// </summary>
    public int SamplingDurationSeconds { get; set; } = 30;

    /// <summary>
    /// Duration in seconds to keep the circuit breaker open before allowing a test request.
    /// </summary>
    public int BreakDurationSeconds { get; set; } = 30;

    /// <summary>
    /// Ratio of failures (0.0 to 1.0) required to trip the circuit breaker.
    /// </summary>
    public double FailureRatio { get; set; } = 0.5;
}

/// <summary>
/// Configuration for timeout behavior.
/// </summary>
public class TimeoutSettings
{
    /// <summary>
    /// Default timeout in seconds for standard operations.
    /// </summary>
    public int DefaultTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Timeout in seconds for long-running operations (batch operations, scans).
    /// </summary>
    public int LongOperationTimeoutSeconds { get; set; } = 120;
}

/// <summary>
/// Configuration for rate limiting/throttling handling.
/// </summary>
public class RateLimitingSettings
{
    /// <summary>
    /// Default delay in seconds when no Retry-After header is provided.
    /// </summary>
    public int DefaultRetryAfterSeconds { get; set; } = 60;

    /// <summary>
    /// Maximum delay in seconds to wait when throttled (caps Retry-After values).
    /// </summary>
    public int MaxRetryAfterSeconds { get; set; } = 300;
}
