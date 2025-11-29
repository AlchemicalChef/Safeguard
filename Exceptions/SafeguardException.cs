namespace Safeguard.Exceptions;

/// <summary>
/// Base exception for all Safeguard-specific errors.
/// Provides error code and correlation ID for tracking and debugging.
/// </summary>
public class SafeguardException : Exception
{
    /// <summary>
    /// A short error code for categorizing the error (e.g., "AUTH_FAILED", "GRAPH_ERROR")
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>
    /// A unique correlation ID for tracking this specific error instance
    /// </summary>
    public string CorrelationId { get; }

    /// <summary>
    /// Additional context about the error for debugging
    /// </summary>
    public IDictionary<string, object> Context { get; }

    public SafeguardException(string message, string errorCode, Exception? innerException = null)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
        CorrelationId = Guid.NewGuid().ToString("N")[..8];
        Context = new Dictionary<string, object>();
    }

    public SafeguardException WithContext(string key, object value)
    {
        Context[key] = value;
        return this;
    }

    public override string ToString()
    {
        return $"[{ErrorCode}] {Message} (CorrelationId: {CorrelationId})";
    }
}
