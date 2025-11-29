namespace Safeguard.Exceptions;

/// <summary>
/// Exception thrown when connection to Entra ID fails.
/// </summary>
public class EntraConnectionException : SafeguardException
{
    /// <summary>
    /// The tenant ID that was being connected to
    /// </summary>
    public string? TenantId { get; }

    /// <summary>
    /// The type of connection failure
    /// </summary>
    public ConnectionFailureType FailureType { get; }

    public EntraConnectionException(
        string message,
        ConnectionFailureType failureType,
        string? tenantId = null,
        Exception? innerException = null)
        : base(message, GetErrorCode(failureType), innerException)
    {
        TenantId = tenantId;
        FailureType = failureType;
    }

    private static string GetErrorCode(ConnectionFailureType failureType) => failureType switch
    {
        ConnectionFailureType.TenantUnreachable => "CONN_TENANT_UNREACHABLE",
        ConnectionFailureType.ServiceUnavailable => "CONN_SERVICE_UNAVAILABLE",
        ConnectionFailureType.ThrottlingExceeded => "CONN_THROTTLED",
        ConnectionFailureType.ConfigurationError => "CONN_CONFIG_ERROR",
        ConnectionFailureType.CertificateError => "CONN_CERT_ERROR",
        ConnectionFailureType.NetworkError => "CONN_NETWORK_ERROR",
        ConnectionFailureType.Timeout => "CONN_TIMEOUT",
        ConnectionFailureType.CircuitBreakerOpen => "CONN_CIRCUIT_OPEN",
        _ => "CONN_UNKNOWN"
    };
}

public enum ConnectionFailureType
{
    /// <summary>The tenant cannot be reached</summary>
    TenantUnreachable,

    /// <summary>The service is temporarily unavailable (5xx error)</summary>
    ServiceUnavailable,

    /// <summary>Rate limiting threshold exceeded</summary>
    ThrottlingExceeded,

    /// <summary>Configuration error (invalid tenant ID, client ID, etc.)</summary>
    ConfigurationError,

    /// <summary>SSL/TLS certificate validation failed</summary>
    CertificateError,

    /// <summary>Network connectivity issue (DNS, routing, etc.)</summary>
    NetworkError,

    /// <summary>Operation timed out</summary>
    Timeout,

    /// <summary>Circuit breaker is open due to repeated failures</summary>
    CircuitBreakerOpen
}
