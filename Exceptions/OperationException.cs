namespace Safeguard.Exceptions;

/// <summary>
/// Exception thrown when a specific operation fails.
/// </summary>
public class OperationException : SafeguardException
{
    /// <summary>
    /// The name of the operation that failed
    /// </summary>
    public string OperationName { get; }

    /// <summary>
    /// The target resource (user ID, app ID, etc.) if applicable
    /// </summary>
    public string? TargetResource { get; }

    /// <summary>
    /// The type of operation failure
    /// </summary>
    public OperationFailureType FailureType { get; }

    public OperationException(
        string message,
        string operationName,
        OperationFailureType failureType = OperationFailureType.Unknown,
        string? targetResource = null,
        Exception? innerException = null)
        : base(message, GetErrorCode(operationName, failureType), innerException)
    {
        OperationName = operationName;
        TargetResource = targetResource;
        FailureType = failureType;
    }

    private static string GetErrorCode(string operationName, OperationFailureType failureType)
    {
        var opCode = operationName.ToUpperInvariant().Replace(" ", "_");
        var typeCode = failureType switch
        {
            OperationFailureType.NotFound => "NOT_FOUND",
            OperationFailureType.PermissionDenied => "DENIED",
            OperationFailureType.InvalidInput => "INVALID_INPUT",
            OperationFailureType.Conflict => "CONFLICT",
            OperationFailureType.PartialFailure => "PARTIAL",
            OperationFailureType.Timeout => "TIMEOUT",
            OperationFailureType.Cancelled => "CANCELLED",
            _ => "FAILED"
        };
        return $"OP_{opCode}_{typeCode}";
    }
}

public enum OperationFailureType
{
    /// <summary>Unknown failure type</summary>
    Unknown,

    /// <summary>The target resource was not found</summary>
    NotFound,

    /// <summary>Permission to perform the operation was denied</summary>
    PermissionDenied,

    /// <summary>Invalid input parameters</summary>
    InvalidInput,

    /// <summary>Operation conflicted with existing state</summary>
    Conflict,

    /// <summary>Operation partially completed</summary>
    PartialFailure,

    /// <summary>Operation timed out</summary>
    Timeout,

    /// <summary>Operation was cancelled by user</summary>
    Cancelled
}
