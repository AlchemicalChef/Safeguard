using Microsoft.Graph.Models.ODataErrors;

namespace Safeguard.Exceptions;

/// <summary>
/// Exception thrown when a Microsoft Graph API call fails.
/// </summary>
public class GraphApiException : SafeguardException
{
    /// <summary>
    /// The OData error code from the Graph API response
    /// </summary>
    public string? ODataErrorCode { get; }

    /// <summary>
    /// The HTTP status code of the response
    /// </summary>
    public int? HttpStatusCode { get; }

    /// <summary>
    /// The request ID from Graph API for troubleshooting
    /// </summary>
    public string? RequestId { get; }

    /// <summary>
    /// The operation that was being performed when the error occurred
    /// </summary>
    public string? OperationName { get; }

    public GraphApiException(
        string message,
        string? odataErrorCode = null,
        int? httpStatusCode = null,
        string? requestId = null,
        string? operationName = null,
        Exception? innerException = null)
        : base(message, GetErrorCode(odataErrorCode, httpStatusCode), innerException)
    {
        ODataErrorCode = odataErrorCode;
        HttpStatusCode = httpStatusCode;
        RequestId = requestId;
        OperationName = operationName;
    }

    /// <summary>
    /// Creates a GraphApiException from an ODataError
    /// </summary>
    public static GraphApiException FromODataError(ODataError error, string? operationName = null)
    {
        var errorCode = error.Error?.Code;
        var message = error.Error?.Message ?? "An error occurred while calling Microsoft Graph API";
        var requestId = error.Error?.AdditionalData?.TryGetValue("request-id", out var rid) == true
            ? rid?.ToString()
            : null;

        return new GraphApiException(
            message,
            errorCode,
            error.ResponseStatusCode,
            requestId,
            operationName,
            error);
    }

    /// <summary>
    /// Determines if this error is retryable
    /// </summary>
    public bool IsRetryable => ODataErrorCode is "ServiceNotAvailable" or "TooManyRequests"
        or "InternalServerError" or "BadGateway" or "GatewayTimeout"
        || HttpStatusCode is >= 500 and <= 599 or 408 or 429;

    /// <summary>
    /// Determines if this is a throttling error
    /// </summary>
    public bool IsThrottling => ODataErrorCode == "TooManyRequests" || HttpStatusCode == 429;

    private static string GetErrorCode(string? odataErrorCode, int? httpStatusCode)
    {
        if (!string.IsNullOrEmpty(odataErrorCode))
        {
            return $"GRAPH_{odataErrorCode.ToUpperInvariant()}";
        }

        return httpStatusCode switch
        {
            400 => "GRAPH_BAD_REQUEST",
            401 => "GRAPH_UNAUTHORIZED",
            403 => "GRAPH_FORBIDDEN",
            404 => "GRAPH_NOT_FOUND",
            429 => "GRAPH_THROTTLED",
            >= 500 and <= 599 => "GRAPH_SERVER_ERROR",
            _ => "GRAPH_ERROR"
        };
    }
}
