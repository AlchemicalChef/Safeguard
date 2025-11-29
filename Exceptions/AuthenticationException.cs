namespace Safeguard.Exceptions;

/// <summary>
/// Exception thrown when authentication with Entra ID fails.
/// </summary>
public class AuthenticationException : SafeguardException
{
    public AuthenticationFailureReason Reason { get; }

    public AuthenticationException(string message, AuthenticationFailureReason reason, Exception? innerException = null)
        : base(message, GetErrorCode(reason), innerException)
    {
        Reason = reason;
    }

    private static string GetErrorCode(AuthenticationFailureReason reason) => reason switch
    {
        AuthenticationFailureReason.InvalidCredentials => "AUTH_INVALID_CREDENTIALS",
        AuthenticationFailureReason.MfaRequired => "AUTH_MFA_REQUIRED",
        AuthenticationFailureReason.InteractiveRequired => "AUTH_INTERACTIVE_REQUIRED",
        AuthenticationFailureReason.TokenExpired => "AUTH_TOKEN_EXPIRED",
        AuthenticationFailureReason.TokenRefreshFailed => "AUTH_REFRESH_FAILED",
        AuthenticationFailureReason.RefreshTokenExpired => "AUTH_REFRESH_TOKEN_EXPIRED",
        AuthenticationFailureReason.TenantNotFound => "AUTH_TENANT_NOT_FOUND",
        AuthenticationFailureReason.InsufficientPermissions => "AUTH_INSUFFICIENT_PERMISSIONS",
        AuthenticationFailureReason.NetworkError => "AUTH_NETWORK_ERROR",
        AuthenticationFailureReason.UserCancelled => "AUTH_USER_CANCELLED",
        AuthenticationFailureReason.InvalidClient => "AUTH_INVALID_CLIENT",
        _ => "AUTH_UNKNOWN"
    };
}

public enum AuthenticationFailureReason
{
    /// <summary>Invalid username or password</summary>
    InvalidCredentials,

    /// <summary>Multi-factor authentication is required</summary>
    MfaRequired,

    /// <summary>Interactive authentication is required (cannot use silent auth)</summary>
    InteractiveRequired,

    /// <summary>The access token has expired and cannot be refreshed</summary>
    TokenExpired,

    /// <summary>Token refresh failed</summary>
    TokenRefreshFailed,

    /// <summary>The refresh token has expired or been revoked</summary>
    RefreshTokenExpired,

    /// <summary>The specified tenant was not found</summary>
    TenantNotFound,

    /// <summary>The user/app does not have required permissions</summary>
    InsufficientPermissions,

    /// <summary>Network connectivity issue</summary>
    NetworkError,

    /// <summary>User cancelled the authentication flow</summary>
    UserCancelled,

    /// <summary>Invalid client ID or app configuration</summary>
    InvalidClient
}
