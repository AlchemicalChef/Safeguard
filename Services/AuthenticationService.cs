using System.Security;
using Azure.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensions.Msal;
using Safeguard.Exceptions;
using Safeguard.Infrastructure;
using Safeguard.Models;
using AuthenticationResult = Safeguard.Models.AuthenticationResult;

namespace Safeguard.Services;

public class AuthenticationService
{
    private readonly AppConfiguration _config;
    private readonly ILogger<AuthenticationService> _logger;
    private GraphServiceClient? _graphClient;
    private IPublicClientApplication? _publicClientApp;
    private string? _currentUserId;
    private string? _currentUserPrincipalName;
    private IAccount? _cachedAccount;
    private MsalCacheHelper? _cacheHelper;

    private static readonly string[] RequiredScopes =
    [
        // OIDC standard scopes
        "offline_access",  // Explicitly request refresh token
        "openid",          // ID token with user claims
        "profile",         // Basic profile information
        // Microsoft Graph permissions
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All",
        "Application.ReadWrite.All",
        "Domain.ReadWrite.All",
        "User.Read"
    ];

    public event Action<DateTimeOffset>? OnTokenRefreshed;

    public AuthenticationService(AppConfiguration config, ILogger<AuthenticationService>? logger = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? LoggingConfiguration.GetLogger<AuthenticationService>();
    }

    public GraphServiceClient GraphClient => _graphClient
        ?? throw new InvalidOperationException("Not authenticated. Call AuthenticateInteractiveAsync first.");

    public string? CurrentUserId => _currentUserId;
    public string? CurrentUserPrincipalName => _currentUserPrincipalName;

    /// <summary>
    /// Authenticates using OAuth2 Authorization Code Flow with PKCE.
    /// Opens the system browser for user authentication.
    /// </summary>
    public async Task<AuthenticationResult> AuthenticateInteractiveAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Starting interactive authentication for tenant {TenantId}",
                _config.AzureAd.TenantId);

            var authority = $"https://login.microsoftonline.com/{_config.AzureAd.TenantId}";

            _publicClientApp = PublicClientApplicationBuilder
                .Create(_config.AzureAd.ClientId)
                .WithAuthority(authority)
                .WithRedirectUri("http://localhost")
                .WithClientCapabilities(new[] { "cp1" })  // Enable Continuous Access Evaluation (CAE)
                .Build();

            // Initialize persistent token cache
            await InitializeTokenCacheAsync();

            Microsoft.Identity.Client.AuthenticationResult msalResult;

            // Try silent auth first (returning users)
            var accounts = await _publicClientApp.GetAccountsAsync();
            var firstAccount = accounts.FirstOrDefault();

            if (firstAccount != null)
            {
                _logger.LogDebug("Found cached account, attempting silent authentication");
                try
                {
                    msalResult = await _publicClientApp
                        .AcquireTokenSilent(RequiredScopes, firstAccount)
                        .ExecuteAsync(cancellationToken);

                    _logger.LogInformation("Silent authentication successful");
                }
                catch (MsalUiRequiredException)
                {
                    _logger.LogDebug("Silent auth failed, falling back to interactive");
                    msalResult = await AcquireTokenInteractiveAsync(cancellationToken);
                }
            }
            else
            {
                _logger.LogDebug("No cached account, starting interactive authentication");
                msalResult = await AcquireTokenInteractiveAsync(cancellationToken);
            }

            if (msalResult == null || string.IsNullOrEmpty(msalResult.AccessToken))
            {
                _logger.LogError("Failed to acquire access token - result was null or empty");
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = "Failed to acquire access token"
                };
            }

            _cachedAccount = msalResult.Account;

            var tokenCredential = new RefreshingTokenCredential(
                _publicClientApp,
                _cachedAccount,
                RequiredScopes,
                expiresOn =>
                {
                    _logger.LogDebug("Token refreshed, expires at {ExpiresOn}", expiresOn);
                    OnTokenRefreshed?.Invoke(expiresOn);
                },
                _logger);

            _graphClient = new GraphServiceClient(tokenCredential, RequiredScopes);

            var me = await _graphClient.Me.GetAsync(cancellationToken: cancellationToken);

            if (me == null)
            {
                throw new InvalidOperationException("Failed to retrieve current user information");
            }

            _currentUserId = me.Id;
            _currentUserPrincipalName = me.UserPrincipalName;

            _logger.LogInformation("Authentication successful for user {UserPrincipalName}",
                _currentUserPrincipalName);

            return new AuthenticationResult
            {
                Success = true,
                UserId = _currentUserId,
                UserPrincipalName = _currentUserPrincipalName,
                DisplayName = me.DisplayName,
                AuthMethod = "Interactive Browser Authentication",
                TokenExpiresOn = msalResult.ExpiresOn
            };
        }
        catch (MsalClientException ex) when (ex.ErrorCode == "authentication_canceled")
        {
            _logger.LogWarning("Authentication was cancelled by user");
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Authentication was cancelled."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "access_denied")
        {
            _logger.LogError(ex, "Access denied - may need admin consent");
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Access denied. You may need admin consent for the required permissions."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_client")
        {
            _logger.LogError(ex, "Invalid client configuration");
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Invalid Client ID or the application is not properly configured."
            };
        }
        catch (MsalClientException ex) when (ex.ErrorCode == "no_network")
        {
            _logger.LogError(ex, "No network connection");
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "No network connection available. Please check your internet connection."
            };
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Authentication operation was cancelled");
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Authentication was cancelled."
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed with unexpected error");
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Authentication failed: {ex.Message}"
            };
        }
    }

    private async Task<Microsoft.Identity.Client.AuthenticationResult> AcquireTokenInteractiveAsync(
        CancellationToken cancellationToken)
    {
        return await _publicClientApp!
            .AcquireTokenInteractive(RequiredScopes)
            .WithUseEmbeddedWebView(false) // Use system browser
            .ExecuteAsync(cancellationToken);
    }

    /// <summary>
    /// Initializes persistent token cache for cross-session authentication.
    /// </summary>
    private async Task InitializeTokenCacheAsync()
    {
        try
        {
            var cacheFileName = "safeguard_msal_cache.dat";
            var cacheDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Safeguard");

            Directory.CreateDirectory(cacheDir);

            var storageProperties = new StorageCreationPropertiesBuilder(cacheFileName, cacheDir)
                .WithMacKeyChain("SafeguardTokenCache", "SafeguardApp")
                .WithLinuxKeyring(
                    schemaName: "com.safeguard.tokencache",
                    collection: "default",
                    secretLabel: "Safeguard MSAL Token Cache",
                    attribute1: new KeyValuePair<string, string>("Version", "1"),
                    attribute2: new KeyValuePair<string, string>("Product", "Safeguard"))
                .Build();

            _cacheHelper = await MsalCacheHelper.CreateAsync(storageProperties);
            _cacheHelper.RegisterCache(_publicClientApp!.UserTokenCache);

            _logger.LogDebug("Token cache initialized at {CacheDir}", cacheDir);
        }
        catch (Exception ex)
        {
            // Token cache is optional - continue without it
            _logger.LogWarning(ex, "Failed to initialize token cache, continuing without persistence");
        }
    }

    /// <summary>
    /// Attempts silent authentication using cached credentials.
    /// Returns true if successful, false if interactive auth is required.
    /// </summary>
    public async Task<bool> TrySilentAuthAsync(CancellationToken cancellationToken = default)
    {
        if (_publicClientApp == null)
            return false;

        try
        {
            var accounts = await _publicClientApp.GetAccountsAsync();
            var firstAccount = accounts.FirstOrDefault();

            if (firstAccount == null)
                return false;

            var result = await _publicClientApp
                .AcquireTokenSilent(RequiredScopes, firstAccount)
                .ExecuteAsync(cancellationToken);

            if (result == null || string.IsNullOrEmpty(result.AccessToken))
                return false;

            _cachedAccount = result.Account;

            var tokenCredential = new RefreshingTokenCredential(
                _publicClientApp,
                _cachedAccount,
                RequiredScopes,
                expiresOn => OnTokenRefreshed?.Invoke(expiresOn),
                _logger);

            _graphClient = new GraphServiceClient(tokenCredential, RequiredScopes);

            var me = await _graphClient.Me.GetAsync(cancellationToken: cancellationToken);
            if (me == null)
                return false;

            _currentUserId = me.Id;
            _currentUserPrincipalName = me.UserPrincipalName;

            _logger.LogInformation("Silent authentication successful for {UserPrincipalName}",
                _currentUserPrincipalName);
            return true;
        }
        catch (MsalUiRequiredException)
        {
            _logger.LogDebug("Silent auth requires UI interaction");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Silent authentication failed");
            return false;
        }
    }

    /// <summary>
    /// Gets the current access token, refreshing if necessary.
    /// Throws AuthenticationException if token cannot be obtained.
    /// </summary>
    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_publicClientApp == null || _cachedAccount == null)
        {
            throw new AuthenticationException(
                "Not authenticated. Call AuthenticateInteractiveAsync first.",
                AuthenticationFailureReason.TokenExpired);
        }

        try
        {
            var result = await _publicClientApp
                .AcquireTokenSilent(RequiredScopes, _cachedAccount)
                .ExecuteAsync(cancellationToken);

            _logger.LogDebug("Access token acquired, expires at {ExpiresOn}", result.ExpiresOn);
            OnTokenRefreshed?.Invoke(result.ExpiresOn);
            return result.AccessToken;
        }
        catch (MsalUiRequiredException ex)
        {
            _logger.LogWarning(ex, "Token refresh requires user interaction");
            throw new AuthenticationException(
                "Session expired. Please sign in again.",
                AuthenticationFailureReason.InteractiveRequired,
                ex);
        }
        catch (MsalClientException ex) when (ex.ErrorCode == "no_network")
        {
            _logger.LogError(ex, "Network error during token refresh");
            throw new AuthenticationException(
                "No network connection available.",
                AuthenticationFailureReason.NetworkError,
                ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh access token");
            throw new AuthenticationException(
                "Failed to refresh access token.",
                AuthenticationFailureReason.TokenRefreshFailed,
                ex);
        }
    }

    public async Task<bool> IsTokenValidAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await GetAccessTokenAsync(cancellationToken);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task SignOutAsync()
    {
        _logger.LogInformation("Signing out user {UserPrincipalName}", _currentUserPrincipalName);

        if (_publicClientApp != null)
        {
            var accounts = await _publicClientApp.GetAccountsAsync();
            foreach (var account in accounts)
            {
                await _publicClientApp.RemoveAsync(account);
            }
        }

        _graphClient = null;
        _publicClientApp = null;
        _cachedAccount = null;
        _currentUserId = null;
        _currentUserPrincipalName = null;
    }

    [Obsolete("Use SignOutAsync instead")]
    public void SignOut()
    {
        SignOutAsync().GetAwaiter().GetResult();
    }
}

internal class RefreshingTokenCredential : TokenCredential
{
    private readonly IPublicClientApplication _publicClientApp;
    private readonly IAccount _account;
    private readonly string[] _scopes;
    private readonly Action<DateTimeOffset>? _onRefreshed;
    private readonly ILogger? _logger;

    // Use volatile to ensure thread-safe reads of cached values
    private volatile string? _cachedToken;
    private volatile DateTimeOffset _tokenExpiry = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromMinutes(5);

    public RefreshingTokenCredential(
        IPublicClientApplication publicClientApp,
        IAccount account,
        string[] scopes,
        Action<DateTimeOffset>? onRefreshed = null,
        ILogger? logger = null)
    {
        _publicClientApp = publicClientApp;
        _account = account;
        _scopes = scopes;
        _onRefreshed = onRefreshed;
        _logger = logger;
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return GetTokenAsync(requestContext, cancellationToken).AsTask().GetAwaiter().GetResult();
    }

    public override async ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        // Quick check without lock
        var cachedToken = _cachedToken;
        var tokenExpiry = _tokenExpiry;

        if (!string.IsNullOrEmpty(cachedToken) && DateTimeOffset.UtcNow.Add(RefreshBuffer) < tokenExpiry)
        {
            return new AccessToken(cachedToken, tokenExpiry);
        }

        // Acquire lock for refresh
        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            // Double-check after acquiring lock
            cachedToken = _cachedToken;
            tokenExpiry = _tokenExpiry;

            if (!string.IsNullOrEmpty(cachedToken) && DateTimeOffset.UtcNow.Add(RefreshBuffer) < tokenExpiry)
            {
                return new AccessToken(cachedToken, tokenExpiry);
            }

            _logger?.LogDebug("Refreshing access token");

            var result = await _publicClientApp
                .AcquireTokenSilent(_scopes, _account)
                .ExecuteAsync(cancellationToken);

            // Update cached values atomically
            _cachedToken = result.AccessToken;
            _tokenExpiry = result.ExpiresOn;

            _logger?.LogDebug("Token refreshed, new expiry: {ExpiresOn}", result.ExpiresOn);
            _onRefreshed?.Invoke(result.ExpiresOn);

            return new AccessToken(result.AccessToken, result.ExpiresOn);
        }
        catch (MsalUiRequiredException ex)
        {
            _logger?.LogWarning(ex, "Token refresh requires user interaction");
            throw new AuthenticationException(
                "Session expired. Please sign out and sign in again to continue.",
                AuthenticationFailureReason.InteractiveRequired,
                ex);
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_grant")
        {
            _logger?.LogWarning(ex, "Refresh token expired or revoked");
            throw new AuthenticationException(
                "Your session has expired. Please sign in again.",
                AuthenticationFailureReason.RefreshTokenExpired,
                ex);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to refresh token");
            throw new AuthenticationException(
                "Failed to refresh access token.",
                AuthenticationFailureReason.TokenRefreshFailed,
                ex);
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}
