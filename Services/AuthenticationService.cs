using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using Safeguard.Models;
using AuthenticationResult = Safeguard.Models.AuthenticationResult;

namespace Safeguard.Services;

public class AuthenticationService
{
    private readonly AppConfiguration _config;
    private GraphServiceClient? _graphClient;
    private IPublicClientApplication? _publicClientApp;
    private string? _currentUserId;
    private string? _currentUserPrincipalName;
    private IAccount? _cachedAccount;

    private static readonly string[] RequiredScopes = new[]
    {
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All",
        "Application.ReadWrite.All",
        "Domain.ReadWrite.All",
        "User.Read"
    };

    public event Action<DateTimeOffset>? OnTokenRefreshed;

    public AuthenticationService(AppConfiguration config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    public GraphServiceClient GraphClient => _graphClient 
        ?? throw new InvalidOperationException("Not authenticated. Call AuthenticateAsync first.");

    public string? CurrentUserId => _currentUserId;
    public string? CurrentUserPrincipalName => _currentUserPrincipalName;

    public async Task<AuthenticationResult> AuthenticateAsync(
        string username,
        SecureString password,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = "Username is required"
                };
            }

            if (password == null || password.Length == 0)
            {
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = "Password is required"
                };
            }

            var authority = $"https://login.microsoftonline.com/{_config.AzureAd.TenantId}";
            
            _publicClientApp = PublicClientApplicationBuilder
                .Create(_config.AzureAd.ClientId)
                .WithAuthority(authority)
                .WithDefaultRedirectUri()
                .Build();

            if (!password.IsReadOnly())
            {
                password.MakeReadOnly();
            }

            var passwordString = ConvertToUnsecureString(password);

            var msalResult = await _publicClientApp
                .AcquireTokenByUsernamePassword(RequiredScopes, username, passwordString)
                .ExecuteAsync(cancellationToken);

            if (msalResult == null || string.IsNullOrEmpty(msalResult.AccessToken))
            {
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
                (expiresOn) => OnTokenRefreshed?.Invoke(expiresOn));
            
            _graphClient = new GraphServiceClient(tokenCredential, RequiredScopes);

            var me = await _graphClient.Me.GetAsync(cancellationToken: cancellationToken);

            if (me == null)
            {
                throw new InvalidOperationException("Failed to retrieve current user information");
            }

            _currentUserId = me.Id;
            _currentUserPrincipalName = me.UserPrincipalName;

            return new AuthenticationResult
            {
                Success = true,
                UserId = _currentUserId,
                UserPrincipalName = _currentUserPrincipalName,
                DisplayName = me.DisplayName,
                AuthMethod = "Credential Authentication",
                TokenExpiresOn = msalResult.ExpiresOn
            };
        }
        catch (MsalUiRequiredException)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Interactive authentication required. This account may have MFA enabled or requires consent."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_grant")
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Invalid username or password."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "interaction_required")
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "This account requires interactive sign-in due to MFA or Conditional Access policy."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_client")
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Invalid Client ID or the application is not configured for public client flows."
            };
        }
        catch (MsalClientException ex) when (ex.ErrorCode == "unknown_user_type")
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Unknown user type. Ensure the username is a valid organizational account."
            };
        }
        catch (MsalClientException)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Authentication client error. Please verify your Client ID."
            };
        }
        catch (Exception)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Authentication failed. Please verify your credentials and network connection."
            };
        }
    }

    public async Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            if (_publicClientApp != null && _cachedAccount != null)
            {
                var result = await _publicClientApp
                    .AcquireTokenSilent(RequiredScopes, _cachedAccount)
                    .ExecuteAsync(cancellationToken);
                    
                OnTokenRefreshed?.Invoke(result.ExpiresOn);
                return result.AccessToken;
            }
            
            return null;
        }
        catch (MsalUiRequiredException)
        {
            return null;
        }
        catch
        {
            return null;
        }
    }

    public async Task<bool> IsTokenValidAsync(CancellationToken cancellationToken = default)
    {
        var token = await GetAccessTokenAsync(cancellationToken);
        return !string.IsNullOrEmpty(token);
    }

    public void SignOut()
    {
        _graphClient = null;
        _publicClientApp = null;
        _cachedAccount = null;
        _currentUserId = null;
        _currentUserPrincipalName = null;
    }

    private static string ConvertToUnsecureString(SecureString secureString)
    {
        if (secureString == null)
        {
            throw new ArgumentNullException(nameof(secureString));
        }

        var unmanagedString = IntPtr.Zero;
        try
        {
            unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            return Marshal.PtrToStringUni(unmanagedString) ?? string.Empty;
        }
        finally
        {
            if (unmanagedString != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
    }
}

internal class RefreshingTokenCredential : TokenCredential
{
    private readonly IPublicClientApplication _publicClientApp;
    private readonly IAccount _account;
    private readonly string[] _scopes;
    private readonly Action<DateTimeOffset>? _onRefreshed;
    
    private string? _cachedToken;
    private DateTimeOffset _tokenExpiry = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    
    private static readonly TimeSpan RefreshBuffer = TimeSpan.FromMinutes(5);

    public RefreshingTokenCredential(
        IPublicClientApplication publicClientApp, 
        IAccount account, 
        string[] scopes,
        Action<DateTimeOffset>? onRefreshed = null)
    {
        _publicClientApp = publicClientApp;
        _account = account;
        _scopes = scopes;
        _onRefreshed = onRefreshed;
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return GetTokenAsync(requestContext, cancellationToken).AsTask().GetAwaiter().GetResult();
    }

    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_cachedToken) && DateTimeOffset.UtcNow.Add(RefreshBuffer) < _tokenExpiry)
        {
            return new AccessToken(_cachedToken, _tokenExpiry);
        }

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            if (!string.IsNullOrEmpty(_cachedToken) && DateTimeOffset.UtcNow.Add(RefreshBuffer) < _tokenExpiry)
            {
                return new AccessToken(_cachedToken, _tokenExpiry);
            }

            var result = await _publicClientApp
                .AcquireTokenSilent(_scopes, _account)
                .ExecuteAsync(cancellationToken);

            _cachedToken = result.AccessToken;
            _tokenExpiry = result.ExpiresOn;
            
            _onRefreshed?.Invoke(_tokenExpiry);

            return new AccessToken(_cachedToken, _tokenExpiry);
        }
        catch (MsalUiRequiredException)
        {
            throw new InvalidOperationException(
                "Session expired. Please sign out and sign in again to continue.");
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}
