using System;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using EntraTokenRevocationGUI.Models;

namespace EntraTokenRevocationGUI.Services;

public enum AuthenticationMethod
{
    DeviceCode,
    UsernamePassword
}

public class AuthenticationService
{
    private readonly AppConfiguration _config;
    private readonly Action<string, string>? _deviceCodeCallback;
    private GraphServiceClient? _graphClient;
    private DeviceCodeCredential? _deviceCodeCredential;
    private IPublicClientApplication? _publicClientApp;
    private string? _currentUserId;
    private string? _currentUserPrincipalName;
    private AuthenticationMethod _authMethod;

    private static readonly string[] RequiredScopes = new[]
    {
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All",
        "Application.ReadWrite.All",
        "Domain.ReadWrite.All",
        "User.Read"
    };

    public AuthenticationService(AppConfiguration config, Action<string, string>? deviceCodeCallback = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _deviceCodeCallback = deviceCodeCallback;
    }

    public GraphServiceClient GraphClient => _graphClient 
        ?? throw new InvalidOperationException("Not authenticated. Call AuthenticateAsync first.");

    public string? CurrentUserId => _currentUserId;
    public string? CurrentUserPrincipalName => _currentUserPrincipalName;
    public AuthenticationMethod CurrentAuthMethod => _authMethod;

    /// <summary>
    /// Authenticate using Device Code Flow (recommended)
    /// </summary>
    public async Task<AuthenticationResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        _authMethod = AuthenticationMethod.DeviceCode;
        
        try
        {
            var deviceCodeCredentialOptions = new DeviceCodeCredentialOptions
            {
                AuthorityHost = AzureAuthorityHosts.AzurePublicCloud,
                ClientId = _config.AzureAd.ClientId,
                TenantId = _config.AzureAd.TenantId,
                DeviceCodeCallback = (deviceCodeInfo, cancellation) =>
                {
                    var userCode = deviceCodeInfo.UserCode;
                    _deviceCodeCallback?.Invoke(deviceCodeInfo.Message, userCode);
                    return Task.CompletedTask;
                }
            };

            _deviceCodeCredential = new DeviceCodeCredential(deviceCodeCredentialOptions);
            _graphClient = new GraphServiceClient(_deviceCodeCredential, RequiredScopes);

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
                AuthMethod = "Device Code Flow"
            };
        }
        catch (AuthenticationFailedException ex)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Authentication failed: {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Authenticate using Username and Password (ROPC flow)
    /// WARNING: This method is less secure and does not work with MFA-enabled accounts.
    /// Only use in emergency incident response scenarios where MFA may be compromised.
    /// </summary>
    public async Task<AuthenticationResult> AuthenticateWithCredentialsAsync(
        string username, 
        string password,
        CancellationToken cancellationToken = default)
    {
        _authMethod = AuthenticationMethod.UsernamePassword;
        
        try
        {
            // Validate inputs
            if (string.IsNullOrWhiteSpace(username))
            {
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = "Username is required"
                };
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = "Password is required"
                };
            }

            // Build the public client application for ROPC
            var authority = $"https://login.microsoftonline.com/{_config.AzureAd.TenantId}";
            
            _publicClientApp = PublicClientApplicationBuilder
                .Create(_config.AzureAd.ClientId)
                .WithAuthority(authority)
                .WithDefaultRedirectUri()
                .Build();

            // Convert password to SecureString for security
            var securePassword = new SecureString();
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }
            securePassword.MakeReadOnly();

            // Attempt to acquire token using username/password
            var msalResult = await _publicClientApp
                .AcquireTokenByUsernamePassword(RequiredScopes, username, securePassword)
                .ExecuteAsync(cancellationToken);

            if (msalResult == null || string.IsNullOrEmpty(msalResult.AccessToken))
            {
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorMessage = "Failed to acquire access token"
                };
            }

            // Create a credential provider that uses the acquired token
            var tokenCredential = new StaticTokenCredential(msalResult.AccessToken, msalResult.ExpiresOn);
            _graphClient = new GraphServiceClient(tokenCredential, RequiredScopes);

            // Get current user info
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
                AuthMethod = "Username/Password (ROPC)"
            };
        }
        catch (MsalUiRequiredException ex)
        {
            // This happens when MFA is required or consent is needed
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Interactive authentication required (MFA may be enabled): {ex.Message}\n\nPlease use Device Code Flow instead."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "invalid_grant")
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "Invalid username or password. Please verify your credentials."
            };
        }
        catch (MsalServiceException ex) when (ex.ErrorCode == "interaction_required")
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = "This account requires interactive sign-in (MFA or Conditional Access policy). Please use Device Code Flow."
            };
        }
        catch (MsalClientException ex)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Client error: {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorMessage = $"Authentication failed: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Get an access token for direct API calls (e.g., beta endpoints)
    /// </summary>
    public async Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            if (_authMethod == AuthenticationMethod.DeviceCode && _deviceCodeCredential != null)
            {
                var tokenRequestContext = new Azure.Core.TokenRequestContext(
                    new[] { "https://graph.microsoft.com/.default" });
                var accessToken = await _deviceCodeCredential.GetTokenAsync(tokenRequestContext, cancellationToken);
                return accessToken.Token;
            }
            else if (_authMethod == AuthenticationMethod.UsernamePassword && _publicClientApp != null)
            {
                var accounts = await _publicClientApp.GetAccountsAsync();
                var account = accounts.FirstOrDefault();
                
                if (account != null)
                {
                    var result = await _publicClientApp
                        .AcquireTokenSilent(RequiredScopes, account)
                        .ExecuteAsync(cancellationToken);
                    return result.AccessToken;
                }
            }
            
            return null;
        }
        catch
        {
            return null;
        }
    }

    public void SignOut()
    {
        _graphClient = null;
        _deviceCodeCredential = null;
        _publicClientApp = null;
        _currentUserId = null;
        _currentUserPrincipalName = null;
    }
}

/// <summary>
/// Simple token credential that uses a pre-acquired access token
/// </summary>
internal class StaticTokenCredential : Azure.Core.TokenCredential
{
    private readonly string _accessToken;
    private readonly DateTimeOffset _expiresOn;

    public StaticTokenCredential(string accessToken, DateTimeOffset expiresOn)
    {
        _accessToken = accessToken;
        _expiresOn = expiresOn;
    }

    public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new Azure.Core.AccessToken(_accessToken, _expiresOn);
    }

    public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new ValueTask<Azure.Core.AccessToken>(new Azure.Core.AccessToken(_accessToken, _expiresOn));
    }
}
