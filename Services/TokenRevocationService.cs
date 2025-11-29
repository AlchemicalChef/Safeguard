using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Safeguard.Exceptions;
using Safeguard.Infrastructure;
using Safeguard.Models;

namespace Safeguard.Services;

public class TokenRevocationService
{
    private readonly AuthenticationService _authService;
    private readonly ILogger<TokenRevocationService> _logger;
    private readonly ResilientGraphOperations _graphOps;

    public event Action<int, string>? OnThrottled;
    public event Action<int, TimeSpan, string>? OnRetry;
    public event Action<string>? OnCircuitOpened;
    public event Action<string>? OnCircuitClosed;

    public TokenRevocationService(
        AuthenticationService authService,
        ResilienceConfiguration? resilienceConfig = null,
        ILogger<TokenRevocationService>? logger = null)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        _logger = logger ?? LoggingConfiguration.GetLogger<TokenRevocationService>();

        var config = resilienceConfig ?? new ResilienceConfiguration();
        _graphOps = new ResilientGraphOperations(config, _logger);

        // Wire up resilience events
        _graphOps.OnThrottled += (retryAfter, op) =>
        {
            _logger.LogWarning("Throttled during {Operation}, waiting {RetryAfter}s", op, retryAfter);
            OnThrottled?.Invoke(retryAfter, op);
        };
        _graphOps.OnRetry += (attempt, delay, op) =>
        {
            _logger.LogDebug("Retry {Attempt} for {Operation}, delay {Delay}ms", attempt, op, delay);
            OnRetry?.Invoke(attempt, delay, op);
        };
        _graphOps.OnCircuitOpened += op =>
        {
            _logger.LogWarning("Circuit breaker opened for {Operation}", op);
            OnCircuitOpened?.Invoke(op);
        };
        _graphOps.OnCircuitClosed += op =>
        {
            _logger.LogInformation("Circuit breaker closed for {Operation}", op);
            OnCircuitClosed?.Invoke(op);
        };
    }

    private GraphServiceClient GraphClient => _authService.GraphClient;

    public async Task<RevocationResult> RevokeUserTokensAsync(string userIdentifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userIdentifier))
        {
            return new RevocationResult
            {
                Success = false,
                ErrorMessage = "User identifier cannot be empty"
            };
        }

        try
        {
            var user = await GetUserAsync(userIdentifier, cancellationToken);

            if (user == null)
            {
                _logger.LogWarning("User not found: {UserIdentifier}", userIdentifier);
                return new RevocationResult
                {
                    Success = false,
                    ErrorMessage = "User not found"
                };
            }

            var revocationSuccess = await ExecuteRevocationAsync(user.Id!, cancellationToken);

            if (revocationSuccess)
            {
                return new RevocationResult
                {
                    Success = true,
                    UserId = user.Id,
                    UserPrincipalName = user.UserPrincipalName,
                    DisplayName = user.DisplayName,
                    RevocationTime = DateTime.UtcNow
                };
            }
            else
            {
                return new RevocationResult
                {
                    Success = false,
                    UserId = user.Id,
                    UserPrincipalName = user.UserPrincipalName,
                    ErrorMessage = "Revocation API call failed after retries"
                };
            }
        }
        catch (Microsoft.Graph.Models.ODataErrors.ODataError odataEx)
        {
            return new RevocationResult
            {
                Success = false,
                ErrorMessage = $"Graph API error: {odataEx.Error?.Code} - {odataEx.Error?.Message}"
            };
        }
        catch (Exception ex)
        {
            return new RevocationResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            };
        }
    }

    public async Task<MassRevocationResult> MassRevokeTokensAsync(
        string excludeUserId,
        int batchSize = 50,
        int delayBetweenBatchesMs = 1000,
        Action<int, int, string>? progressCallback = null,
        Action<string>? errorCallback = null,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var results = new List<RevocationResult>();
        var processedCount = 0;
        var allUsers = new List<User>();

        try
        {
            var usersResponse = await GraphClient.Users
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Select = new[]
                    {
                        "id",
                        "userPrincipalName",
                        "displayName",
                        "accountEnabled"
                    };
                    requestConfiguration.QueryParameters.Top = 999;
                    requestConfiguration.QueryParameters.Filter = "userType eq 'Member' and accountEnabled eq true";
                }, cancellationToken);

            if (usersResponse?.Value != null)
            {
                var pageIterator = PageIterator<User, UserCollectionResponse>
                    .CreatePageIterator(GraphClient, usersResponse, (user) =>
                    {
                        allUsers.Add(user);
                        return true;
                    });

                await pageIterator.IterateAsync(cancellationToken);
            }

            var usersToRevoke = allUsers
                .Where(u => u.Id != excludeUserId)
                .ToList();

            var totalUsers = usersToRevoke.Count;

            for (var i = 0; i < usersToRevoke.Count; i += batchSize)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var batch = usersToRevoke.Skip(i).Take(batchSize).ToList();

                var batchTasks = batch.Select(async user =>
                {
                    progressCallback?.Invoke(Interlocked.Increment(ref processedCount), totalUsers, user.UserPrincipalName ?? "Unknown");

                    var result = await RevokeUserTokensAsync(user.Id!, cancellationToken);
                    result.UserId ??= user.Id;
                    result.UserPrincipalName ??= user.UserPrincipalName;
                    result.DisplayName ??= user.DisplayName;

                    return result;
                });

                var batchResults = await Task.WhenAll(batchTasks);
                results.AddRange(batchResults);

                if (i + batchSize < usersToRevoke.Count)
                {
                    await Task.Delay(delayBetweenBatchesMs, cancellationToken);
                }
            }
        }
        catch (Exception ex)
        {
            var message = $"Failed to enumerate users for mass revocation: {ex.Message}";
            errorCallback?.Invoke(message);

            results.Add(new RevocationResult
            {
                Success = false,
                ErrorMessage = message
            });
        }

        stopwatch.Stop();

        return new MassRevocationResult
        {
            TotalProcessed = results.Count,
            SuccessCount = results.Count(r => r.Success),
            FailureCount = results.Count(r => !r.Success),
            Results = results,
            Duration = stopwatch.Elapsed,
            FailedUsers = results.Where(r => !r.Success).ToList()
        };
    }

    public async Task<User?> GetUserInfoAsync(string userIdentifier, CancellationToken cancellationToken = default)
    {
        return await GetUserAsync(userIdentifier, cancellationToken);
    }

    public async Task<List<User>> GetUsersAsync(int top = 100, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Getting users list, top={Top}", top);

        var response = await _graphOps.ExecuteAsync(
            async () => await GraphClient.Users
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Select = new[]
                    {
                        "id",
                        "userPrincipalName",
                        "displayName",
                        "department",
                        "accountEnabled"
                    };
                    requestConfiguration.QueryParameters.Top = top;
                    requestConfiguration.QueryParameters.Filter = "userType eq 'Member'";
                    requestConfiguration.QueryParameters.Orderby = new[] { "displayName" };
                }, cancellationToken),
            "GetUsers",
            cancellationToken);

        var users = response?.Value?.ToList() ?? new List<User>();
        _logger.LogDebug("Retrieved {Count} users", users.Count);
        return users;
    }

    private async Task<bool> ExecuteRevocationAsync(string userId, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Executing token revocation for user {UserId}", userId);

        var result = await _graphOps.ExecuteAsync(
            async () => await GraphClient.Users[userId]
                .RevokeSignInSessions
                .PostAsRevokeSignInSessionsPostResponseAsync(cancellationToken: cancellationToken),
            "RevokeSignInSessions",
            cancellationToken);

        if (result?.Value == true)
        {
            _logger.LogInformation("Successfully revoked tokens for user {UserId}", userId);
            return true;
        }

        _logger.LogWarning("Token revocation returned false for user {UserId}", userId);
        return false;
    }

    private async Task<User?> GetUserAsync(string userIdentifier, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Looking up user {UserIdentifier}", userIdentifier);

        try
        {
            var user = await _graphOps.ExecuteAsync(
                async () => await GraphClient.Users[userIdentifier]
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id",
                            "userPrincipalName",
                            "displayName",
                            "mail",
                            "jobTitle",
                            "department",
                            "accountEnabled",
                            "signInSessionsValidFromDateTime"
                        };
                    }, cancellationToken),
                "GetUser",
                cancellationToken);

            return user;
        }
        catch (GraphApiException ex) when (ex.ODataErrorCode == "Request_ResourceNotFound")
        {
            _logger.LogDebug("User not found: {UserIdentifier}", userIdentifier);
            return null;
        }
    }

    // Legacy methods for backward compatibility
    [Obsolete("Use ExecuteRevocationAsync instead")]
    private Task<bool> ExecuteRevocationWithRetryAsync(string userId, CancellationToken cancellationToken)
        => ExecuteRevocationAsync(userId, cancellationToken);

    [Obsolete("Use GetUserAsync instead")]
    private Task<User?> GetUserWithRetryAsync(string userIdentifier, CancellationToken cancellationToken)
        => GetUserAsync(userIdentifier, cancellationToken);

    #region MFA Reset Operations

    public async Task<List<AuthMethodInfo>> GetUserAuthMethodsAsync(string userId, CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Getting authentication methods for user {UserId}", userId);
        var methods = new List<AuthMethodInfo>();

        // Get Phone authentication methods
        await TryGetAuthMethodAsync(async () =>
        {
            var phoneMethods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.PhoneMethods.GetAsync(cancellationToken: cancellationToken),
                "GetPhoneMethods", cancellationToken);
            if (phoneMethods?.Value != null)
            {
                methods.AddRange(phoneMethods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "Phone",
                    DisplayName = $"{m.PhoneType}: {m.PhoneNumber}"
                }));
            }
        }, "Phone", userId);

        // Get Microsoft Authenticator methods
        await TryGetAuthMethodAsync(async () =>
        {
            var authAppMethods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.MicrosoftAuthenticatorMethods.GetAsync(cancellationToken: cancellationToken),
                "GetAuthenticatorMethods", cancellationToken);
            if (authAppMethods?.Value != null)
            {
                methods.AddRange(authAppMethods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "MicrosoftAuthenticator",
                    DisplayName = $"Authenticator: {m.DisplayName}"
                }));
            }
        }, "MicrosoftAuthenticator", userId);

        // Get FIDO2 security keys
        await TryGetAuthMethodAsync(async () =>
        {
            var fido2Methods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.Fido2Methods.GetAsync(cancellationToken: cancellationToken),
                "GetFido2Methods", cancellationToken);
            if (fido2Methods?.Value != null)
            {
                methods.AddRange(fido2Methods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "Fido2",
                    DisplayName = $"FIDO2: {m.DisplayName}"
                }));
            }
        }, "Fido2", userId);

        // Get Software OATH tokens
        await TryGetAuthMethodAsync(async () =>
        {
            var softwareOathMethods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.SoftwareOathMethods.GetAsync(cancellationToken: cancellationToken),
                "GetSoftwareOathMethods", cancellationToken);
            if (softwareOathMethods?.Value != null)
            {
                methods.AddRange(softwareOathMethods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "SoftwareOath",
                    DisplayName = "Software OATH Token"
                }));
            }
        }, "SoftwareOath", userId);

        // Get Windows Hello for Business methods
        await TryGetAuthMethodAsync(async () =>
        {
            var whfbMethods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.WindowsHelloForBusinessMethods.GetAsync(cancellationToken: cancellationToken),
                "GetWindowsHelloMethods", cancellationToken);
            if (whfbMethods?.Value != null)
            {
                methods.AddRange(whfbMethods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "WindowsHelloForBusiness",
                    DisplayName = $"Windows Hello: {m.DisplayName}"
                }));
            }
        }, "WindowsHelloForBusiness", userId);

        // Get Email authentication methods
        await TryGetAuthMethodAsync(async () =>
        {
            var emailMethods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.EmailMethods.GetAsync(cancellationToken: cancellationToken),
                "GetEmailMethods", cancellationToken);
            if (emailMethods?.Value != null)
            {
                methods.AddRange(emailMethods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "Email",
                    DisplayName = $"Email: {m.EmailAddress}"
                }));
            }
        }, "Email", userId);

        // Get Temporary Access Pass methods
        await TryGetAuthMethodAsync(async () =>
        {
            var tapMethods = await _graphOps.ExecuteAsync(
                () => GraphClient.Users[userId].Authentication.TemporaryAccessPassMethods.GetAsync(cancellationToken: cancellationToken),
                "GetTapMethods", cancellationToken);
            if (tapMethods?.Value != null)
            {
                methods.AddRange(tapMethods.Value.Select(m => new AuthMethodInfo
                {
                    Id = m.Id,
                    MethodType = "TemporaryAccessPass",
                    DisplayName = "Temporary Access Pass"
                }));
            }
        }, "TemporaryAccessPass", userId);

        _logger.LogDebug("Found {Count} authentication methods for user {UserId}", methods.Count, userId);
        return methods;
    }

    private async Task TryGetAuthMethodAsync(Func<Task> getMethod, string methodType, string userId)
    {
        try
        {
            await getMethod();
        }
        catch (GraphApiException ex) when (ex.ODataErrorCode == "Request_ResourceNotFound" || ex.ODataErrorCode == "Authentication_RequestsThrottled")
        {
            _logger.LogDebug("Could not retrieve {MethodType} methods for user {UserId}: {Error}",
                methodType, userId, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to retrieve {MethodType} methods for user {UserId}",
                methodType, userId);
        }
    }

    public async Task<MfaResetResult> ResetUserMfaAsync(string userIdentifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userIdentifier))
        {
            return new MfaResetResult
            {
                Success = false,
                ErrorMessage = "User identifier cannot be empty"
            };
        }

        _logger.LogInformation("Resetting MFA for user {UserIdentifier}", userIdentifier);

        try
        {
            var user = await GetUserAsync(userIdentifier, cancellationToken);

            if (user == null)
            {
                return new MfaResetResult
                {
                    Success = false,
                    ErrorMessage = "User not found"
                };
            }

            var methods = await GetUserAuthMethodsAsync(user.Id!, cancellationToken);
            var removedMethods = new List<string>();
            var errors = new List<string>();

            // Delete each authentication method (except password which cannot be deleted)
            foreach (var method in methods)
            {
                try
                {
                    var deleted = await DeleteAuthMethodAsync(user.Id!, method, cancellationToken);
                    if (deleted)
                    {
                        removedMethods.Add(method.MethodType!);
                    }
                }
                catch (Exception ex)
                {
                    errors.Add($"{method.MethodType}: {ex.Message}");
                }
            }

            return new MfaResetResult
            {
                Success = removedMethods.Count > 0 || methods.Count == 0,
                UserId = user.Id,
                UserPrincipalName = user.UserPrincipalName,
                DisplayName = user.DisplayName,
                ResetTime = DateTime.UtcNow,
                MethodsRemoved = removedMethods.Count,
                RemovedMethodTypes = removedMethods,
                ErrorMessage = errors.Count > 0 ? string.Join("; ", errors) : null
            };
        }
        catch (Microsoft.Graph.Models.ODataErrors.ODataError odataEx)
        {
            return new MfaResetResult
            {
                Success = false,
                ErrorMessage = $"Graph API error: {odataEx.Error?.Code} - {odataEx.Error?.Message}"
            };
        }
        catch (Exception ex)
        {
            return new MfaResetResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            };
        }
    }

    private async Task<bool> DeleteAuthMethodAsync(string userId, AuthMethodInfo method, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(method.Id) || string.IsNullOrEmpty(method.MethodType))
            return false;

        try
        {
            switch (method.MethodType)
            {
                case "Phone":
                    await GraphClient.Users[userId].Authentication.PhoneMethods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                case "MicrosoftAuthenticator":
                    await GraphClient.Users[userId].Authentication.MicrosoftAuthenticatorMethods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                case "Fido2":
                    await GraphClient.Users[userId].Authentication.Fido2Methods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                case "SoftwareOath":
                    await GraphClient.Users[userId].Authentication.SoftwareOathMethods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                case "WindowsHelloForBusiness":
                    await GraphClient.Users[userId].Authentication.WindowsHelloForBusinessMethods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                case "Email":
                    await GraphClient.Users[userId].Authentication.EmailMethods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                case "TemporaryAccessPass":
                    await GraphClient.Users[userId].Authentication.TemporaryAccessPassMethods[method.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    break;

                default:
                    return false;
            }

            return true;
        }
        catch (Microsoft.Graph.Models.ODataErrors.ODataError ex) when (ex.Error?.Code == "Request_ResourceNotFound")
        {
            // Method already deleted or doesn't exist
            return true;
        }
        catch
        {
            throw;
        }
    }

    public async Task<MassMfaResetResult> MassResetMfaAsync(
        string excludeUserId,
        int batchSize = 20,
        int delayBetweenBatchesMs = 2000,
        Action<int, int, string>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var results = new List<MfaResetResult>();
        var processedCount = 0;
        var allUsers = new List<User>();

        try
        {
            var usersResponse = await GraphClient.Users
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Select = new[]
                    {
                        "id",
                        "userPrincipalName",
                        "displayName",
                        "accountEnabled"
                    };
                    requestConfiguration.QueryParameters.Top = 999;
                    requestConfiguration.QueryParameters.Filter = "userType eq 'Member' and accountEnabled eq true";
                }, cancellationToken);

            if (usersResponse?.Value != null)
            {
                var pageIterator = PageIterator<User, UserCollectionResponse>
                    .CreatePageIterator(GraphClient, usersResponse, (user) =>
                    {
                        allUsers.Add(user);
                        return true;
                    });

                await pageIterator.IterateAsync(cancellationToken);
            }

            var usersToReset = allUsers
                .Where(u => u.Id != excludeUserId)
                .ToList();

            var totalUsers = usersToReset.Count;

            // Use smaller batch size for MFA operations as they are more intensive
            for (var i = 0; i < usersToReset.Count; i += batchSize)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var batch = usersToReset.Skip(i).Take(batchSize).ToList();

                // Process MFA resets sequentially within batch to avoid rate limiting
                foreach (var user in batch)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    progressCallback?.Invoke(Interlocked.Increment(ref processedCount), totalUsers, user.UserPrincipalName ?? "Unknown");

                    var result = await ResetUserMfaAsync(user.Id!, cancellationToken);
                    result.UserId ??= user.Id;
                    result.UserPrincipalName ??= user.UserPrincipalName;
                    result.DisplayName ??= user.DisplayName;

                    results.Add(result);

                    // Small delay between users to respect rate limits
                    await Task.Delay(500, cancellationToken);
                }

                if (i + batchSize < usersToReset.Count)
                {
                    await Task.Delay(delayBetweenBatchesMs, cancellationToken);
                }
            }
        }
        catch (Exception)
        {
            // Log error but continue with partial results
        }

        stopwatch.Stop();

        return new MassMfaResetResult
        {
            TotalProcessed = results.Count,
            SuccessCount = results.Count(r => r.Success),
            FailureCount = results.Count(r => !r.Success),
            TotalMethodsRemoved = results.Sum(r => r.MethodsRemoved),
            Results = results,
            Duration = stopwatch.Elapsed,
            FailedUsers = results.Where(r => !r.Success).ToList()
        };
    }

    #endregion

    #region Enterprise Application Cleanup Operations

    /// <summary>
    /// Get the current application's service principal info
    /// </summary>
    public async Task<EnterpriseAppInfo?> GetCurrentAppInfoAsync(string clientId, CancellationToken cancellationToken = default)
    {
        try
        {
            // Find the service principal by appId
            var servicePrincipals = await GraphClient.ServicePrincipals
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Filter = $"appId eq '{clientId}'";
                    requestConfiguration.QueryParameters.Select = new[]
                    {
                        "id",
                        "appId",
                        "displayName",
                        "createdDateTime",
                        "tags"
                    };
                }, cancellationToken);

            var sp = servicePrincipals?.Value?.FirstOrDefault();

            // Find the application registration
            var applications = await GraphClient.Applications
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Filter = $"appId eq '{clientId}'";
                    requestConfiguration.QueryParameters.Select = new[]
                    {
                        "id",
                        "appId",
                        "displayName",
                        "createdDateTime"
                    };
                }, cancellationToken);

            var app = applications?.Value?.FirstOrDefault();

            if (sp == null && app == null)
                return null;

                return new EnterpriseAppInfo
                {
                    ApplicationId = clientId,
                    ObjectId = app?.Id,
                    DisplayName = app?.DisplayName ?? sp?.DisplayName,
                    ServicePrincipalId = sp?.Id,
                    CreatedDateTime = app?.CreatedDateTime?.UtcDateTime,
                    Tags = sp?.Tags?.ToList() ?? new List<string>()
                };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Get all enterprise applications (service principals) in the tenant
    /// </summary>
    public async Task<List<EnterpriseAppInfo>> GetEnterpriseAppsAsync(
        string? excludeAppId = null,
        int top = 100,
        CancellationToken cancellationToken = default)
    {
        var apps = new List<EnterpriseAppInfo>();

        try
        {
            var servicePrincipals = await GraphClient.ServicePrincipals
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Select = new[]
                    {
                        "id",
                        "appId",
                        "displayName",
                        "createdDateTime",
                        "tags",
                        "servicePrincipalType"
                    };
                    requestConfiguration.QueryParameters.Top = top;
                    // Filter to only show Application type (not managed identities, etc.)
                    requestConfiguration.QueryParameters.Filter = "servicePrincipalType eq 'Application'";
                    requestConfiguration.QueryParameters.Orderby = new[] { "displayName" };
                }, cancellationToken);

            if (servicePrincipals?.Value != null)
            {
                foreach (var sp in servicePrincipals.Value)
                {
                    if (!string.IsNullOrEmpty(excludeAppId) && sp.AppId == excludeAppId)
                        continue;

                    apps.Add(new EnterpriseAppInfo
                    {
                        ApplicationId = sp.AppId,
                        ServicePrincipalId = sp.Id,
                        DisplayName = sp.DisplayName,
                        Tags = sp.Tags?.ToList() ?? new List<string>()
                    });
                }
            }
        }
        catch
        {
            // Return whatever we have
        }

        return apps;
    }

    /// <summary>
    /// Delete an enterprise application (service principal and optionally the app registration)
    /// </summary>
    public async Task<AppCleanupResult> DeleteEnterpriseAppAsync(
        string appId,
        bool deleteAppRegistration = true,
        CancellationToken cancellationToken = default)
    {
        var result = new AppCleanupResult
        {
            ApplicationId = appId,
            CleanupTime = DateTime.UtcNow
        };

        try
        {
            // First, find and delete the service principal
            var servicePrincipals = await GraphClient.ServicePrincipals
                .GetAsync(requestConfiguration =>
                {
                    requestConfiguration.QueryParameters.Filter = $"appId eq '{appId}'";
                }, cancellationToken);

            var sp = servicePrincipals?.Value?.FirstOrDefault();
            if (sp != null)
            {
                result.DisplayName = sp.DisplayName;
                await GraphClient.ServicePrincipals[sp.Id]
                    .DeleteAsync(cancellationToken: cancellationToken);
                result.ServicePrincipalDeleted = true;
            }

            // Then, find and delete the application registration if requested
            if (deleteAppRegistration)
            {
                var applications = await GraphClient.Applications
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Filter = $"appId eq '{appId}'";
                    }, cancellationToken);

                var app = applications?.Value?.FirstOrDefault();
                if (app != null)
                {
                    result.DisplayName ??= app.DisplayName;
                    await GraphClient.Applications[app.Id]
                        .DeleteAsync(cancellationToken: cancellationToken);
                    result.ApplicationDeleted = true;
                }
            }

            result.Success = result.ServicePrincipalDeleted || result.ApplicationDeleted;
            if (!result.Success)
            {
                result.ErrorMessage = "Application not found in tenant";
            }
        }
        catch (Microsoft.Graph.Models.ODataErrors.ODataError odataEx)
        {
            result.Success = false;
            result.ErrorMessage = $"Graph API error: {odataEx.Error?.Code} - {odataEx.Error?.Message}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = $"Unexpected error: {ex.Message}";
        }

        return result;
    }

    /// <summary>
    /// Mass delete enterprise applications (excluding current app)
    /// </summary>
    public async Task<MassAppCleanupResult> MassDeleteEnterpriseAppsAsync(
        string excludeAppId,
        List<string> appIdsToDelete,
        bool deleteAppRegistrations = true,
        int delayBetweenDeletesMs = 500,
        Action<int, int, string>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var results = new List<AppCleanupResult>();
        var processedCount = 0;

        var appsToDelete = appIdsToDelete
            .Where(id => id != excludeAppId)
            .ToList();

        var totalApps = appsToDelete.Count;

        foreach (var appId in appsToDelete)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            progressCallback?.Invoke(++processedCount, totalApps, appId);

            var result = await DeleteEnterpriseAppAsync(appId, deleteAppRegistrations, cancellationToken);
            results.Add(result);

            if (processedCount < totalApps)
            {
                await Task.Delay(delayBetweenDeletesMs, cancellationToken);
            }
        }

        stopwatch.Stop();

        return new MassAppCleanupResult
        {
            TotalProcessed = results.Count,
            SuccessCount = results.Count(r => r.Success),
            FailureCount = results.Count(r => !r.Success),
            ServicePrincipalsDeleted = results.Count(r => r.ServicePrincipalDeleted),
            ApplicationsDeleted = results.Count(r => r.ApplicationDeleted),
            Duration = stopwatch.Elapsed,
            Results = results,
            FailedApps = results.Where(r => !r.Success).ToList()
        };
    }

    #endregion
}
