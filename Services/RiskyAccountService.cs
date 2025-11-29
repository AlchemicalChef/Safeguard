using System;
using System.Collections.Generic;
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

/// <summary>
/// Service for detecting risky user accounts based on password configuration
/// </summary>
public class RiskyAccountService
{
    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<RiskyAccountService> _logger;
    private readonly ResilientGraphOperations _graphOps;

    // Windows FILETIME epoch - January 1, 1601
    private static readonly DateTimeOffset WindowsEpoch = new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public event Action<int, string>? OnThrottled;
    public event Action<int, TimeSpan, string>? OnRetry;
    public event Action<string>? OnCircuitOpened;

    public RiskyAccountService(
        GraphServiceClient graphClient,
        ResilienceConfiguration? resilienceConfig = null,
        ILogger<RiskyAccountService>? logger = null)
    {
        _graphClient = graphClient ?? throw new ArgumentNullException(nameof(graphClient));
        _logger = logger ?? LoggingConfiguration.GetLogger<RiskyAccountService>();

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
    }
    
    /// <summary>
    /// Scans all users for risky password configurations
    /// </summary>
    public async Task<RiskyAccountScanResult> ScanForRiskyAccountsAsync(
        Action<int, int>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var result = new RiskyAccountScanResult();
        var riskyAccounts = new List<RiskyAccountViewModel>();
        int totalScanned = 0;
        
        try
        {
            var (users, error) = await GetUsersWithPasswordInfoAsync(cancellationToken);
            
            if (error != null)
            {
                result.Success = false;
                result.ErrorMessage = error;
                return result;
            }
            
            if (users.Count == 0)
            {
                result.Success = true;
                result.ErrorMessage = "No users found in directory";
                return result;
            }
            
            foreach (var user in users)
            {
                cancellationToken.ThrowIfCancellationRequested();
                totalScanned++;
                
                var risks = AnalyzeUserRisks(user);
                if (risks.Any())
                {
                    foreach (var risk in risks)
                    {
                        riskyAccounts.Add(new RiskyAccountViewModel
                        {
                            Id = user.Id,
                            DisplayName = user.DisplayName ?? "Unknown",
                            UserPrincipalName = user.UserPrincipalName ?? "Unknown",
                            Department = user.Department,
                            AccountEnabled = user.AccountEnabled ?? false,
                            LastPasswordChangeDateTime = user.LastPasswordChangeDateTime,
                            RiskReason = risk.Reason,
                            Severity = risk.Severity
                        });
                    }
                }
                
                progressCallback?.Invoke(totalScanned, riskyAccounts.Count);
            }
            
            result.Success = true;
            result.TotalUsersScanned = totalScanned;
            result.RiskyAccountsFound = riskyAccounts.Count;
            result.RiskyAccounts = riskyAccounts
                .OrderByDescending(a => a.Severity)
                .ThenBy(a => a.DisplayName)
                .ToList();
        }
        catch (OperationCanceledException)
        {
            result.Success = false;
            result.ErrorMessage = "Scan was cancelled";
            result.RiskyAccounts = riskyAccounts;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = $"An error occurred while scanning: {ex.Message}";
        }
        
        return result;
    }
    
    /// <summary>
    /// Retrieves all users with password-related properties
    /// </summary>
    private async Task<(List<User> users, string? error)> GetUsersWithPasswordInfoAsync(CancellationToken cancellationToken)
    {
        var users = new List<User>();
        _logger.LogDebug("Retrieving users with password information");

        try
        {
            var response = await _graphOps.ExecuteAsync(
                async () => await _graphClient.Users
                    .GetAsync(requestConfiguration =>
                    {
                        requestConfiguration.QueryParameters.Select = new[]
                        {
                            "id",
                            "userPrincipalName",
                            "displayName",
                            "department",
                            "accountEnabled",
                            "lastPasswordChangeDateTime",
                            "createdDateTime",
                            "userType"
                        };
                        requestConfiguration.QueryParameters.Top = 999;
                        requestConfiguration.QueryParameters.Filter = "userType eq 'Member'";
                    }, cancellationToken),
                "GetUsersWithPasswordInfo",
                cancellationToken);

            if (response?.Value != null)
            {
                users.AddRange(response.Value);
            }

            // Handle pagination
            while (response?.OdataNextLink != null)
            {
                cancellationToken.ThrowIfCancellationRequested();

                response = await _graphOps.ExecuteAsync(
                    async () => await _graphClient.Users
                        .WithUrl(response.OdataNextLink)
                        .GetAsync(cancellationToken: cancellationToken),
                    "GetUsersWithPasswordInfo_Page",
                    cancellationToken);

                if (response?.Value != null)
                {
                    users.AddRange(response.Value);
                }
            }

            _logger.LogInformation("Retrieved {Count} users for risk analysis", users.Count);
            return (users, null);
        }
        catch (GraphApiException ex)
        {
            _logger.LogError(ex, "Failed to retrieve users for risk analysis");
            return (users, $"Error retrieving users: {ex.Message}");
        }
        catch (EntraConnectionException ex)
        {
            _logger.LogError(ex, "Connection error while retrieving users");
            return (users, $"Connection error: {ex.Message}");
        }
    }
    
    /// <summary>
    /// Analyzes a user for password-related risks
    /// </summary>
    private List<(string Reason, RiskSeverity Severity)> AnalyzeUserRisks(User user)
    {
        var risks = new List<(string Reason, RiskSeverity Severity)>();
        
        // Check 1: Password never set (1601 epoch or null)
        if (user.LastPasswordChangeDateTime == null)
        {
            // Null password date on an enabled account is critical
            if (user.AccountEnabled == true)
            {
                risks.Add(("Password never set on enabled account", RiskSeverity.Critical));
            }
            else
            {
                risks.Add(("Password never set", RiskSeverity.High));
            }
        }
        else if (IsWindowsEpoch(user.LastPasswordChangeDateTime.Value))
        {
            // 1601 timestamp indicates password never set (Windows FILETIME epoch)
            if (user.AccountEnabled == true)
            {
                risks.Add(("Password timestamp is 1601 epoch (never set) on enabled account", RiskSeverity.Critical));
            }
            else
            {
                risks.Add(("Password timestamp is 1601 epoch (never set)", RiskSeverity.High));
            }
        }
        
        // Check 2: Password older than 365 days
        if (user.LastPasswordChangeDateTime != null && 
            !IsWindowsEpoch(user.LastPasswordChangeDateTime.Value))
        {
            var passwordAge = DateTimeOffset.UtcNow - user.LastPasswordChangeDateTime.Value;
            
            if (passwordAge.TotalDays > 730 && user.AccountEnabled == true) // > 2 years
            {
                risks.Add(($"Password not changed in {(int)passwordAge.TotalDays} days (enabled account)", RiskSeverity.High));
            }
            else if (passwordAge.TotalDays > 365 && user.AccountEnabled == true) // > 1 year
            {
                risks.Add(($"Password not changed in {(int)passwordAge.TotalDays} days", RiskSeverity.Medium));
            }
        }
        
        // Check 3: Account created but password set at exactly same time (potential scripted creation without user password change)
        if (user.CreatedDateTime != null && 
            user.LastPasswordChangeDateTime != null &&
            !IsWindowsEpoch(user.LastPasswordChangeDateTime.Value))
        {
            var timeDiff = Math.Abs((user.CreatedDateTime.Value - user.LastPasswordChangeDateTime.Value).TotalMinutes);
            if (timeDiff < 1 && user.AccountEnabled == true)
            {
                risks.Add(("Password set at account creation time (user may not have changed initial password)", RiskSeverity.Medium));
            }
        }
        
        return risks;
    }
    
    /// <summary>
    /// Checks if the datetime is the Windows FILETIME epoch (1601-01-01)
    /// </summary>
    private bool IsWindowsEpoch(DateTimeOffset dateTime)
    {
        return dateTime.Year == 1601 && dateTime.Month == 1 && dateTime.Day == 1;
    }
    
    /// <summary>
    /// Forces a password reset for the specified user
    /// </summary>
    public async Task<bool> ForcePasswordResetAsync(string userId, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Forcing password reset for user {UserId}", userId);

        try
        {
            var userUpdate = new User
            {
                PasswordProfile = new PasswordProfile
                {
                    ForceChangePasswordNextSignIn = true,
                    ForceChangePasswordNextSignInWithMfa = true
                }
            };

            await _graphOps.ExecuteAsync(
                async () =>
                {
                    await _graphClient.Users[userId]
                        .PatchAsync(userUpdate, cancellationToken: cancellationToken);
                    return true;
                },
                "ForcePasswordReset",
                cancellationToken);

            _logger.LogInformation("Successfully forced password reset for user {UserId}", userId);
            return true;
        }
        catch (GraphApiException ex)
        {
            _logger.LogError(ex, "Failed to force password reset for user {UserId}", userId);
            throw new OperationException(
                $"Failed to force password reset: {ex.Message}",
                "FORCE_PASSWORD_RESET_FAILED",
                OperationType.UserModification,
                userId,
                ex);
        }
    }

    /// <summary>
    /// Disables the specified user account
    /// </summary>
    public async Task<bool> DisableAccountAsync(string userId, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Disabling account for user {UserId}", userId);

        try
        {
            var userUpdate = new User
            {
                AccountEnabled = false
            };

            await _graphOps.ExecuteAsync(
                async () =>
                {
                    await _graphClient.Users[userId]
                        .PatchAsync(userUpdate, cancellationToken: cancellationToken);
                    return true;
                },
                "DisableAccount",
                cancellationToken);

            _logger.LogInformation("Successfully disabled account for user {UserId}", userId);
            return true;
        }
        catch (GraphApiException ex)
        {
            _logger.LogError(ex, "Failed to disable account for user {UserId}", userId);
            throw new OperationException(
                $"Failed to disable account: {ex.Message}",
                "DISABLE_ACCOUNT_FAILED",
                OperationType.UserModification,
                userId,
                ex);
        }
    }
    
    /// <summary>
    /// Performs bulk remediation on selected risky accounts
    /// </summary>
    public async Task<(int succeeded, int failed)> BulkRemediateAsync(
        List<RiskyAccountViewModel> accounts,
        bool forcePasswordReset,
        bool disableAccount,
        string? excludeUserId = null,
        Action<int, int>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation(
            "Starting bulk remediation for {Count} accounts (forceReset={ForceReset}, disable={Disable})",
            accounts.Count, forcePasswordReset, disableAccount);

        int succeeded = 0;
        int failed = 0;
        int processed = 0;

        foreach (var account in accounts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (account.Id == excludeUserId)
            {
                _logger.LogDebug("Skipping excluded user {UserId}", account.Id);
                processed++;
                progressCallback?.Invoke(processed, accounts.Count);
                continue;
            }

            try
            {
                bool success = true;

                if (disableAccount)
                {
                    success &= await DisableAccountAsync(account.Id!, cancellationToken);
                }

                if (forcePasswordReset && success)
                {
                    success &= await ForcePasswordResetAsync(account.Id!, cancellationToken);
                }

                if (success)
                {
                    succeeded++;
                    _logger.LogDebug("Successfully remediated account {UserId}", account.Id);
                }
                else
                {
                    failed++;
                    _logger.LogWarning("Remediation returned false for account {UserId}", account.Id);
                }
            }
            catch (OperationException ex)
            {
                failed++;
                _logger.LogError(ex, "Failed to remediate account {UserId}: {Error}",
                    account.Id, ex.Message);
            }
            catch (Exception ex)
            {
                failed++;
                _logger.LogError(ex, "Unexpected error remediating account {UserId}", account.Id);
            }

            processed++;
            progressCallback?.Invoke(processed, accounts.Count);

            await Task.Delay(100, cancellationToken);
        }

        _logger.LogInformation(
            "Bulk remediation completed: {Succeeded} succeeded, {Failed} failed",
            succeeded, failed);

        return (succeeded, failed);
    }
}
