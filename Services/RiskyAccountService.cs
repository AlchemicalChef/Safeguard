using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Safeguard.Models;
using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace Safeguard.Services;

/// <summary>
/// Service for detecting risky user accounts based on password configuration
/// </summary>
public class RiskyAccountService
{
    private readonly GraphServiceClient _graphClient;
    
    // Windows FILETIME epoch - January 1, 1601
    private static readonly DateTimeOffset WindowsEpoch = new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);
    
    public RiskyAccountService(GraphServiceClient graphClient)
    {
        _graphClient = graphClient ?? throw new ArgumentNullException(nameof(graphClient));
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
        string? error = null;
        
        try
        {
            var response = await _graphClient.Users
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
                }, cancellationToken);
            
            if (response?.Value != null)
            {
                users.AddRange(response.Value);
            }
            
            // Handle pagination
            while (response?.OdataNextLink != null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                response = await _graphClient.Users
                    .WithUrl(response.OdataNextLink)
                    .GetAsync(cancellationToken: cancellationToken);
                
                if (response?.Value != null)
                {
                    users.AddRange(response.Value);
                }
            }
        }
        catch (Exception)
        {
            error = "Error retrieving users. Please verify permissions and connectivity.";
        }
        
        return (users, error);
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
            
            await _graphClient.Users[userId]
                .PatchAsync(userUpdate, cancellationToken: cancellationToken);
            
            return true;
        }
        catch
        {
            return false;
        }
    }
    
    /// <summary>
    /// Disables the specified user account
    /// </summary>
    public async Task<bool> DisableAccountAsync(string userId, CancellationToken cancellationToken = default)
    {
        try
        {
            var userUpdate = new User
            {
                AccountEnabled = false
            };
            
            await _graphClient.Users[userId]
                .PatchAsync(userUpdate, cancellationToken: cancellationToken);
            
            return true;
        }
        catch
        {
            return false;
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
        int succeeded = 0;
        int failed = 0;
        int processed = 0;
        
        foreach (var account in accounts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            if (account.Id == excludeUserId)
            {
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
                    succeeded++;
                else
                    failed++;
            }
            catch
            {
                failed++;
            }
            
            processed++;
            progressCallback?.Invoke(processed, accounts.Count);
            
            await Task.Delay(100, cancellationToken);
        }
        
        return (succeeded, failed);
    }
}
