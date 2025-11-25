using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Safeguard.Models;
using Safeguard.Services;
using Microsoft.Graph.Models;
using System.Security;

namespace Safeguard;

public partial class MainWindow : Window
{
    private AuthenticationService? _authService;
    private TokenRevocationService? _revocationService;
    private BackdoorDetectionService? _backdoorService;
    private RiskyAccountService? _riskyAccountService;
    private AppProvisioningService? _provisioningService;
    private CancellationTokenSource? _cancellationTokenSource;
    private User? _selectedUserForRevocation;
    private string? _currentClientId;
    private string? _provisionedClientId;
    private string? _currentTenantId;

    private readonly ObservableCollection<ActivityLogEntry> _activityLog = new();
    private readonly ObservableCollection<UserViewModel> _users = new();
    private readonly ObservableCollection<EnterpriseAppViewModel> _enterpriseApps = new();
    private readonly ObservableCollection<FindingViewModel> _findings = new();
    private readonly ObservableCollection<RiskyAccountViewModel> _riskyAccounts = new();
    private BackdoorScanResult? _lastScanResult;
    
    private FindingViewModel? _selectedFinding;
    
    private DispatcherTimer? _throttleCountdownTimer;
    private int _throttleSecondsRemaining;
    private DateTime _lastThrottleAlert = DateTime.MinValue;

    public MainWindow()
    {
        InitializeComponent();
        InitializeServices();
        InitializeBindings();
        ShowSetupWizard();
    }

    private void InitializeBindings()
    {
        ActivityLogList.ItemsSource = _activityLog;
        FindingsListView.ItemsSource = _findings;
        RiskyAccountsListView.ItemsSource = _riskyAccounts;
    }

    private void ShowSetupWizard()
    {
        SetupWizardPanel.IsVisible = true;
        LoginPanel.IsVisible = false;
        MainPanel.IsVisible = false;
    }

    private void InitializeServices()
    {
        _throttleCountdownTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _throttleCountdownTimer.Tick += ThrottleCountdownTimer_Tick;
    }

    private void OnThrottled(int retryAfterSeconds, string operation)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            if ((DateTime.Now - _lastThrottleAlert).TotalSeconds < 5)
                return;
            
            _lastThrottleAlert = DateTime.Now;
            _throttleSecondsRemaining = retryAfterSeconds;
            
            ThrottleAlertMessage.Text = $"Microsoft Graph API is throttling requests during '{operation}'. " +
                                        $"Operations will automatically retry after the cooldown period.";
            ThrottleCountdownText.Text = $"{retryAfterSeconds}s";
            ThrottleAlertBanner.IsVisible = true;
            
            _throttleCountdownTimer?.Start();
            
            AddLogEntry($"API throttled during {operation}. Retry after {retryAfterSeconds}s", LogLevel.Warning);
        });
    }
    
    private void ThrottleCountdownTimer_Tick(object? sender, EventArgs e)
    {
        _throttleSecondsRemaining--;
        
        if (_throttleSecondsRemaining <= 0)
        {
            _throttleCountdownTimer?.Stop();
            ThrottleAlertBanner.IsVisible = false;
        }
        else
        {
            ThrottleCountdownText.Text = $"{_throttleSecondsRemaining}s";
        }
    }
    
    private void ThrottleDismissButton_Click(object? sender, RoutedEventArgs e)
    {
        _throttleCountdownTimer?.Stop();
        ThrottleAlertBanner.IsVisible = false;
    }

    private void UpdateMfaResetButtonState(object? sender, RoutedEventArgs e)
    {
        MassMfaResetButton.IsEnabled = 
            (MfaResetConfirmation1.IsChecked == true) && 
            (MfaResetConfirmation2.IsChecked == true);
    }

    private void UpdateMassRevokeButtonState(object? sender, RoutedEventArgs e)
    {
        MassRevokeButton.IsEnabled = MassRevocationConfirmation.IsChecked == true;
    }

    #region Setup Wizard

    private async void ProvisionAppButton_Click(object? sender, RoutedEventArgs e)
    {
        var tenantId = SetupTenantIdInput.Text?.Trim() ?? "common";
        _currentTenantId = tenantId;
        
        ProvisionAppButton.IsEnabled = false;
        ProvisioningStatusPanel.IsVisible = true;
        ProvisioningProgressBar.IsVisible = true;
        ProvisioningSuccessPanel.IsVisible = false;
        ProvisioningErrorPanel.IsVisible = false;
        ProvisioningStatusText.Text = "Initializing...";

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            
            _provisioningService = new AppProvisioningService();
            
            _provisioningService.OnStatusUpdate += (status) =>
            {
                Dispatcher.UIThread.InvokeAsync(() => ProvisioningStatusText.Text = status);
            };

            var result = await _provisioningService.ProvisionSafeguardAppAsync(tenantId, cts.Token);

            if (result.Success && result.ClientId != null)
            {
                _provisionedClientId = result.ClientId;
                ProvisionedClientIdText.Text = $"Client ID: {result.ClientId}";
                ProvisioningSuccessPanel.IsVisible = true;
                ProvisioningStatusPanel.IsVisible = false;
                AddLogEntry($"Safeguard app provisioned: {result.ClientId}", LogLevel.Success);
            }
            else
            {
                ProvisioningErrorText.Text = result.ErrorMessage ?? "Unknown error";
                ProvisioningErrorPanel.IsVisible = true;
                ProvisioningStatusPanel.IsVisible = false;
                AddLogEntry("App provisioning failed", LogLevel.Error);
            }
        }
        catch (OperationCanceledException)
        {
            ProvisioningErrorText.Text = "Operation timed out";
            ProvisioningErrorPanel.IsVisible = true;
            ProvisioningStatusPanel.IsVisible = false;
        }
        catch (Exception)
        {
            ProvisioningErrorText.Text = "An unexpected error occurred";
            ProvisioningErrorPanel.IsVisible = true;
            ProvisioningStatusPanel.IsVisible = false;
        }
        finally
        {
            ProvisionAppButton.IsEnabled = true;
            ProvisioningProgressBar.IsVisible = false;
        }
    }

    private async void CopyClientIdButton_Click(object? sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_provisionedClientId))
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard != null)
            {
                await clipboard.SetTextAsync(_provisionedClientId);
                AddLogEntry("Client ID copied to clipboard", LogLevel.Info);
            }
        }
    }

    private void ProceedToLoginButton_Click(object? sender, RoutedEventArgs e)
    {
        SetupWizardPanel.IsVisible = false;
        LoginPanel.IsVisible = true;
        
        if (!string.IsNullOrEmpty(_provisionedClientId))
        {
            ClientIdInput.Text = _provisionedClientId;
        }
        
        var tenantId = SetupTenantIdInput.Text?.Trim();
        if (!string.IsNullOrEmpty(tenantId) && tenantId != "common")
        {
            TenantIdInput.Text = tenantId;
        }
    }

    private void SkipSetupButton_Click(object? sender, RoutedEventArgs e)
    {
        SetupWizardPanel.IsVisible = false;
        LoginPanel.IsVisible = true;
    }

    #endregion

    #region Authentication

    private static SecureString GetSecurePassword(TextBox passwordBox)
    {
        var securePassword = new SecureString();
        var password = passwordBox.Text ?? string.Empty;
        foreach (char c in password)
        {
            securePassword.AppendChar(c);
        }
        return securePassword;
    }

    private async void ConnectButton_Click(object? sender, RoutedEventArgs e)
    {
        var tenantId = TenantIdInput.Text?.Trim() ?? "";
        var clientId = ClientIdInput.Text?.Trim() ?? "";
        var username = UsernameInput.Text?.Trim() ?? "";
        
        using var securePassword = GetSecurePassword(PasswordInput);

        if (string.IsNullOrWhiteSpace(clientId))
        {
            ShowConnectionError("Client ID is required");
            return;
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            ShowConnectionError("Username is required");
            return;
        }

        if (securePassword.Length == 0)
        {
            ShowConnectionError("Password is required");
            return;
        }

        _currentClientId = clientId;

        ConnectButton.IsEnabled = false;
        ConnectButton.Content = "Authenticating...";
        ConnectionErrorPanel.IsVisible = false;

        try
        {
            var config = new AppConfiguration
            {
                AzureAd = new AzureAdConfiguration
                {
                    TenantId = string.IsNullOrWhiteSpace(tenantId) ? "organizations" : tenantId,
                    ClientId = clientId
                }
            };

            _authService = new AuthenticationService(config);
            _authService.OnTokenRefreshed += OnTokenRefreshed;
            
            AddLogEntry("Authenticating...", LogLevel.Info);
            UpdateStatus("Authenticating...");
            
            var result = await _authService.AuthenticateAsync(username, securePassword);

            if (result.Success)
            {
                _revocationService = new TokenRevocationService(_authService);
                _backdoorService = new BackdoorDetectionService(_authService);
                _riskyAccountService = new RiskyAccountService(_authService.GraphClient!);
                
                _revocationService.OnThrottled += OnThrottled;
                
                LoginPanel.IsVisible = false;
                MainPanel.IsVisible = true;
                
                AuthStatusIndicator.Fill = new SolidColorBrush(Color.Parse("#107C10"));
                AuthStatusText.Text = result.UserPrincipalName;
                AuthMethodText.Text = $"({result.AuthMethod})";
                SignOutButton.IsVisible = true;
                HeaderSignOutButton.IsVisible = true;
                
                if (result.TokenExpiresOn.HasValue)
                {
                    UpdateTokenStatus(result.TokenExpiresOn.Value);
                }

                PasswordInput.Text = "";
                UsernameInput.Text = "";

                AddLogEntry($"Connected as {result.UserPrincipalName}", LogLevel.Success);
                UpdateStatus($"Connected as {result.DisplayName}");
            }
            else
            {
                ShowConnectionError(result.ErrorMessage ?? "Authentication failed");
                AddLogEntry("Authentication failed", LogLevel.Error);
            }
        }
        catch (Exception)
        {
            ShowConnectionError("An unexpected error occurred during authentication");
            AddLogEntry("Connection error occurred", LogLevel.Error);
        }
        finally
        {
            ConnectButton.IsEnabled = true;
            ConnectButton.Content = "Authenticate";
            PasswordInput.Text = "";
        }
    }

    private void ShowConnectionError(string message)
    {
        ConnectionErrorText.Text = message;
        ConnectionErrorPanel.IsVisible = true;
    }

    private void OnTokenRefreshed(DateTimeOffset expiresOn)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            UpdateTokenStatus(expiresOn);
            AddLogEntry("Token refreshed successfully", LogLevel.Info);
        });
    }

    private void UpdateTokenStatus(DateTimeOffset expiresOn)
    {
        var timeRemaining = expiresOn - DateTimeOffset.UtcNow;
        if (timeRemaining.TotalMinutes > 60)
        {
            TokenStatusText.Text = $"Token valid for {timeRemaining.Hours}h {timeRemaining.Minutes}m";
            TokenStatusText.Foreground = new SolidColorBrush(Color.Parse("#107C10"));
        }
        else if (timeRemaining.TotalMinutes > 10)
        {
            TokenStatusText.Text = $"Token valid for {timeRemaining.Minutes}m";
            TokenStatusText.Foreground = new SolidColorBrush(Color.Parse("#FF8C00"));
        }
        else
        {
            TokenStatusText.Text = $"Token expires soon ({timeRemaining.Minutes}m)";
            TokenStatusText.Foreground = new SolidColorBrush(Color.Parse("#D32F2F"));
        }
    }

    private void SignOutButton_Click(object? sender, RoutedEventArgs e)
    {
        _authService = null;
        _revocationService = null;
        _backdoorService = null;
        _riskyAccountService = null;
        
        MainPanel.IsVisible = false;
        LoginPanel.IsVisible = true;
        SignOutButton.IsVisible = false;
        HeaderSignOutButton.IsVisible = false;
        
        HeaderAuthIndicator.Fill = new SolidColorBrush(Color.Parse("#FFB900"));
        HeaderAuthText.Text = "Not Connected";
        
        _activityLog.Clear();
        _findings.Clear();
        _riskyAccounts.Clear();
        
        AddLogEntry("Signed out", LogLevel.Info);
        UpdateStatus("Disconnected");
    }

    #endregion

    #region Single User Revocation

    private async void LookupUserButton_Click(object? sender, RoutedEventArgs e)
    {
        var userIdentifier = SingleUserInput.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(userIdentifier) || _revocationService == null)
            return;

        UpdateStatus($"Looking up user: {userIdentifier}...");
        AddLogEntry($"Looking up user: {userIdentifier}", LogLevel.Info);

        try
        {
            var user = await _revocationService.GetUserInfoAsync(userIdentifier);
            
            if (user != null)
            {
                _selectedUserForRevocation = user;
                DisplayUserInfo(user);
                UserInfoPanel.IsVisible = true;
                AddLogEntry($"Found user: {user.DisplayName}", LogLevel.Success);
            }
            else
            {
                UserInfoPanel.IsVisible = false;
                _selectedUserForRevocation = null;
                AddLogEntry($"User not found: {userIdentifier}", LogLevel.Warning);
            }
        }
        catch (Exception)
        {
            AddLogEntry("Error looking up user", LogLevel.Error);
        }
        finally
        {
            UpdateStatus("Ready");
        }
    }

    private void DisplayUserInfo(User user)
    {
        UserDisplayName.Text = user.DisplayName ?? "Unknown";
        UserEmail.Text = user.UserPrincipalName ?? "N/A";
        UserDepartment.Text = string.IsNullOrEmpty(user.Department) ? "" : $"Department: {user.Department}";
        
        var initials = GetInitials(user.DisplayName ?? "?");
        UserInitials.Text = initials;
    }

    private static string GetInitials(string name)
    {
        var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
            return $"{parts[0][0]}{parts[^1][0]}".ToUpper();
        return parts.Length == 1 ? parts[0][..Math.Min(2, parts[0].Length)].ToUpper() : "?";
    }

    private async void RevokeSingleButton_Click(object? sender, RoutedEventArgs e)
    {
        var userIdentifier = SingleUserInput.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(userIdentifier) || _revocationService == null)
            return;

        RevokeSingleButton.IsEnabled = false;
        UpdateStatus($"Revoking tokens for {userIdentifier}...");
        AddLogEntry($"Revoking tokens for: {userIdentifier}", LogLevel.Info);

        try
        {
            var result = await _revocationService.RevokeUserTokensAsync(userIdentifier);
            
            ShowSingleResult(result.Success, result.Success 
                ? $"Successfully revoked tokens for {result.UserPrincipalName}"
                : $"Failed: {result.ErrorMessage}");

            AddLogEntry(result.Success 
                ? $"Revoked tokens for {result.UserPrincipalName}"
                : $"Failed to revoke tokens: {result.ErrorMessage}",
                result.Success ? LogLevel.Success : LogLevel.Error);
        }
        catch (Exception ex)
        {
            ShowSingleResult(false, $"Error: {ex.Message}");
            AddLogEntry($"Error during revocation: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            RevokeSingleButton.IsEnabled = true;
            UpdateStatus("Ready");
        }
    }

    private void ShowSingleResult(bool success, string message)
    {
        SingleResultPanel.IsVisible = true;
        SingleResultPanel.Background = new SolidColorBrush(Color.Parse(success ? "#E8F5E9" : "#FFEBEE"));
        SingleResultIcon.Text = success ? "OK" : "X";
        SingleResultIcon.Foreground = new SolidColorBrush(Color.Parse(success ? "#0F7B0F" : "#C42B1C"));
        SingleResultText.Text = message;
    }

    #endregion

    #region Mass Revocation

    private async void MassRevokeButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_revocationService == null || _authService?.CurrentUserId == null)
            return;

        if (!int.TryParse(BatchSizeInput.Text, out var batchSize) || batchSize < 1 || batchSize > 100)
            batchSize = 50;

        if (!int.TryParse(DelayInput.Text, out var delay) || delay < 100 || delay > 10000)
            delay = 1000;

        MassRevokeButton.IsEnabled = false;
        MassRevocationConfirmation.IsEnabled = false;
        MassProgressPanel.IsVisible = true;
        MassResultsPanel.IsVisible = false;

        _cancellationTokenSource = new CancellationTokenSource();

        AddLogEntry("Starting mass token revocation...", LogLevel.Warning);
        UpdateStatus("Mass revocation in progress...");

        try
        {
            var result = await _revocationService.MassRevokeTokensAsync(
                _authService.CurrentUserId,
                batchSize,
                delay,
                OnMassRevocationProgress,
                _cancellationTokenSource.Token);

            ShowMassResults(result);
            AddLogEntry($"Mass revocation completed. Success: {result.SuccessCount}, Failed: {result.FailureCount}", 
                result.FailureCount == 0 ? LogLevel.Success : LogLevel.Warning);
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("Mass revocation cancelled", LogLevel.Warning);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Mass revocation error: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            MassRevokeButton.IsEnabled = true;
            MassRevocationConfirmation.IsEnabled = true;
            MassRevocationConfirmation.IsChecked = false;
            MassProgressPanel.IsVisible = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            UpdateStatus("Ready");
        }
    }

    private void OnMassRevocationProgress(int current, int total, string currentUser)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            var percent = (double)current / total * 100;
            MassProgressBar.Value = percent;
            MassProgressText.Text = $"Processing {current} of {total} users...";
            MassProgressPercent.Text = $"{percent:F1}%";
            MassCurrentUser.Text = $"Current: {currentUser}";
        });
    }

    private void ShowMassResults(MassRevocationResult result)
    {
        MassResultsPanel.IsVisible = true;
        MassTotalCount.Text = result.TotalProcessed.ToString();
        MassSuccessCount.Text = result.SuccessCount.ToString();
        MassFailedCount.Text = result.FailureCount.ToString();
        MassDuration.Text = $"Completed in {result.Duration.TotalSeconds:F1} seconds";
    }

    #endregion

    #region Mass MFA Reset

    private async void MassMfaResetButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_revocationService == null || _authService?.CurrentUserId == null)
            return;

        if (!int.TryParse(MfaBatchSizeInput.Text, out var batchSize) || batchSize < 1 || batchSize > 50)
            batchSize = 20;

        if (!int.TryParse(MfaDelayInput.Text, out var delay) || delay < 500 || delay > 10000)
            delay = 2000;

        MassMfaResetButton.IsEnabled = false;
        MfaProgressPanel.IsVisible = true;
        MfaResultsPanel.IsVisible = false;

        _cancellationTokenSource = new CancellationTokenSource();

        AddLogEntry("Starting mass MFA reset...", LogLevel.Warning);
        UpdateStatus("Mass MFA reset in progress...");

        try
        {
            var result = await _revocationService.MassResetMfaAsync(
                _authService.CurrentUserId,
                batchSize,
                delay,
                OnMfaResetProgress,
                _cancellationTokenSource.Token);

            ShowMfaResults(result);
            AddLogEntry($"Mass MFA reset completed. Success: {result.SuccessCount}, Failed: {result.FailureCount}", 
                result.FailureCount == 0 ? LogLevel.Success : LogLevel.Warning);
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("Mass MFA reset cancelled", LogLevel.Warning);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Mass MFA reset error: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            MassMfaResetButton.IsEnabled = true;
            MfaResetConfirmation1.IsChecked = false;
            MfaResetConfirmation2.IsChecked = false;
            MfaProgressPanel.IsVisible = false;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            UpdateStatus("Ready");
        }
    }

    private void OnMfaResetProgress(int current, int total, string currentUser)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            var percent = (double)current / total * 100;
            MfaProgressBar.Value = percent;
            MfaProgressText.Text = $"Processing {current} of {total} users...";
            MfaProgressPercent.Text = $"{percent:F1}%";
            MfaCurrentUser.Text = $"Current: {currentUser}";
        });
    }

    private void ShowMfaResults(MassMfaResetResult result)
    {
        MfaResultsPanel.IsVisible = true;
        MfaTotalCount.Text = result.TotalProcessed.ToString();
        MfaSuccessCount.Text = result.SuccessCount.ToString();
        MfaFailedCount.Text = result.FailureCount.ToString();
        MfaMethodsRemovedCount.Text = result.TotalMethodsRemoved.ToString();
        MfaDuration.Text = $"Completed in {result.Duration.TotalSeconds:F1} seconds";
    }

    #endregion

    #region Backdoor Detection

    private async void RunBackdoorScanButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_backdoorService == null)
            return;

        RunBackdoorScanButton.IsEnabled = false;
        BackdoorScanProgressPanel.IsVisible = true;
        BackdoorResultsPanel.IsVisible = false;
        FindingsHeader.IsVisible = false;
        FindingsListBorder.IsVisible = false;
        _findings.Clear();

        AddLogEntry("Starting backdoor detection scan...", LogLevel.Info);
        UpdateStatus("Scanning for backdoors...");

        try
        {
            var options = new BackdoorScanOptions
            {
                ScanFederatedDomains = ScanDomainsCheckbox.IsChecked == true,
                ScanPTAAgents = ScanPTACheckbox.IsChecked == true,
                ScanServicePrincipals = ScanServicePrincipalsCheckbox.IsChecked == true,
                ScanOAuthGrants = ScanOAuthGrantsCheckbox.IsChecked == true,
                ScanAppCredentials = ScanAppCredentialsCheckbox.IsChecked == true
            };

            var result = await _backdoorService.ScanForBackdoorsAsync(options);
            _lastScanResult = result;

            ShowBackdoorResults(result);
            AddLogEntry($"Backdoor scan completed. Found {result.Findings.Count} findings", LogLevel.Success);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Backdoor scan error: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            RunBackdoorScanButton.IsEnabled = true;
            BackdoorScanProgressPanel.IsVisible = false;
            UpdateStatus("Ready");
        }
    }

    private void ShowBackdoorResults(BackdoorScanResult result)
    {
        BackdoorResultsPanel.IsVisible = true;
        
        CriticalFindingsCount.Text = result.Findings.Count(f => f.Severity == SeverityLevel.Critical).ToString();
        HighFindingsCount.Text = result.Findings.Count(f => f.Severity == SeverityLevel.High).ToString();
        MediumFindingsCount.Text = result.Findings.Count(f => f.Severity == SeverityLevel.Medium).ToString();
        LowFindingsCount.Text = result.Findings.Count(f => f.Severity == SeverityLevel.Low).ToString();
        InfoFindingsCount.Text = result.Findings.Count(f => f.Severity == SeverityLevel.Info).ToString();
        BackdoorScanDuration.Text = $"Scan completed in {result.ScanDuration.TotalSeconds:F1} seconds";

        if (result.Findings.Count > 0)
        {
            FindingsHeader.IsVisible = true;
            FindingsListBorder.IsVisible = true;
            
            foreach (var finding in result.Findings)
            {
                _findings.Add(new FindingViewModel
                {
                    Id = finding.Id,
                    Title = finding.Title,
                    TypeDisplay = finding.Type.ToString(),
                    Severity = finding.Severity,
                    Description = finding.Description,
                    AffectedResource = finding.AffectedResource,
                    ResourceId = finding.ResourceId,
                    Recommendation = finding.Recommendation,
                    MitreAttackId = finding.MitreAttackId,
                    Details = finding.Details,
                    Finding = finding
                });
            }
        }
    }

    private static Color GetSeverityColor(SeverityLevel severity)
    {
        return severity switch
        {
            SeverityLevel.Critical => Color.Parse("#D32F2F"),
            SeverityLevel.High => Color.Parse("#F57C00"),
            SeverityLevel.Medium => Color.Parse("#FBC02D"),
            SeverityLevel.Low => Color.Parse("#1B3A57"),
            _ => Color.Parse("#5C5C5C")
        };
    }

    private void FindingsListView_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        _selectedFinding = FindingsListView.SelectedItem as FindingViewModel;
    }

    private async void ExportFindingsButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_lastScanResult == null)
            return;

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export Findings",
            SuggestedFileName = $"safeguard-findings-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            FileTypeChoices = new[] { new FilePickerFileType("JSON") { Patterns = new[] { "*.json" } } }
        });

        if (file != null)
        {
            var json = JsonSerializer.Serialize(_lastScanResult.Findings, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(file.Path.LocalPath, json);
            AddLogEntry($"Findings exported to {file.Name}", LogLevel.Success);
        }
    }

    #endregion

    #region Risky Accounts

    private async void ScanRiskyAccountsButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_riskyAccountService == null)
            return;

        ScanRiskyAccountsButton.IsEnabled = false;
        RiskyAccountsProgressPanel.IsVisible = true;
        RiskyAccountsResultsPanel.IsVisible = false;
        RiskyAccountsListBorder.IsVisible = false;
        _riskyAccounts.Clear();

        AddLogEntry("Scanning for risky accounts...", LogLevel.Info);
        UpdateStatus("Scanning accounts...");

        try
        {
            var result = await _riskyAccountService.ScanForRiskyAccountsAsync();

            if (!result.Success)
            {
                AddLogEntry(result.ErrorMessage ?? "Risky account scan failed", LogLevel.Error);
                UpdateStatus("Risky account scan failed");
                return;
            }

            RiskyAccountsResultsPanel.IsVisible = true;
            CriticalRiskyCount.Text = result.RiskyAccounts.Count(a => a.Severity == RiskSeverity.Critical).ToString();
            HighRiskyCount.Text = result.RiskyAccounts.Count(a => a.Severity == RiskSeverity.High).ToString();
            MediumRiskyCount.Text = result.RiskyAccounts.Count(a => a.Severity == RiskSeverity.Medium).ToString();

            if (result.RiskyAccounts.Count > 0)
            {
                RiskyAccountsListBorder.IsVisible = true;
                foreach (var account in result.RiskyAccounts)
                {
                    _riskyAccounts.Add(account);
                }
            }

            AddLogEntry($"Found {result.RiskyAccounts.Count} risky accounts", LogLevel.Success);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error scanning accounts: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            ScanRiskyAccountsButton.IsEnabled = true;
            RiskyAccountsProgressPanel.IsVisible = false;
            UpdateStatus("Ready");
        }
    }

    #endregion

    #region Activity Log

    private void AddLogEntry(string message, LogLevel level)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            var entry = new ActivityLogEntry
            {
                Timestamp = DateTime.Now,
                Message = message,
                Level = level,
                LevelColor = new SolidColorBrush(GetLogLevelColor(level))
            };
            
            _activityLog.Insert(0, entry);
            
            if (_activityLog.Count > 500)
            {
                _activityLog.RemoveAt(_activityLog.Count - 1);
            }
        });
    }

    private static Color GetLogLevelColor(LogLevel level)
    {
        return level switch
        {
            LogLevel.Success => Color.Parse("#0F7B0F"),
            LogLevel.Warning => Color.Parse("#F7630C"),
            LogLevel.Error => Color.Parse("#C42B1C"),
            _ => Color.Parse("#1B3A57")
        };
    }

    private void ClearLogButton_Click(object? sender, RoutedEventArgs e)
    {
        _activityLog.Clear();
    }

    private async void ExportLogButton_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null) return;

        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export Activity Log",
            SuggestedFileName = $"safeguard-log-{DateTime.Now:yyyyMMdd-HHmmss}.json",
            FileTypeChoices = new[] { new FilePickerFileType("JSON") { Patterns = new[] { "*.json" } } }
        });

        if (file != null)
        {
            var logData = _activityLog.Select(e => new
            {
                e.Timestamp,
                e.Message,
                Level = e.Level.ToString()
            });
            
            var json = JsonSerializer.Serialize(logData, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(file.Path.LocalPath, json);
            AddLogEntry($"Log exported to {file.Name}", LogLevel.Success);
        }
    }

    #endregion

    #region Helpers

    private void UpdateStatus(string status)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            FooterStatusText.Text = status;
            StatusText.Text = status;
        });
    }

    #endregion
}
