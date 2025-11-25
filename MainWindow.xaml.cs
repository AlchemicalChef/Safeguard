using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using EntraTokenRevocationGUI.Models;
using EntraTokenRevocationGUI.Services;
using Microsoft.Graph.Models;
using Microsoft.Win32;
using System.Security;
using System.Text.RegularExpressions;

namespace EntraTokenRevocationGUI;

public partial class MainWindow : Window
{
    private AuthenticationService? _authService;
    private TokenRevocationService? _revocationService;
    private BackdoorDetectionService? _backdoorService;
    private RiskyAccountService? _riskyAccountService;
    private CancellationTokenSource? _cancellationTokenSource;
    private User? _selectedUserForRevocation;
    private string? _currentClientId;

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
        ActivityLogList.ItemsSource = _activityLog;
        UsersDataGrid.ItemsSource = _users;
        EnterpriseAppsDataGrid.ItemsSource = _enterpriseApps;
        FindingsListView.ItemsSource = _findings;
        RiskyAccountsListView.ItemsSource = _riskyAccounts;
        
        MassRevocationConfirmation.Checked += (s, e) => MassRevokeButton.IsEnabled = true;
        MassRevocationConfirmation.Unchecked += (s, e) => MassRevokeButton.IsEnabled = false;
        
        MfaResetConfirmation1.Checked += UpdateMfaResetButtonState;
        MfaResetConfirmation1.Unchecked += UpdateMfaResetButtonState;
        MfaResetConfirmation2.Checked += UpdateMfaResetButtonState;
        MfaResetConfirmation2.Unchecked += UpdateMfaResetButtonState;

        MassAppDeleteConfirmation.Checked += (s, e) => MassDeleteAppsButton.IsEnabled = true;
        MassAppDeleteConfirmation.Unchecked += (s, e) => MassDeleteAppsButton.IsEnabled = false;
        
        _throttleCountdownTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _throttleCountdownTimer.Tick += ThrottleCountdownTimer_Tick;
        
        AddLogEntry("Application started", LogLevel.Info);
    }

    private void OnThrottled(int retryAfterSeconds, string operation)
    {
        Dispatcher.Invoke(() =>
        {
            // Prevent alert spam - don't show if we showed one in the last 5 seconds
            if ((DateTime.Now - _lastThrottleAlert).TotalSeconds < 5)
                return;
            
            _lastThrottleAlert = DateTime.Now;
            _throttleSecondsRemaining = retryAfterSeconds;
            
            ThrottleAlertMessage.Text = $"Microsoft Graph API is throttling requests during '{operation}'. " +
                                        $"Operations will automatically retry after the cooldown period.";
            ThrottleCountdownText.Text = $"{retryAfterSeconds}s";
            ThrottleAlertBanner.Visibility = Visibility.Visible;
            
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
            ThrottleAlertBanner.Visibility = Visibility.Collapsed;
        }
        else
        {
            ThrottleCountdownText.Text = $"{_throttleSecondsRemaining}s";
        }
    }
    
    private void ThrottleDismissButton_Click(object sender, RoutedEventArgs e)
    {
        _throttleCountdownTimer?.Stop();
        ThrottleAlertBanner.Visibility = Visibility.Collapsed;
    }

    private void UpdateMfaResetButtonState(object sender, RoutedEventArgs e)
    {
        MassMfaResetButton.IsEnabled = 
            (MfaResetConfirmation1.IsChecked == true) && 
            (MfaResetConfirmation2.IsChecked == true);
    }

    #region Authentication

    private static SecureString GetSecurePassword(PasswordBox passwordBox)
    {
        var securePassword = new SecureString();
        foreach (char c in passwordBox.Password)
        {
            securePassword.AppendChar(c);
        }
        return securePassword;
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        var tenantId = TenantIdInput.Text.Trim();
        var clientId = ClientIdInput.Text.Trim();
        var username = UsernameInput.Text.Trim();
        
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
        ConnectionErrorPanel.Visibility = Visibility.Collapsed;

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
            
            // Using the updated method signature
            _authService.OnTokenRefreshed += (sender, expiresOn) => OnTokenRefreshed(expiresOn);
            
            AddLogEntry("Authenticating...", LogLevel.Info);
            UpdateStatus("Authenticating...");
            
            var result = await _authService.AuthenticateAsync(username, securePassword);

            if (result.Success)
            {
                _revocationService = new TokenRevocationService(_authService);
                _backdoorService = new BackdoorDetectionService(_authService);
                _riskyAccountService = new RiskyAccountService(_authService.GraphClient!);
                
                _revocationService.OnThrottled += OnThrottled;
                
                LoginPanel.Visibility = Visibility.Collapsed;
                MainPanel.Visibility = Visibility.Visible;
                
                AuthStatusIndicator.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#107C10"));
                AuthStatusText.Text = result.UserPrincipalName;
                AuthMethodText.Text = $"({result.AuthMethod})";
                SignOutButton.Visibility = Visibility.Visible;
                
                if (result.TokenExpiresOn.HasValue)
                {
                    UpdateTokenStatus(result.TokenExpiresOn.Value);
                }

                PasswordInput.Clear();
                
                UsernameInput.Clear();

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
            
            PasswordInput.Clear();
        }
    }


    private void ShowConnectionError(string message)
    {
        ConnectionErrorText.Text = message;
        ConnectionErrorPanel.Visibility = Visibility.Visible;
    }

    // Updated method signature to accept DateTimeOffset
    private void OnTokenRefreshed(DateTimeOffset expiresOn)
    {
        Dispatcher.Invoke(() =>
        {
            var remaining = expiresOn - DateTimeOffset.UtcNow;
            var color = remaining.TotalMinutes > 60 ? "#107C10" : // Green
                       remaining.TotalMinutes > 10 ? "#FF8C00" : "#D32F2F"; // Orange, Red
            
            if (FindName("TokenStatusText") is TextBlock tokenStatus)
            {
                tokenStatus.Text = $"Token: {remaining.TotalMinutes:F0}m remaining";
                tokenStatus.Foreground = new SolidColorBrush(
                    (Color)ColorConverter.ConvertFromString(color));
            }
            
            AddLogEntry("Token refreshed successfully", LogLevel.Info);
        });
    }

    private void UpdateTokenStatus(DateTimeOffset expiresOn)
    {
        var timeRemaining = expiresOn - DateTimeOffset.UtcNow;
        if (timeRemaining.TotalMinutes > 60)
        {
            TokenStatusText.Text = $"Token valid for {timeRemaining.Hours}h {timeRemaining.Minutes}m";
            TokenStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#107C10"));
        }
        else if (timeRemaining.TotalMinutes > 10)
        {
            TokenStatusText.Text = $"Token valid for {timeRemaining.Minutes}m";
            TokenStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FF8C00"));
        }
        else
        {
            TokenStatusText.Text = $"Token expires soon ({timeRemaining.Minutes}m)";
            TokenStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D32F2F"));
        }
    }

    #endregion

    #region Single User Revocation

    private async void LookupUserButton_Click(object sender, RoutedEventArgs e)
    {
        var userIdentifier = SingleUserInput.Text.Trim();
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
                UserInfoPanel.Visibility = Visibility.Visible;
                AddLogEntry($"Found user: {user.DisplayName}", LogLevel.Success);
            }
            else
            {
                UserInfoPanel.Visibility = Visibility.Collapsed;
                _selectedUserForRevocation = null;
                AddLogEntry($"User not found: {userIdentifier}", LogLevel.Warning);
                MessageBox.Show("User not found", "Lookup Result", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error looking up user: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Lookup Error", MessageBoxButton.OK, MessageBoxImage.Error);
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

    private async void RevokeSingleButton_Click(object sender, RoutedEventArgs e)
    {
        var userIdentifier = SingleUserInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(userIdentifier) || _revocationService == null)
            return;

        var confirmResult = MessageBox.Show(
            $"Are you sure you want to revoke all tokens for:\n\n{userIdentifier}\n\nThis will force the user to re-authenticate on all devices.",
            "Confirm Token Revocation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
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
        SingleResultPanel.Visibility = Visibility.Visible;
        SingleResultPanel.Background = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(success ? "#E8F5E9" : "#FFEBEE"));
        SingleResultIcon.Text = success ? "✓" : "✗";
        SingleResultIcon.Foreground = success 
            ? (SolidColorBrush)FindResource("SuccessBrush") 
            : (SolidColorBrush)FindResource("DangerBrush");
        SingleResultText.Text = message;
    }

    #endregion

    #region Mass Revocation

    private async void MassRevokeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_revocationService == null || _authService?.CurrentUserId == null)
            return;

        if (!int.TryParse(BatchSizeInput.Text, out var batchSize) || batchSize < 1 || batchSize > 100)
            batchSize = 50;

        if (!int.TryParse(DelayInput.Text, out var delay) || delay < 100 || delay > 10000)
            delay = 1000;

        var confirmResult = MessageBox.Show(
            "FINAL WARNING\n\nYou are about to revoke tokens for ALL users in your tenant (except yourself).\n\n" +
            "This action will:\n" +
            "• Force all users to re-authenticate\n" +
            "• Invalidate all active sessions\n" +
            "• Potentially disrupt ongoing work\n\n" +
            "Are you absolutely sure you want to proceed?",
            "Confirm Mass Token Revocation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        MassRevokeButton.IsEnabled = false;
        MassRevocationConfirmation.IsEnabled = false;
        MassProgressPanel.Visibility = Visibility.Visible;
        MassResultsPanel.Visibility = Visibility.Collapsed;

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
            MessageBox.Show($"Error: {ex.Message}", "Mass Revocation Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            MassRevokeButton.IsEnabled = true;
            MassRevocationConfirmation.IsEnabled = true;
            MassRevocationConfirmation.IsChecked = false;
            MassProgressPanel.Visibility = Visibility.Collapsed;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            UpdateStatus("Ready");
        }
    }

    private void OnMassRevocationProgress(int current, int total, string currentUser)
    {
        Dispatcher.Invoke(() =>
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
        MassResultsPanel.Visibility = Visibility.Visible;
        MassTotalCount.Text = result.TotalProcessed.ToString();
        MassSuccessCount.Text = result.SuccessCount.ToString();
        MassFailedCount.Text = result.FailureCount.ToString();
        MassDuration.Text = $"Completed in {result.Duration.TotalSeconds:F1} seconds";
    }

    #endregion

    #region Mass MFA Reset

    private async void MassMfaResetButton_Click(object sender, RoutedEventArgs e)
    {
        if (_revocationService == null || _authService?.CurrentUserId == null)
            return;

        if (!int.TryParse(MfaBatchSizeInput.Text, out var batchSize) || batchSize < 1 || batchSize > 50)
            batchSize = 20;

        if (!int.TryParse(MfaDelayInput.Text, out var delay) || delay < 500 || delay > 10000)
            delay = 2000;

        var confirmResult = MessageBox.Show(
            "FINAL WARNING - MASS MFA RESET\n\n" +
            "You are about to remove ALL authentication methods for ALL users in your tenant (except yourself).\n\n" +
            "This action will:\n" +
            "• Remove Microsoft Authenticator registrations\n" +
            "• Delete phone numbers used for SMS/Voice MFA\n" +
            "• Remove FIDO2 security keys\n" +
            "• Delete software OATH tokens\n" +
            "• Remove Windows Hello for Business registrations\n" +
            "• Delete email authentication methods\n" +
            "• Invalidate Temporary Access Passes\n\n" +
            "Users will need to re-register their MFA methods.\n\n" +
            "ARE YOU ABSOLUTELY SURE YOU WANT TO PROCEED?",
            "Confirm Mass MFA Reset",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        // Second confirmation
        var secondConfirm = MessageBox.Show(
            "SECOND CONFIRMATION REQUIRED\n\n" +
            "Type 'RESET MFA' in your mind and click Yes to confirm.\n\n" +
            "This is your last chance to cancel.",
            "Final Confirmation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Exclamation);

        if (secondConfirm != MessageBoxResult.Yes)
            return;

        MassMfaResetButton.IsEnabled = false;
        MfaResetConfirmation1.IsEnabled = false;
        MfaResetConfirmation2.IsEnabled = false;
        MfaProgressPanel.Visibility = Visibility.Visible;
        MfaResultsPanel.Visibility = Visibility.Collapsed;

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
            AddLogEntry($"Mass MFA reset completed. Success: {result.SuccessCount}, Failed: {result.FailureCount}, Methods removed: {result.TotalMethodsRemoved}", 
                result.FailureCount == 0 ? LogLevel.Success : LogLevel.Warning);
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("Mass MFA reset cancelled", LogLevel.Warning);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Mass MFA reset error: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Mass MFA Reset Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            MassMfaResetButton.IsEnabled = true;
            MfaResetConfirmation1.IsEnabled = true;
            MfaResetConfirmation2.IsEnabled = true;
            MfaResetConfirmation1.IsChecked = false;
            MfaResetConfirmation2.IsChecked = false;
            MfaProgressPanel.Visibility = Visibility.Collapsed;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            UpdateStatus("Ready");
        }
    }

    private void OnMfaResetProgress(int current, int total, string currentUser)
    {
        Dispatcher.Invoke(() =>
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
        MfaResultsPanel.Visibility = Visibility.Visible;
        MfaTotalCount.Text = result.TotalProcessed.ToString();
        MfaSuccessCount.Text = result.SuccessCount.ToString();
        MfaFailedCount.Text = result.FailureCount.ToString();
        MfaMethodsRemovedCount.Text = result.TotalMethodsRemoved.ToString();
        MfaDuration.Text = $"Completed in {result.Duration.TotalSeconds:F1} seconds";
    }

    #endregion

    #region Enterprise App Cleanup

    private async void LoadAppsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_revocationService == null || string.IsNullOrEmpty(_currentClientId))
            return;

        LoadAppsButton.IsEnabled = false;
        UpdateStatus("Loading enterprise applications...");
        AddLogEntry("Loading enterprise applications...", LogLevel.Info);

        try
        {
            _enterpriseApps.Clear();

            // Load current app info
            var currentAppInfo = await _revocationService.GetCurrentAppInfoAsync(_currentClientId);
            if (currentAppInfo != null)
            {
                CurrentAppName.Text = currentAppInfo.DisplayName ?? "Unknown";
                CurrentAppId.Text = $"App ID: {currentAppInfo.ApplicationId}";
            }

            // Load all enterprise apps (excluding current)
            var apps = await _revocationService.GetEnterpriseAppsAsync(_currentClientId, 200);

            foreach (var app in apps)
            {
                _enterpriseApps.Add(new EnterpriseAppViewModel
                {
                    ApplicationId = app.ApplicationId,
                    ServicePrincipalId = app.ServicePrincipalId,
                    DisplayName = app.DisplayName,
                    CreatedDateTime = app.CreatedDateTime,
                    IsSelected = false
                });
            }

            AddLogEntry($"Loaded {apps.Count} enterprise applications", LogLevel.Success);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error loading apps: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Load Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            LoadAppsButton.IsEnabled = true;
            UpdateStatus("Ready");
        }
    }

    private async void DeleteCurrentAppButton_Click(object sender, RoutedEventArgs e)
    {
        if (_revocationService == null || string.IsNullOrEmpty(_currentClientId))
            return;

        var confirmResult = MessageBox.Show(
            "WARNING: You are about to delete the application you are currently signed into!\n\n" +
            "This will:\n" +
            "• Remove your current authentication session\n" +
            "• Delete the app registration from your tenant\n" +
            "• Require you to create a new app to use this tool again\n\n" +
            "The app will be recoverable for 30 days.\n\n" +
            "Are you sure you want to proceed?",
            "Confirm Delete Current Application",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        // Second confirmation
        var secondConfirm = MessageBox.Show(
            "FINAL CONFIRMATION\n\n" +
            "After deletion, you will be signed out immediately.\n\n" +
            "Continue?",
            "Final Confirmation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Exclamation);

        if (secondConfirm != MessageBoxResult.Yes)
            return;

        DeleteCurrentAppButton.IsEnabled = false;
        UpdateStatus("Deleting current application...");
        AddLogEntry($"Deleting current application: {_currentClientId}", LogLevel.Warning);

        try
        {
            var result = await _revocationService.DeleteEnterpriseAppAsync(
                _currentClientId,
                DeleteAppRegistrationCheckbox.IsChecked == true);

            if (result.Success)
            {
                AddLogEntry($"Successfully deleted application: {result.DisplayName}", LogLevel.Success);
                MessageBox.Show(
                    "Application deleted successfully.\n\nYou will now be signed out.",
                    "Cleanup Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                
                // Sign out
                SignOutButton_Click(sender, e);
            }
            else
            {
                ShowAppDeleteResult(false, $"Failed: {result.ErrorMessage}");
                AddLogEntry($"Failed to delete application: {result.ErrorMessage}", LogLevel.Error);
            }
        }
        catch (Exception ex)
        {
            ShowAppDeleteResult(false, $"Error: {ex.Message}");
            AddLogEntry($"Error deleting application: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            DeleteCurrentAppButton.IsEnabled = true;
            UpdateStatus("Ready");
        }
    }

    private async void DeleteSingleAppButton_Click(object sender, RoutedEventArgs e)
    {
        var appId = AppIdToDeleteInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(appId) || _revocationService == null)
            return;

        if (appId == _currentClientId)
        {
            MessageBox.Show(
                "Cannot delete the current application using this method.\n\nUse the 'Delete This App' button above instead.",
                "Invalid Operation",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        var confirmResult = MessageBox.Show(
            $"Are you sure you want to delete the enterprise application?\n\n" +
            $"App ID: {appId}\n\n" +
            "The app will be recoverable for 30 days.",
            "Confirm Delete Application",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        UpdateStatus($"Deleting application {appId}...");
        AddLogEntry($"Deleting application: {appId}", LogLevel.Info);

        try
        {
            var result = await _revocationService.DeleteEnterpriseAppAsync(
                appId,
                DeleteAppRegistrationCheckbox.IsChecked == true);

            ShowAppDeleteResult(result.Success, result.Success
                ? $"Successfully deleted: {result.DisplayName ?? appId}"
                : $"Failed: {result.ErrorMessage}");

            AddLogEntry(result.Success
                ? $"Deleted application: {result.DisplayName ?? appId}"
                : $"Failed to delete: {result.ErrorMessage}",
                result.Success ? LogLevel.Success : LogLevel.Error);

            // Refresh the list if successful
            if (result.Success)
            {
                LoadAppsButton_Click(sender, e);
            }
        }
        catch (Exception ex)
        {
            ShowAppDeleteResult(false, $"Error: {ex.Message}");
            AddLogEntry($"Error deleting application: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            UpdateStatus("Ready");
        }
    }

    private void ShowAppDeleteResult(bool success, string message)
    {
        AppDeleteResultPanel.Visibility = Visibility.Visible;
        AppDeleteResultPanel.Background = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(success ? "#E8F5E9" : "#FFEBEE"));
        AppDeleteResultIcon.Text = success ? "✓" : "✗";
        AppDeleteResultIcon.Foreground = success 
            ? (SolidColorBrush)FindResource("SuccessBrush") 
            : (SolidColorBrush)FindResource("DangerBrush");
        AppDeleteResultText.Text = message;
    }

    private async void MassDeleteAppsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_revocationService == null || string.IsNullOrEmpty(_currentClientId))
            return;

        var selectedApps = _enterpriseApps.Where(a => a.IsSelected).ToList();
        if (selectedApps.Count == 0)
        {
            MessageBox.Show("Please select at least one application to delete.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirmResult = MessageBox.Show(
            $"You are about to delete {selectedApps.Count} enterprise application(s).\n\n" +
            "This action will:\n" +
            "• Remove service principals from your tenant\n" +
            (DeleteAppRegistrationCheckbox.IsChecked == true ? "• Delete associated app registrations\n" : "") +
            "• Apps are recoverable for 30 days\n\n" +
            "Are you sure you want to proceed?",
            "Confirm Mass Delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        MassDeleteAppsButton.IsEnabled = false;
        MassAppDeleteConfirmation.IsEnabled = false;
        AppCleanupProgressPanel.Visibility = Visibility.Visible;
        AppCleanupResultsPanel.Visibility = Visibility.Collapsed;

        _cancellationTokenSource = new CancellationTokenSource();

        AddLogEntry($"Starting mass application cleanup for {selectedApps.Count} apps...", LogLevel.Warning);
        UpdateStatus("Mass application cleanup in progress...");

        try
        {
            var appIds = selectedApps.Select(a => a.ApplicationId!).ToList();

            var result = await _revocationService.MassDeleteEnterpriseAppsAsync(
                _currentClientId,
                appIds,
                DeleteAppRegistrationCheckbox.IsChecked == true,
                500,
                OnAppCleanupProgress,
                _cancellationTokenSource.Token);

            ShowAppCleanupResults(result);
            AddLogEntry($"Mass cleanup completed. Success: {result.SuccessCount}, Failed: {result.FailureCount}",
                result.FailureCount == 0 ? LogLevel.Success : LogLevel.Warning);

            // Refresh the list
            LoadAppsButton_Click(sender, e);
        }
        catch (OperationCanceledException)
        {
            AddLogEntry("Mass cleanup cancelled", LogLevel.Warning);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Mass cleanup error: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Mass Cleanup Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            MassDeleteAppsButton.IsEnabled = true;
            MassAppDeleteConfirmation.IsEnabled = true;
            MassAppDeleteConfirmation.IsChecked = false;
            AppCleanupProgressPanel.Visibility = Visibility.Collapsed;
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            UpdateStatus("Ready");
        }
    }

    private void OnAppCleanupProgress(int current, int total, string currentApp)
    {
        Dispatcher.Invoke(() =>
        {
            var percent = (double)current / total * 100;
            AppCleanupProgressBar.Value = percent;
            AppCleanupProgressText.Text = $"Processing {current} of {total} apps...";
            AppCleanupProgressPercent.Text = $"{percent:F1}%";
            AppCleanupCurrentApp.Text = $"Current: {currentApp}";
        });
    }

    private void ShowAppCleanupResults(MassAppCleanupResult result)
    {
        AppCleanupResultsPanel.Visibility = Visibility.Visible;
        AppCleanupTotalCount.Text = result.TotalProcessed.ToString();
        AppCleanupSuccessCount.Text = result.SuccessCount.ToString();
        AppCleanupFailedCount.Text = result.FailureCount.ToString();
        AppRegsDeletedCount.Text = result.ApplicationsDeleted.ToString();
        AppCleanupDuration.Text = $"Completed in {result.Duration.TotalSeconds:F1} seconds";
    }

    #endregion

    #region Users Grid

    private async void LoadUsersButton_Click(object sender, RoutedEventArgs e)
    {
        if (_revocationService == null)
            return;

        UpdateStatus("Loading users...");
        AddLogEntry("Loading user directory...", LogLevel.Info);

        try
        {
            _users.Clear();
            var users = await _revocationService.GetUsersAsync(100);
            
            foreach (var user in users)
            {
                _users.Add(new UserViewModel
                {
                    Id = user.Id,
                    DisplayName = user.DisplayName,
                    UserPrincipalName = user.UserPrincipalName,
                    Department = user.Department,
                    AccountEnabled = user.AccountEnabled ?? false
                });
            }

            AddLogEntry($"Loaded {users.Count} users", LogLevel.Success);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error loading users: {ex.Message}", LogLevel.Error);
        }
        finally
        {
            UpdateStatus("Ready");
        }
    }

    private void UserSearchInput_KeyUp(object sender, System.Windows.Input.KeyEventArgs e)
    {
        var searchText = UserSearchInput.Text.ToLower();
        
        if (string.IsNullOrWhiteSpace(searchText))
        {
            foreach (var user in _users)
                user.IsVisible = true;
        }
        else
        {
            foreach (var user in _users)
            {
                user.IsVisible = (user.DisplayName?.ToLower().Contains(searchText) ?? false) ||
                                 (user.UserPrincipalName?.ToLower().Contains(searchText) ?? false);
            }
        }

        UsersDataGrid.Items.Refresh();
    }

    private void UsersDataGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        // Selection handling if needed
    }

    private async void RevokeFromGridButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button button) return;
        if (button.DataContext is not UserViewModel user) return;
        if (_revocationService == null || string.IsNullOrEmpty(user.Id)) return;

        var confirmResult = MessageBox.Show(
            $"Revoke all tokens for:\n\n{user.DisplayName}\n({user.UserPrincipalName})",
            "Confirm Revocation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        AddLogEntry($"Revoking tokens for {user.UserPrincipalName}...", LogLevel.Info);

        try
        {
            var result = await _revocationService.RevokeUserTokensAsync(user.Id);
            
            AddLogEntry(result.Success 
                ? $"Revoked tokens for {user.UserPrincipalName}"
                : $"Failed: {result.ErrorMessage}",
                result.Success ? LogLevel.Success : LogLevel.Error);

            if (result.Success)
            {
                MessageBox.Show($"Successfully revoked tokens for {user.DisplayName}", "Success", 
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show($"Failed to revoke tokens: {result.ErrorMessage}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    #endregion

    #region Activity Log

    private void InitializeActivityLog()
    {
        // This method is not present in the original code, but if it were, its content would go here.
        // For now, it's a placeholder to acknowledge the marker in the updates.
    }

    private void AddLogEntry(string message, LogLevel level)
    {
        var entry = new ActivityLogEntry
        {
            Timestamp = DateTime.Now,
            Message = message,
            Level = level,
            StatusColor = level switch
            {
                LogLevel.Success => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#107C10")),
                LogLevel.Error => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D13438")),
                LogLevel.Warning => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFB900")),
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0078D4"))
            }
        };

        Dispatcher.Invoke(() =>
        {
            _activityLog.Insert(0, entry);
            
            // Keep only last 100 entries
            while (_activityLog.Count > 100)
                _activityLog.RemoveAt(_activityLog.Count - 1);
        });
    }

    private void ExportAuditLogButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
            DefaultExt = ".json",
            FileName = $"audit_log_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var entries = _activityLog.Select(entry => new
                {
                    entry.Timestamp,
                    // Redact email addresses and UPNs from log messages
                    Message = SanitizeLogMessage(entry.Message),
                    Level = entry.Level.ToString()
                });

                var json = System.Text.Json.JsonSerializer.Serialize(entries, new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true
                });

                System.IO.File.WriteAllText(dialog.FileName, json);
                AddLogEntry("Audit log exported", LogLevel.Success);
                MessageBox.Show("Audit log exported successfully", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception)
            {
                AddLogEntry("Failed to export audit log", LogLevel.Error);
                MessageBox.Show("Export failed. Please check file permissions.", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
    
    private static string SanitizeLogMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return message;
        
        // Regex to match email/UPN patterns
        var emailPattern = new Regex(
            @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            RegexOptions.Compiled);
        
        // Replace with redacted placeholder
        return emailPattern.Replace(message, "[REDACTED_UPN]");
    }

    private void ClearLogButton_Click(object sender, RoutedEventArgs e)
    {
        _activityLog.Clear();
        AddLogEntry("Log cleared", LogLevel.Info);
    }

    #endregion

    #region Backdoor Detection


    private async void RunBackdoorScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (_backdoorService == null)
            return;

        RunBackdoorScanButton.IsEnabled = false;
        BackdoorScanProgressPanel.Visibility = Visibility.Visible;
        BackdoorResultsPanel.Visibility = Visibility.Collapsed;
        FindingsHeader.Visibility = Visibility.Collapsed;
        FindingsListBorder.Visibility = Visibility.Collapsed;
        FindingDetailsPanel.Visibility = Visibility.Collapsed;
        _findings.Clear();


        AddLogEntry("Starting backdoor detection scan...", LogLevel.Warning);
        UpdateStatus("Running backdoor detection scan...");

        try
        {
            _lastScanResult = await _backdoorService.RunFullScanAsync(
                progress => Dispatcher.Invoke(() => BackdoorScanProgressText.Text = progress));

            // Display results
            DisplayScanResults(_lastScanResult);

            var criticalOrHigh = _lastScanResult.CriticalCount + _lastScanResult.HighCount;
            AddLogEntry(
                $"Backdoor scan complete. Found {_lastScanResult.TotalFindingsCount} findings ({_lastScanResult.CriticalCount} critical, {_lastScanResult.HighCount} high)",
                criticalOrHigh > 0 ? LogLevel.Error : LogLevel.Success);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Backdoor scan error: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Scan error: {ex.Message}", "Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RunBackdoorScanButton.IsEnabled = true;
            BackdoorScanProgressPanel.Visibility = Visibility.Collapsed;
            UpdateStatus("Ready");
        }
    }

    private void DisplayScanResults(BackdoorScanResult result)
    {
        BackdoorResultsPanel.Visibility = Visibility.Visible;

        CriticalFindingsCount.Text = result.CriticalCount.ToString();
        HighFindingsCount.Text = result.HighCount.ToString();
        MediumFindingsCount.Text = result.MediumCount.ToString();
        LowFindingsCount.Text = result.LowCount.ToString();
        InfoFindingsCount.Text = result.Findings.Count(f => f.Severity == SeverityLevel.Informational).ToString();

        BackdoorScanDuration.Text = $"Scan completed in {result.Duration.TotalSeconds:F1}s | " +
                                     $"Domains: {result.DomainsScanned}, Service Principals: {result.ServicePrincipalsScanned}, " +
                                     $"OAuth Grants: {result.OAuthGrantsScanned}, PTA Agents: {result.PTAAgentsScanned}";

        // Populate findings list
        _findings.Clear();
        foreach (var finding in result.Findings.OrderByDescending(f => f.Severity))
        {
            _findings.Add(new FindingViewModel
            {
                Id = finding.Id,
                Title = finding.Title,
                Description = finding.Description,
                Severity = finding.Severity,
                Type = finding.Type,
                TypeDisplay = GetTypeDisplayName(finding.Type),
                AffectedResource = finding.AffectedResource,
                ResourceId = finding.ResourceId,
                Recommendation = finding.Recommendation,
                MitreAttackTechnique = finding.MitreAttackTechnique,
                Details = finding.Details,
                SeverityColor = GetSeverityBrush(finding.Severity)
            });
        }

        if (_findings.Count > 0)
        {
            FindingsHeader.Visibility = Visibility.Visible;
            FindingsListBorder.Visibility = Visibility.Visible;
        }

        // Show errors if any
        if (result.Errors.Count > 0)
        {
            foreach (var error in result.Errors)
            {
                AddLogEntry($"Scan warning: {error}", LogLevel.Warning);
            }
        }
    }

    private static string GetTypeDisplayName(BackdoorType type)
    {
        return type switch
        {
            BackdoorType.FederatedDomainBackdoor => "Federation Backdoor",
            BackdoorType.PassThroughAuthenticationAgent => "PTA Agent",
            BackdoorType.SuspiciousServicePrincipal => "Suspicious App",
            BackdoorType.HighPrivilegeOAuthGrant => "OAuth Grant",
            BackdoorType.RecentDomainAuthenticationChange => "Domain Change",
            BackdoorType.SuspiciousAppRegistration => "App Registration",
            BackdoorType.AdminConsentGrant => "Admin Consent",
            BackdoorType.SuspiciousCredential => "App Credential",
            BackdoorType.UnknownPTAAgent => "Unknown PTA Agent",
            BackdoorType.FederationMfaBypass => "MFA Bypass",
            BackdoorType.SecondarySigningCertificate => "Secondary Signing Cert",
            BackdoorType.SuspiciousSigningCertificate => "Suspicious Signing Cert",
            _ => type.ToString()
        };
    }

    private static SolidColorBrush GetSeverityBrush(SeverityLevel severity)
    {
        return severity switch
        {
            SeverityLevel.Critical => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D32F2F")),
            SeverityLevel.High => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F57C00")),
            SeverityLevel.Medium => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FBC02D")),
            SeverityLevel.Low => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0078D4")),
            _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#757575"))
        };
    }

    private void FindingsListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FindingsListView.SelectedItem is not FindingViewModel finding)
        {
            FindingDetailsPanel.Visibility = Visibility.Collapsed;
            _selectedFinding = null;
            RevokeFederationPanel.Visibility = Visibility.Collapsed;
            MassRevokeFederationPanel.Visibility = Visibility.Collapsed;
            RemediationPanel.Visibility = Visibility.Collapsed;
            MassRemediateAllPanel.Visibility = Visibility.Collapsed;
            return;
        }

        _selectedFinding = finding;
        FindingDetailsPanel.Visibility = Visibility.Visible;

        // Set severity badge
        FindingSeverityBadge.Background = finding.SeverityColor;
        FindingSeverityText.Text = finding.Severity.ToString().ToUpper();

        // Set content
        FindingMitreTechnique.Text = finding.MitreAttackTechnique;
        FindingTitle.Text = finding.Title;
        FindingDescription.Text = finding.Description;
        FindingAffectedResource.Text = finding.AffectedResource ?? "N/A";
        FindingRecommendation.Text = finding.Recommendation;

        // Set details
        FindingDetailsList.ItemsSource = finding.Details?.ToList() ?? new List<KeyValuePair<string, string>>();

        RevokeFederationPanel.Visibility = Visibility.Collapsed;
        MassRevokeFederationPanel.Visibility = Visibility.Collapsed;
        RemediationPanel.Visibility = Visibility.Collapsed;
        MassRemediateAllPanel.Visibility = Visibility.Collapsed;
        ConfirmRemediationCheckbox.IsChecked = false;
        RemediateButton.IsEnabled = false;

        switch (finding.Type)
        {
            case BackdoorType.FederatedDomainBackdoor:
                RevokeFederationPanel.Visibility = Visibility.Visible;
                ConfirmRevokeFederationCheckbox.IsChecked = false;
                RevokeFederationButton.IsEnabled = false;
                ShowMassRemediationOptions();
                break;
                
            case BackdoorType.FederationMfaBypass:
                ShowRemediationPanel(
                    "FIX MFA BYPASS VULNERABILITY",
                    "This will set federatedIdpMfaBehavior to 'rejectMfaByFederatedIdp', ensuring Entra ID enforces MFA even when the federated IdP claims MFA was already performed. This prevents Golden SAML-style attacks.",
                    "I understand this will change federation MFA behavior and users may need to complete MFA again");
                ShowMassRemediationOptions();
                break;
                
            case BackdoorType.SecondarySigningCertificate:
                ShowRemediationPanel(
                    "REMOVE SECONDARY SIGNING CERTIFICATE",
                    "This will remove the secondary (next) signing certificate from the federation configuration. If this certificate was added by an attacker, removing it will prevent them from forging tokens.",
                    "I understand this will remove the secondary signing certificate");
                ShowMassRemediationOptions();
                break;
                
            case BackdoorType.SuspiciousSigningCertificate:
                ShowRemediationPanel(
                    "REVOKE SUSPICIOUS FEDERATION",
                    "The signing certificate has suspicious characteristics. This will remove the entire federation configuration for this domain, converting it to managed authentication.",
                    "I understand this will convert the domain to managed authentication");
                ShowMassRemediationOptions();
                break;
                
            case BackdoorType.SuspiciousServicePrincipal:
                ShowRemediationPanel(
                    "DELETE SUSPICIOUS SERVICE PRINCIPAL",
                    "This will permanently delete the suspicious service principal (enterprise application) from your tenant. All associated permissions and access will be revoked.",
                    "I understand this will permanently delete the application");
                ShowMassRemediationOptions();
                break;
                
            case BackdoorType.AdminConsentGrant:
                ShowRemediationPanel(
                    "REVOKE ADMIN CONSENT GRANT",
                    "This will revoke the admin consent grant, removing the application's ability to access resources on behalf of all users in the organization.",
                    "I understand this will revoke the admin consent");
                ShowMassRemediationOptions();
                break;
                
            default:
                // For non-remediatable types, still show mass remediation if there are remediatable findings
                ShowMassRemediationOptions();
                break;
        }
    }

    private void ShowRemediationPanel(string title, string description, string confirmText)
    {
        RemediationPanel.Visibility = Visibility.Visible;
        RemediationTitle.Text = title;
        RemediationDescription.Text = description;
        RemediationConfirmText.Text = confirmText;
        ConfirmRemediationCheckbox.IsChecked = false;
        RemediateButton.IsEnabled = false;
    }

    private void ShowMassRemediationOptions()
    {
        if (_lastScanResult == null) return;
        
        // Backdoor types that can be automatically remediated
        var remediableTypes = new[]
        {
            BackdoorType.FederatedDomainBackdoor,
            BackdoorType.FederationMfaBypass,
            BackdoorType.SecondarySigningCertificate,
            BackdoorType.SuspiciousSigningCertificate,
            BackdoorType.SuspiciousServicePrincipal,
            BackdoorType.AdminConsentGrant
        };
        
        var remediableCount = _lastScanResult.Findings.Count(f => remediableTypes.Contains(f.Type));
        var federationCount = _lastScanResult.Findings.Count(f => f.Type == BackdoorType.FederatedDomainBackdoor);
        
        // Show mass federation revoke panel if multiple federation backdoors
        if (federationCount > 1 && _selectedFinding?.Type == BackdoorType.FederatedDomainBackdoor)
        {
            MassRevokeFederationPanel.Visibility = Visibility.Visible;
            MassRevokeFederationCount.Text = $"Found {federationCount} federation backdoors that can be revoked.";
            ConfirmMassRevokeFederation1.IsChecked = false;
            ConfirmMassRevokeFederation2.IsChecked = false;
            MassRevokeFederationButton.IsEnabled = false;
        }
        
        // Show mass remediate all panel if multiple remediatable findings
        if (remediableCount > 1)
        {
            MassRemediateAllPanel.Visibility = Visibility.Visible;
            MassRemediateAllCount.Text = $"Found {remediableCount} backdoors that can be automatically remediated.";
            ConfirmMassRemediateAll1.IsChecked = false;
            ConfirmMassRemediateAll2.IsChecked = false;
            ConfirmMassRemediateAll3.IsChecked = false;
            MassRemediateAllButton.IsEnabled = false;
        }
    }

    private void ConfirmRemediationCheckbox_Changed(object sender, RoutedEventArgs e)
    {
        RemediateButton.IsEnabled = ConfirmRemediationCheckbox.IsChecked == true;
    }

    private void ConfirmMassRemediateAll_Changed(object sender, RoutedEventArgs e)
    {
        MassRemediateAllButton.IsEnabled = 
            ConfirmMassRemediateAll1.IsChecked == true && 
            ConfirmMassRemediateAll2.IsChecked == true &&
            ConfirmMassRemediateAll3.IsChecked == true;
    }

    private async void RemediateButton_Click(object sender, RoutedEventArgs e)
    {
        if (_backdoorService == null || _selectedFinding == null)
            return;

        var resourceName = _selectedFinding.AffectedResource ?? _selectedFinding.ResourceId ?? "Unknown";
        
        var confirm = MessageBox.Show(
            $"Are you sure you want to remediate this finding?\n\n" +
            $"Type: {_selectedFinding.Type}\n" +
            $"Resource: {resourceName}\n\n" +
            "This action may not be easily reversible.",
            "Confirm Remediation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
            return;

        RemediateButton.IsEnabled = false;
        RemediateButton.Content = "Remediating...";
        AddLogEntry($"Remediating {_selectedFinding.Type}: {resourceName}", LogLevel.Warning);
        UpdateStatus($"Remediating {resourceName}...");

        try
        {
            // Convert FindingViewModel to BackdoorFinding
            var finding = new BackdoorFinding
            {
                Type = _selectedFinding.Type,
                ResourceId = _selectedFinding.ResourceId,
                AffectedResource = _selectedFinding.AffectedResource,
                Details = _selectedFinding.Details ?? new Dictionary<string, string>()
            };

            var result = await _backdoorService.RemediateBackdoorAsync(finding);

            if (result.Success)
            {
                AddLogEntry($"Successfully remediated {_selectedFinding.Type}: {resourceName}", LogLevel.Success);
                MessageBox.Show(result.Message, "Remediation Successful", MessageBoxButton.OK, MessageBoxImage.Information);

                // Remove the finding from the list
                _findings.Remove(_selectedFinding);
                FindingDetailsPanel.Visibility = Visibility.Collapsed;
                RemediationPanel.Visibility = Visibility.Collapsed;
                
                // Update counts
                if (_lastScanResult != null)
                {
                    _lastScanResult.Findings.RemoveAll(f => 
                        f.Type == _selectedFinding.Type && 
                        (f.AffectedResource == resourceName || f.ResourceId == _selectedFinding.ResourceId));
                    _lastScanResult.CriticalCount = _lastScanResult.Findings.Count(f => f.Severity == SeverityLevel.Critical);
                    _lastScanResult.HighCount = _lastScanResult.Findings.Count(f => f.Severity == SeverityLevel.High);
                    DisplayScanResults(_lastScanResult);
                }
            }
            else
            {
                AddLogEntry($"Failed to remediate: {result.Message}", LogLevel.Error);
                MessageBox.Show($"Remediation failed:\n\n{result.Message}\n\n{result.ErrorDetails}", 
                    "Remediation Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error during remediation: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RemediateButton.IsEnabled = true;
            RemediateButton.Content = "Remediate";
            ConfirmRemediationCheckbox.IsChecked = false;
            UpdateStatus("Ready");
        }
    }

    private async void MassRemediateAllButton_Click(object sender, RoutedEventArgs e)
    {
        if (_backdoorService == null || _lastScanResult == null)
            return;

        var remediableTypes = new[]
        {
            BackdoorType.FederatedDomainBackdoor,
            BackdoorType.FederationMfaBypass,
            BackdoorType.SecondarySigningCertificate,
            BackdoorType.SuspiciousSigningCertificate,
            BackdoorType.SuspiciousServicePrincipal,
            BackdoorType.AdminConsentGrant
        };

        var remediableFindings = _lastScanResult.Findings
            .Where(f => remediableTypes.Contains(f.Type))
            .ToList();

        if (remediableFindings.Count == 0)
        {
            MessageBox.Show("No remediatable backdoors found.", "No Backdoors", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            "CRITICAL ACTION: Mass Remediate " + remediableFindings.Count + " Backdoor(s)\n\n" +
            "This will remediate ALL detected backdoors including:\n" +
            $"  • Federation backdoors: {remediableFindings.Count(f => f.Type == BackdoorType.FederatedDomainBackdoor)}\n" +
            $"  • MFA bypass configs: {remediableFindings.Count(f => f.Type == BackdoorType.FederationMfaBypass)}\n" +
            $"  • Secondary certificates: {remediableFindings.Count(f => f.Type == BackdoorType.SecondarySigningCertificate)}\n" +
            $"  • Suspicious certificates: {remediableFindings.Count(f => f.Type == BackdoorType.SuspiciousSigningCertificate)}\n" +
            $"  • Suspicious apps: {remediableFindings.Count(f => f.Type == BackdoorType.SuspiciousServicePrincipal)}\n" +
            $"  • Admin consent grants: {remediableFindings.Count(f => f.Type == BackdoorType.AdminConsentGrant)}\n\n" +
            "This is an INCIDENT RESPONSE action. Are you sure?",
            "Confirm Mass Remediation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
            return;

        // Second confirmation
        var secondConfirm = MessageBox.Show(
            "FINAL CONFIRMATION\n\n" +
            $"You are about to remediate {remediableFindings.Count} backdoor(s).\n\n" +
            "This action will modify your tenant configuration and cannot be easily undone.\n\n" +
            "Proceed with mass remediation?",
            "Final Confirmation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Stop);

        if (secondConfirm != MessageBoxResult.Yes)
            return;

        MassRemediateAllButton.IsEnabled = false;
        MassRemediateAllProgress.Visibility = Visibility.Visible;
        MassRemediateAllProgressBar.Maximum = remediableFindings.Count;
        MassRemediateAllProgressBar.Value = 0;

        AddLogEntry($"Starting mass remediation of {remediableFindings.Count} backdoors", LogLevel.Warning);
        UpdateStatus("Mass remediating backdoors...");

        try
        {
            var results = await _backdoorService.MassRemediateAllBackdoorsAsync(
                remediableFindings,
                (resourceName, current, total) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        MassRemediateAllProgressText.Text = $"Remediating {resourceName} ({current}/{total})...";
                        MassRemediateAllProgressBar.Value = current;
                    });
                });

            var successCount = results.Count(r => r.Success);
            var failCount = results.Count(r => !r.Success);

            AddLogEntry($"Mass remediation complete: {successCount} succeeded, {failCount} failed", 
                successCount > 0 ? LogLevel.Success : LogLevel.Error);

            // Remove successful remediations from findings
            foreach (var result in results.Where(r => r.Success))
            {
                var findingsToRemove = _findings.Where(f => 
                    f.ResourceId == result.DomainId || 
                    f.AffectedResource == result.DomainId).ToList();
                
                foreach (var finding in findingsToRemove)
                    _findings.Remove(finding);

                _lastScanResult.Findings.RemoveAll(f => 
                    f.ResourceId == result.DomainId || 
                    f.AffectedResource == result.DomainId);
            }

            // Update display
            _lastScanResult.CriticalCount = _lastScanResult.Findings.Count(f => f.Severity == SeverityLevel.Critical);
            _lastScanResult.HighCount = _lastScanResult.Findings.Count(f => f.Severity == SeverityLevel.High);
            _lastScanResult.MediumCount = _lastScanResult.Findings.Count(f => f.Severity == SeverityLevel.Medium);
            _lastScanResult.LowCount = _lastScanResult.Findings.Count(f => f.Severity == SeverityLevel.Low);
            DisplayScanResults(_lastScanResult);
            FindingDetailsPanel.Visibility = Visibility.Collapsed;

            var message = $"Mass Remediation Complete\n\n" +
                         $"Successful: {successCount}\n" +
                         $"Failed: {failCount}\n\n";
            
            if (failCount > 0)
            {
                message += "Failed items:\n" + 
                    string.Join("\n", results.Where(r => !r.Success).Take(10).Select(r => $"  • {r.DomainId}: {r.Message}"));
                if (failCount > 10)
                    message += $"\n  ... and {failCount - 10} more";
            }

            MessageBox.Show(message, "Mass Remediation Complete", MessageBoxButton.OK, 
                failCount > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error during mass remediation: {ex.Message}", LogLevel.Error);
            MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            MassRemediateAllButton.IsEnabled = true;
            MassRemediateAllProgress.Visibility = Visibility.Collapsed;
            ConfirmMassRemediateAll1.IsChecked = false;
            ConfirmMassRemediateAll2.IsChecked = false;
            ConfirmMassRemediateAll3.IsChecked = false;
            UpdateStatus("Ready");
        }
    }

    #endregion

    #region Risky Accounts
    
    private async void ScanRiskyAccountsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_riskyAccountService == null || _authService == null)
        {
            MessageBox.Show("Please connect to Entra ID first.", "Not Connected", 
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ScanRiskyAccountsButton.IsEnabled = false;
        ScanRiskyAccountsButton.Content = "Scanning...";
        RiskyAccountsScanStatus.Text = "Scanning users...";
        _riskyAccounts.Clear();
        RiskSummaryPanel.Visibility = Visibility.Collapsed;

        _cancellationTokenSource = new CancellationTokenSource();

        AddLogEntry("Starting risky account scan...", LogLevel.Info);
        UpdateStatus("Scanning for risky accounts...");

        try
        {
            var result = await _riskyAccountService.ScanForRiskyAccountsAsync(
                (scanned, found) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        RiskyAccountsScanStatus.Text = $"Scanned {scanned} users, found {found} risky accounts...";
                    });
                },
                _cancellationTokenSource.Token);

            if (result.Success)
            {
                foreach (var account in result.RiskyAccounts)
                {
                    _riskyAccounts.Add(account);
                }

                // Update summary panel
                RiskSummaryPanel.Visibility = Visibility.Visible;
                RiskyCriticalCount.Text = result.RiskyAccounts.Count(a => a.Severity == RiskSeverity.Critical).ToString();
                RiskyHighCount.Text = result.RiskyAccounts.Count(a => a.Severity == RiskSeverity.High).ToString();
                RiskyMediumCount.Text = result.RiskyAccounts.Count(a => a.Severity == RiskSeverity.Medium).ToString();
                RiskyTotalScanned.Text = result.TotalUsersScanned.ToString();

                RiskyAccountsScanStatus.Text = $"Found {result.RiskyAccountsFound} risky accounts out of {result.TotalUsersScanned} users";
                
                AddLogEntry($"Risky account scan complete. Found {result.RiskyAccountsFound} risky accounts.", 
                    result.RiskyAccountsFound > 0 ? LogLevel.Warning : LogLevel.Success);
            }
            else
            {
                RiskyAccountsScanStatus.Text = result.ErrorMessage ?? "Scan failed";
                AddLogEntry($"Risky account scan failed: {result.ErrorMessage}", LogLevel.Error);
            }
        }
        catch (OperationCanceledException)
        {
            RiskyAccountsScanStatus.Text = "Scan cancelled";
            AddLogEntry("Risky account scan cancelled", LogLevel.Warning);
        }
        catch (Exception ex)
        {
            RiskyAccountsScanStatus.Text = "Scan error";
            AddLogEntry($"Error during risky account scan: {ex.Message}", LogLevel.Error);
            MessageBox.Show("An error occurred during the scan.", "Scan Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanRiskyAccountsButton.IsEnabled = true;
            ScanRiskyAccountsButton.Content = "Scan for Risky Accounts";
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            UpdateStatus("Ready");
        }
    }

    private async void RemediateSelectedRiskyButton_Click(object sender, RoutedEventArgs e)
    {
        if (_riskyAccountService == null || _authService?.CurrentUserId == null)
            return;

        var selectedAccounts = _riskyAccounts.Where(a => a.IsSelected).ToList();
        if (!selectedAccounts.Any())
        {
            // If no checkboxes selected, use ListView selection
            selectedAccounts = RiskyAccountsListView.SelectedItems.Cast<RiskyAccountViewModel>().ToList();
        }

        if (!selectedAccounts.Any())
        {
            MessageBox.Show("Please select accounts to remediate.", "No Selection", 
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var forceReset = RiskyForcePasswordResetCheck.IsChecked == true;
        var disableAccount = RiskyDisableAccountCheck.IsChecked == true;

        if (!forceReset && !disableAccount)
        {
            MessageBox.Show("Please select at least one remediation action (force password reset or disable account).", 
                "No Action Selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var actionText = new List<string>();
        if (forceReset) actionText.Add("force password reset");
        if (disableAccount) actionText.Add("disable the account");

        var confirmResult = MessageBox.Show(
            $"You are about to {string.Join(" and ", actionText)} for {selectedAccounts.Count} account(s).\n\n" +
            "Your account is protected and will be skipped if included.\n\n" +
            "Do you want to proceed?",
            "Confirm Remediation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        RemediateSelectedRiskyButton.IsEnabled = false;
        AddLogEntry($"Remediating {selectedAccounts.Count} risky accounts...", LogLevel.Info);
        UpdateStatus("Remediating risky accounts...");

        try
        {
            var (succeeded, failed) = await _riskyAccountService.BulkRemediateAsync(
                selectedAccounts,
                forceReset,
                disableAccount,
                _authService.CurrentUserId,
                (current, total) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        RiskyAccountsScanStatus.Text = $"Remediating {current} of {total}...";
                    });
                });

            RiskyAccountsScanStatus.Text = $"Remediation complete. Success: {succeeded}, Failed: {failed}";
            AddLogEntry($"Risky account remediation complete. Success: {succeeded}, Failed: {failed}", 
                failed > 0 ? LogLevel.Warning : LogLevel.Success);

            // Refresh the list
            if (succeeded > 0)
            {
                MessageBox.Show(
                    $"Remediation Complete\n\nSuccessful: {succeeded}\nFailed: {failed}\n\n" +
                    "Click 'Scan for Risky Accounts' to refresh the list.",
                    "Remediation Complete",
                    MessageBoxButton.OK,
                    failed > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error during remediation: {ex.Message}", LogLevel.Error);
            MessageBox.Show("An error occurred during remediation.", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RemediateSelectedRiskyButton.IsEnabled = true;
            UpdateStatus("Ready");
        }
    }

    private async void RemediateAllCriticalButton_Click(object sender, RoutedEventArgs e)
    {
        if (_riskyAccountService == null || _authService?.CurrentUserId == null)
            return;

        var criticalAccounts = _riskyAccounts.Where(a => a.Severity == RiskSeverity.Critical).ToList();
        
        if (!criticalAccounts.Any())
        {
            MessageBox.Show("No critical risk accounts found.", "No Critical Accounts", 
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirmResult = MessageBox.Show(
            $"You are about to DISABLE {criticalAccounts.Count} critical risk account(s) and force password reset.\n\n" +
            "Critical accounts include those with:\n" +
            "• Password never set (1601 epoch) on enabled accounts\n" +
            "• Null password timestamp on enabled accounts\n\n" +
            "Your account is protected and will be skipped if included.\n\n" +
            "Do you want to proceed?",
            "Confirm Critical Account Remediation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmResult != MessageBoxResult.Yes)
            return;

        RemediateAllCriticalButton.IsEnabled = false;
        AddLogEntry($"Remediating {criticalAccounts.Count} critical risk accounts...", LogLevel.Warning);
        UpdateStatus("Remediating critical accounts...");

        try
        {
            var (succeeded, failed) = await _riskyAccountService.BulkRemediateAsync(
                criticalAccounts,
                forcePasswordReset: true,
                disableAccount: true,
                _authService.CurrentUserId,
                (current, total) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        RiskyAccountsScanStatus.Text = $"Remediating critical account {current} of {total}...";
                    });
                });

            RiskyAccountsScanStatus.Text = $"Critical remediation complete. Success: {succeeded}, Failed: {failed}";
            AddLogEntry($"Critical account remediation complete. Success: {succeeded}, Failed: {failed}", 
                failed > 0 ? LogLevel.Warning : LogLevel.Success);

            MessageBox.Show(
                $"Critical Account Remediation Complete\n\nDisabled and forced password reset:\nSuccessful: {succeeded}\nFailed: {failed}\n\n" +
                "Click 'Scan for Risky Accounts' to refresh the list.",
                "Remediation Complete",
                MessageBoxButton.OK,
                failed > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AddLogEntry($"Error during critical remediation: {ex.Message}", LogLevel.Error);
            MessageBox.Show("An error occurred during remediation.", "Error", 
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RemediateAllCriticalButton.IsEnabled = true;
            UpdateStatus("Ready");
        }
    }

    #endregion


    private void UpdateStatus(string message)
    {
        Dispatcher.Invoke(() => StatusText.Text = message);
    }
}

public class EnterpriseAppViewModel
{
    public string? ApplicationId { get; set; }
    public string? ServicePrincipalId { get; set; }
    public string? DisplayName { get; set; }
    public DateTime? CreatedDateTime { get; set; }
    public bool IsSelected { get; set; }
}

public class FindingViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public BackdoorType Type { get; set; }
    public string TypeDisplay { get; set; } = string.Empty;
    public string? AffectedResource { get; set; }
    public string? ResourceId { get; set; }
    public string Recommendation { get; set; } = string.Empty;
    public string MitreAttackTechnique { get; set; } = string.Empty;
    public Dictionary<string, string>? Details { get; set; }
    public SolidColorBrush SeverityColor { get; set; } = new SolidColorBrush(Colors.Gray);
}
