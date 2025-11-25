using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace EntraTokenRevocationGUI.Models;

/// <summary>
/// Represents a user account with risky password configuration
/// </summary>
public class RiskyAccountViewModel : INotifyPropertyChanged
{
    private bool _isSelected;
    
    public string? Id { get; set; }
    public string? DisplayName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? Department { get; set; }
    public bool AccountEnabled { get; set; }
    public DateTimeOffset? LastPasswordChangeDateTime { get; set; }
    public string? RiskReason { get; set; }
    public RiskSeverity Severity { get; set; }
    
    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            _isSelected = value;
            OnPropertyChanged();
        }
    }
    
    /// <summary>
    /// Formatted display of password last set date
    /// </summary>
    public string PasswordLastSetDisplay
    {
        get
        {
            if (LastPasswordChangeDateTime == null)
                return "Never Set";
            
            // Check for Windows epoch (1601-01-01) which indicates never set
            if (LastPasswordChangeDateTime.Value.Year == 1601)
                return "Never Set (1601 Epoch)";
            
            return LastPasswordChangeDateTime.Value.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
        }
    }
    
    /// <summary>
    /// Formatted display of account status
    /// </summary>
    public string AccountStatusDisplay => AccountEnabled ? "Enabled" : "Disabled";
    
    /// <summary>
    /// Color indicator based on severity
    /// </summary>
    public string SeverityColor => Severity switch
    {
        RiskSeverity.Critical => "#DC2626",
        RiskSeverity.High => "#EA580C",
        RiskSeverity.Medium => "#CA8A04",
        RiskSeverity.Low => "#2563EB",
        _ => "#6B7280"
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public enum RiskSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Result of risky account scan
/// </summary>
public class RiskyAccountScanResult
{
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public int TotalUsersScanned { get; set; }
    public int RiskyAccountsFound { get; set; }
    public List<RiskyAccountViewModel> RiskyAccounts { get; set; } = new();
    public DateTime ScanTime { get; set; } = DateTime.Now;
}
