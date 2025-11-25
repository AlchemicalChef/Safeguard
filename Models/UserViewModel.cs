using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace EntraTokenRevocationGUI.Models;

public class UserViewModel : INotifyPropertyChanged
{
    private bool _isVisible = true;

    public string? Id { get; set; }
    public string? DisplayName { get; set; }
    public string? UserPrincipalName { get; set; }
    public string? Department { get; set; }
    public bool AccountEnabled { get; set; }

    public bool IsVisible
    {
        get => _isVisible;
        set
        {
            _isVisible = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
