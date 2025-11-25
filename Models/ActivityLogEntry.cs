using System;
using System.Windows.Media;

namespace EntraTokenRevocationGUI.Models;

public enum LogLevel
{
    Info,
    Success,
    Warning,
    Error
}

public class ActivityLogEntry
{
    public DateTime Timestamp { get; set; }
    public string Message { get; set; } = string.Empty;
    public LogLevel Level { get; set; }
    public SolidColorBrush StatusColor { get; set; } = Brushes.Gray;
}
