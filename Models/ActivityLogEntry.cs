using System;
using Avalonia.Media;

namespace Safeguard.Models;

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
    public ISolidColorBrush LevelColor { get; set; } = Brushes.Gray;
}
