using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace Safeguard.Infrastructure;

/// <summary>
/// Configures application logging with Serilog.
/// </summary>
public static class LoggingConfiguration
{
    private static ILoggerFactory? _loggerFactory;
    private static bool _isInitialized;

    /// <summary>
    /// Initializes the logging infrastructure.
    /// Should be called once at application startup.
    /// </summary>
    public static void Initialize(bool enableConsole = false)
    {
        if (_isInitialized)
            return;

        var logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Safeguard",
            "logs");

        Directory.CreateDirectory(logDirectory);

        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "Safeguard")
            .WriteTo.File(
                Path.Combine(logDirectory, "safeguard-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{SourceContext}] {Message:lj} {Properties:j}{NewLine}{Exception}");

        if (enableConsole)
        {
            loggerConfig.WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}");
        }

        Log.Logger = loggerConfig.CreateLogger();

        _loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddSerilog(Log.Logger, dispose: false);
        });

        _isInitialized = true;
    }

    /// <summary>
    /// Gets a logger for the specified type.
    /// </summary>
    public static Microsoft.Extensions.Logging.ILogger<T> GetLogger<T>()
    {
        if (!_isInitialized)
            Initialize();

        return _loggerFactory!.CreateLogger<T>();
    }

    /// <summary>
    /// Gets a logger with the specified category name.
    /// </summary>
    public static Microsoft.Extensions.Logging.ILogger GetLogger(string categoryName)
    {
        if (!_isInitialized)
            Initialize();

        return _loggerFactory!.CreateLogger(categoryName);
    }

    /// <summary>
    /// Gets the logger factory for dependency injection.
    /// </summary>
    public static ILoggerFactory GetLoggerFactory()
    {
        if (!_isInitialized)
            Initialize();

        return _loggerFactory!;
    }

    /// <summary>
    /// Flushes any buffered log entries and shuts down logging.
    /// Should be called at application shutdown.
    /// </summary>
    public static void Shutdown()
    {
        Log.CloseAndFlush();
        _loggerFactory?.Dispose();
        _isInitialized = false;
    }

    /// <summary>
    /// Gets the path to the log directory.
    /// </summary>
    public static string GetLogDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Safeguard",
            "logs");
    }
}
