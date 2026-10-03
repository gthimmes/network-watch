using System.Collections.Concurrent;

namespace NetworkWatch.Service;

/// <summary>Minimal daily-rolling file logger (logs\service-yyyyMMdd.log). Readable by non-admin users.</summary>
public sealed class FileLoggerProvider(string directory, LogLevel minLevel = LogLevel.Information) : ILoggerProvider
{
    private readonly ConcurrentDictionary<string, FileLogger> _loggers = new();
    private readonly Lock _lock = new();

    public ILogger CreateLogger(string categoryName) => _loggers.GetOrAdd(categoryName, name => new FileLogger(this, name));

    public void Dispose() { }

    private void Write(string category, LogLevel level, string message, Exception? exception)
    {
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [{Short(level)}] {ShortCategory(category)}: {message}";
        if (exception is not null) line += Environment.NewLine + exception;
        lock (_lock)
        {
            try { File.AppendAllText(Path.Combine(directory, $"service-{DateTime.Now:yyyyMMdd}.log"), line + Environment.NewLine); }
            catch (IOException) { }
        }
    }

    public static void DeleteOldLogs(string directory, TimeSpan maxAge)
    {
        foreach (var file in Directory.EnumerateFiles(directory, "service-*.log"))
            if (DateTime.Now - File.GetLastWriteTime(file) > maxAge)
                File.Delete(file);
    }

    private static string Short(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC", LogLevel.Debug => "DBG", LogLevel.Information => "INF",
        LogLevel.Warning => "WRN", LogLevel.Error => "ERR", _ => "CRT",
    };

    private static string ShortCategory(string category) => category[(category.LastIndexOf('.') + 1)..];

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= provider._minLevel && logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel)) provider.Write(category, logLevel, formatter(state, exception), exception);
        }
    }

    private readonly LogLevel _minLevel = minLevel;
}
