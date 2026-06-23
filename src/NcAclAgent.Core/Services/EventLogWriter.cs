using Microsoft.Extensions.Options;
using NcAclAgent.Core.Interfaces;
using NcAclAgent.Core.Models;

namespace NcAclAgent.Core.Services;

public class WindowsEventLogWriter : IEventLogWriter
{
    private readonly EventLogConfig _config;

    public WindowsEventLogWriter(IOptions<AgentConfiguration> config)
    {
        _config = config.Value.EventLog;

#if WINDOWS
        if (!System.Diagnostics.EventLog.SourceExists(_config.Source))
            System.Diagnostics.EventLog.CreateEventSource(_config.Source, _config.LogName);
#endif
    }

    public void WriteInformation(int eventId, string message) => Write("INFO",  eventId, message);
    public void WriteWarning    (int eventId, string message) => Write("WARN",  eventId, message);
    public void WriteError      (int eventId, string message) => Write("ERROR", eventId, message);

    private void Write(string level, int eventId, string message)
    {
#if WINDOWS
        try
        {
            var type = level switch
            {
                "WARN"  => System.Diagnostics.EventLogEntryType.Warning,
                "ERROR" => System.Diagnostics.EventLogEntryType.Error,
                _       => System.Diagnostics.EventLogEntryType.Information
            };
            var truncated = message.Length > 32700 ? message[..32700] + "...[truncated]" : message;
            using var log = new System.Diagnostics.EventLog(_config.LogName) { Source = _config.Source };
            log.WriteEntry(truncated, type, eventId);
        }
        catch { /* не падаем если Event Log недоступен */ }
#else
        // Fallback для Linux (CI/тесты) — пишем в консоль
        Console.WriteLine($"[{level}] EventID={eventId} | {message}");
#endif
    }
}
