using System.Diagnostics;

namespace DNSDiode;

public class EventLogWriter
{
    private const string EventLogSource = "DNSDiode";
    private const string EventLogName = "Application";

    public EventLogWriter()
    {
        try
        {
            if (!EventLog.SourceExists(EventLogSource))
            {
                EventLog.CreateEventSource(EventLogSource, EventLogName);
            }
        }
        catch
        {
            // Event log creation may fail if not running as administrator
            // We'll still try to write, which may also fail
        }
    }

    public void WriteInfo(string message)
    {
        try
        {
            EventLog.WriteEntry(EventLogSource, message, EventLogEntryType.Information);
        }
        catch
        {
            // Silently fail if event log writing is not available
        }
    }

    public void WriteWarning(string message)
    {
        try
        {
            EventLog.WriteEntry(EventLogSource, message, EventLogEntryType.Warning);
        }
        catch
        {
            // Silently fail if event log writing is not available
        }
    }

    public void WriteError(string message)
    {
        try
        {
            EventLog.WriteEntry(EventLogSource, message, EventLogEntryType.Error);
        }
        catch
        {
            // Silently fail if event log writing is not available
        }
    }
}

