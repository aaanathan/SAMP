using System.Diagnostics;
using System.Runtime.Versioning;

namespace SAMP.Logging;

/// <summary>
/// Writes chain-head anchors to the Windows Application event log (source "SAMP"), a store a standard user cannot edit.
/// UNVERIFIED on real Windows: needs the service (SYSTEM) to create the event source once.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogAnchorSink : IAnchorSink
{
    public const string Source = "SAMP";
    public const int AnchorEventId = 4100;

    public EventLogAnchorSink()
    {
        if (!EventLog.SourceExists(Source)) EventLog.CreateEventSource(Source, "Application");
    }

    public void Write(string line) => EventLog.WriteEntry(Source, line, EventLogEntryType.Information, AnchorEventId);

    public IReadOnlyList<string> ReadAll()
    {
        var lines = new List<string>();
        using var log = new EventLog("Application");
        foreach (EventLogEntry e in log.Entries)
            if (e.Source == Source && (e.InstanceId & 0xFFFF) == AnchorEventId) lines.Add(e.Message);
        return lines;
    }
}
