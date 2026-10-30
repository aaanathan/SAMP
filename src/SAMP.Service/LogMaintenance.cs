using SAMP.Core;
using SAMP.Logging;

namespace SAMP.Service;

/// <summary>Daily/hourly chores: anchor, replicate closed files to the external location, prune past 30 days.</summary>
public sealed class LogMaintenance(DeviceLog log, ISettingsStore settings)
{
    public string? ExternalPath => string.IsNullOrWhiteSpace(settings.Get(SettingKeys.ExternalLogPath)) ? null : settings.Get(SettingKeys.ExternalLogPath);

    public void Run()
    {
        log.WriteAnchor();
        var ext = ExternalPath;
        if (ext != null)
        {
            try { log.Replicate(ext); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                log.Append("log.replicate_failed", new { path = ext, error = e.Message });
            }
        }
        // With an external location configured, a day file is only deleted once an identical copy exists there.
        log.Prune(ext == null ? null : day => log.IsReplicated(ext, day));
    }
}
