using SAMP.Core;
using SAMP.Logging;
using SAMP.Ipc;
using System.Text.Json;

namespace SAMP.Service;

/// <summary>Limits failed sign-ins across all accounts (including unknown usernames) to blunt online guessing.</summary>
public sealed class LoginThrottle(IClock clock, int maxFailures = 10, TimeSpan? window = null, TimeSpan? cooldown = null)
{
    private readonly TimeSpan _window = window ?? TimeSpan.FromMinutes(1);
    private readonly TimeSpan _cooldown = cooldown ?? TimeSpan.FromSeconds(30);
    private readonly Queue<DateTime> _failures = new();
    private DateTime? _blockedUntil;
    private readonly object _lock = new();

    public bool IsBlocked(out DateTime? until)
    {
        lock (_lock)
        {
            if (_blockedUntil is { } b && b > clock.UtcNow) { until = b; return true; }
            until = null;
            return false;
        }
    }

    public void RecordFailure()
    {
        lock (_lock)
        {
            var now = clock.UtcNow;
            _failures.Enqueue(now);
            while (_failures.Count > 0 && now - _failures.Peek() > _window) _failures.Dequeue();
            if (_failures.Count >= maxFailures)
            {
                _blockedUntil = now + _cooldown;
                _failures.Clear();
            }
        }
    }
}

/// <summary>
/// Periodic integrity verification of the device log and the audit log. A failure raises a persistent alert that an
/// Admin must acknowledge; the same unchanged damage does not re-alert after acknowledgement.
/// </summary>
public sealed class IntegrityMonitor(DeviceLog deviceLog, IAuditLog audit, ISettingsStore settings)
{
    private const string CurrentKey = "integrity.current";
    private const string AckKey = "integrity.ack";

    public bool IsAlerting
    {
        get
        {
            var cur = settings.Get(CurrentKey);
            return !string.IsNullOrEmpty(cur) && cur != settings.Get(AckKey);
        }
    }

    public string? Details => string.IsNullOrEmpty(settings.Get(CurrentKey)) ? null : settings.Get(CurrentKey);

    public void Check()
    {
        var problems = new List<string>();
        var dl = deviceLog.Verify();
        if (!dl.IsValid) problems.Add($"devicelog@{dl.FirstBrokenSeq}: {dl.Reason}");
        var au = audit.Verify();
        if (!au.IsValid) problems.Add($"audit@{au.FirstBrokenId}: {au.Reason}");

        var signature = string.Join(" | ", problems);
        var previous = settings.Get(CurrentKey) ?? "";
        if (signature == previous) return;

        settings.Set(CurrentKey, signature);
        if (signature.Length > 0)
        {
            try { deviceLog.Append("integrity.failed", new { problems }); } catch (Exception e) when (e is IOException or InvalidOperationException) { }
            audit.Append(null, "integrity.failed", signature);
        }
        else
        {
            audit.Append(null, "integrity.recovered");
        }
    }

    public void Acknowledge(long adminUserId)
    {
        settings.Set(AckKey, settings.Get(CurrentKey) ?? "");
        audit.Append(adminUserId, "integrity.acknowledged", settings.Get(CurrentKey));
    }
}

public static class StartupChecks
{
    /// <summary>
    /// Records service start; when the previous run did not end with a clean "service.stop" (crash, kill, power loss,
    /// or the service being stopped by force) that is logged as its own event.
    /// </summary>
    public static void RecordStart(DeviceLog log)
    {
        var last = log.LastRecord();
        if (last != null && last.EventType != "service.stop")
            log.Append("service.unclean_shutdown", new { lastEvent = last.EventType, lastTimestampUtc = last.TimestampUtc });
        log.Append("service.start");
    }
}

/// <summary>
/// Service access control. SYSTEM keeps full control; Administrators and interactive users may only query the service,
/// so the Services console / <c>sc stop</c> / <c>net stop</c> are refused for them. The installer (running as SYSTEM)
/// can still stop, upgrade and remove it. A determined local administrator can still take ownership of the service key.
/// </summary>
public static class ServiceSecurity
{
    // CC query config, LC query status, SW enumerate dependents, LO interrogate, CR user-defined control, RC read control
    // RP start, WP stop, DT pause/continue, DC change config, SD delete, WD change DACL, WO change owner
    public const string RestrictedSddl =
        "D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" +   // LocalSystem: everything
        "(A;;CCLCSWLOCRRC;;;BA)" +                   // Administrators: read-only
        "(A;;CCLCSWLOCRRC;;;IU)";                    // interactive users: read-only

    /// <summary>Used only during an authorised maintenance window so the (non-SYSTEM) Inno Setup process can stop, replace and remove the services.</summary>
    public const string RelaxedSddl =
        "D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)" +
        "(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
        "(A;;CCLCSWLOCRRC;;;IU)";

    /// <summary>Applies the restricted (default) or relaxed descriptor with <c>sc sdset</c>. Windows only.</summary>
    public static void Apply(string serviceName, bool restricted = true)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("sc.exe")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        psi.ArgumentList.Add("sdset");
        psi.ArgumentList.Add(serviceName);
        psi.ArgumentList.Add(restricted ? RestrictedSddl : RelaxedSddl);
        using var p = System.Diagnostics.Process.Start(psi) ?? throw new InvalidOperationException("Could not start sc.exe.");
        p.WaitForExit(15_000);
        if (!p.HasExited || p.ExitCode != 0)
            throw new InvalidOperationException($"sc sdset failed ({p.ExitCode}): {p.StandardOutput.ReadToEnd()}");
    }
}


/// <summary>
/// A short, password-gated window in which the service lets Administrators stop and replace it (upgrade/uninstall by
/// the Inno Setup program, which does not run as SYSTEM). It closes by itself, and a service restart re-applies the
/// restricted descriptor.
/// </summary>
public sealed class MaintenanceWindow(IClock clock, Action<bool> applyRestricted, TimeSpan? duration = null)
{
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromMinutes(15);
    private readonly TimeSpan _duration = duration ?? DefaultDuration;
    private readonly object _lock = new();
    private DateTime? _until;

    public bool IsOpen
    {
        get { lock (_lock) return _until is { } u && clock.UtcNow < u; }
    }

    public DateTime? OpenUntilUtc
    {
        get { lock (_lock) return _until; }
    }

    public void Begin()
    {
        lock (_lock)
        {
            applyRestricted(false);
            _until = clock.UtcNow + _duration;
        }
    }

    /// <summary>Called by the watchdog; closes an expired window.</summary>
    public void Tick()
    {
        lock (_lock)
        {
            if (_until is { } u && clock.UtcNow >= u)
            {
                applyRestricted(true);
                _until = null;
            }
        }
    }
}
