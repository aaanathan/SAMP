using SAMP.Core;

namespace SAMP.Usb;

/// <summary>
/// Owns the unblock window. Fail-secure: any inconsistency (expiry, clock rollback, drift) leads to Blocked.
/// Driven by the watchdog (<see cref="Tick"/> every ~30 s) and <see cref="Reconcile"/> at start/resume.
/// </summary>
public sealed class UnblockManager
{
    public const int DefaultMinutes = 120;
    public const int MinMinutes = 5;
    public const int DefaultMaxMinutes = 1440;
    private static readonly TimeSpan ClockTolerance = TimeSpan.FromMinutes(2);

    private readonly IUnblockSessionStore _sessions;
    private readonly IBlockRuleStore _rules;
    private readonly IUsbBlocker _blocker;
    private readonly IDeviceController _devices;
    private readonly ISettingsStore _settings;
    private readonly IAuditLog _audit;
    private readonly IClock _clock;
    private readonly object _lock = new();
    private DateTime? _lastTickWall;

    public UnblockManager(IUnblockSessionStore sessions, IBlockRuleStore rules, IUsbBlocker blocker, IDeviceController devices,
        ISettingsStore settings, IAuditLog audit, IClock clock)
    {
        _sessions = sessions; _rules = rules; _blocker = blocker; _devices = devices;
        _settings = settings; _audit = audit; _clock = clock;
    }

    // ---- settings --------------------------------------------------------------------------------

    public int GetMaxMinutes() => ReadInt(SettingKeys.MaxUnblockMinutes, DefaultMaxMinutes);

    public int GetDurationMinutes() => Math.Min(ReadInt(SettingKeys.UnblockDurationMinutes, DefaultMinutes), GetMaxMinutes());

    /// <summary>Admin only. Applies to new sessions; optionally caps the running one (never extends it).</summary>
    public void SetDuration(long actingUserId, Role role, int minutes, bool applyToCurrentSession = false)
    {
        RequireAdmin(role);
        if (minutes < MinMinutes || minutes > GetMaxMinutes())
            throw new ArgumentOutOfRangeException(nameof(minutes), $"Duration must be between {MinMinutes} and {GetMaxMinutes()} minutes.");
        lock (_lock)
        {
            var old = GetDurationMinutes();
            _settings.Set(SettingKeys.UnblockDurationMinutes, minutes.ToString());
            _audit.Append(actingUserId, "settings.unblock_duration", $"{old} -> {minutes} min");
            if (applyToCurrentSession && _sessions.GetActive() is { } a)
            {
                var capped = a.UnblockedAtUtc.AddMinutes(minutes);
                if (capped < a.ExpiresAtUtc) _sessions.SetExpiry(a.Id, capped);
            }
        }
    }

    public void SetMaxMinutes(long actingUserId, Role role, int minutes)
    {
        RequireAdmin(role);
        if (minutes < MinMinutes || minutes > 24 * 60) throw new ArgumentOutOfRangeException(nameof(minutes));
        _settings.Set(SettingKeys.MaxUnblockMinutes, minutes.ToString());
        if (GetDurationMinutes() > minutes) _settings.Set(SettingKeys.UnblockDurationMinutes, minutes.ToString());
        _audit.Append(actingUserId, "settings.max_unblock", $"{minutes} min");
    }

    // ---- commands --------------------------------------------------------------------------------

    public UnblockSession Unblock(long userId, Role role, int? requestedMinutes = null)
    {
        if (role < Role.Operator) throw new UnauthorizedAccessException("Operator role required.");
        lock (_lock)
        {
            var now = _clock.UtcNow;
            if (_sessions.GetActive() is { } active && now < active.ExpiresAtUtc)
                throw new InvalidOperationException("USB storage is already unblocked. Block it first to start a new window.");

            var configured = GetDurationMinutes();
            var minutes = requestedMinutes ?? configured;
            var limit = role == Role.Admin ? GetMaxMinutes() : configured;
            if (minutes < MinMinutes || minutes > limit)
                throw new ArgumentOutOfRangeException(nameof(requestedMinutes), $"Duration must be between {MinMinutes} and {limit} minutes.");

            var s = new UnblockSession
            {
                UserId = userId,
                UnblockedAtUtc = now,
                ExpiresAtUtc = now.AddMinutes(minutes),
                LastSeenUtc = now,
            };
            s.Id = _sessions.Add(s);
            try
            {
                ApplyState(globalBlocked: false);
            }
            catch
            {
                _sessions.End(s.Id, now, "apply_failed");
                TryBlock();
                throw;
            }
            _lastTickWall = now;
            _audit.Append(userId, "usb.unblock", $"{minutes} min, expires {s.ExpiresAtUtc:O}");
            return s;
        }
    }

    public void BlockNow(long? userId, string reason = "manual")
    {
        lock (_lock)
        {
            if (_sessions.GetActive() is { } a) _sessions.End(a.Id, _clock.UtcNow, reason);
            ApplyState(globalBlocked: true);
            _audit.Append(userId, "usb.block", reason);
        }
    }

    /// <summary>Watchdog tick: expiry, clock rollback, and policy drift.</summary>
    public void Tick()
    {
        lock (_lock)
        {
            var now = _clock.UtcNow;
            var active = _sessions.GetActive();
            var rolledBack = _lastTickWall is { } last && now < last - ClockTolerance;

            if (active != null)
            {
                if (rolledBack || now < active.LastSeenUtc - ClockTolerance)
                    EndAndBlock(active, now, "tamper_clock", "tamper.clock_rollback", $"now={now:O}");
                else if (now >= active.ExpiresAtUtc)
                    EndAndBlock(active, now, "expired", "usb.autoblock", $"expired {active.ExpiresAtUtc:O}");
                else
                    _sessions.Touch(active.Id, now);
            }
            else if (!SafeIsGloballyBlocked())
            {
                ApplyState(globalBlocked: true);
                _audit.Append(null, "tamper.drift", "USB policy was unblocked without an active session; re-blocked");
            }
            _lastTickWall = now;
        }
    }

    /// <summary>On service start / resume: re-derive state from the persisted session and assert it.</summary>
    public void Reconcile()
    {
        lock (_lock)
        {
            var now = _clock.UtcNow;
            var active = _sessions.GetActive();
            if (active == null)
            {
                ApplyState(globalBlocked: true);
            }
            else if (now < active.LastSeenUtc - ClockTolerance)
            {
                EndAndBlock(active, now, "tamper_clock", "tamper.clock_rollback", $"at reconcile now={now:O}");
            }
            else if (now >= active.ExpiresAtUtc)
            {
                EndAndBlock(active, now, "expired", "usb.autoblock", "expired while service was not running");
            }
            else
            {
                ApplyState(globalBlocked: false);
                _sessions.Touch(active.Id, now);
                _audit.Append(null, "service.reconcile", $"session {active.Id} resumed, expires {active.ExpiresAtUtc:O}");
            }
            _lastTickWall = now;
        }
    }

    /// <summary>Re-applies policy after rules change.</summary>
    public void ReapplyRules()
    {
        lock (_lock) ApplyState(IsGloballyBlockedNow());
    }

    public UnblockStatus GetStatus()
    {
        lock (_lock)
        {
            var now = _clock.UtcNow;
            if (_sessions.GetActive() is { } a && now < a.ExpiresAtUtc)
                return new UnblockStatus(false, a.Id, a.ExpiresAtUtc, a.ExpiresAtUtc - now, a.UserId);
            return new UnblockStatus(true, null, null, null);
        }
    }

    /// <summary>Decision for a device that just arrived (hot-plug).</summary>
    public DeviceEvaluation EvaluateDevice(DeviceInfo device)
    {
        lock (_lock) return RuleEvaluator.Evaluate(device, _rules.List(), IsGloballyBlockedNow());
    }

    // ---- internals -------------------------------------------------------------------------------

    /// <summary>If the OS state cannot be read, assume it is not blocked so the policy is re-applied (fail-secure).</summary>
    private bool SafeIsGloballyBlocked()
    {
        try { return _blocker.IsGloballyBlocked(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private bool IsGloballyBlockedNow() =>
        !(_sessions.GetActive() is { } a && _clock.UtcNow < a.ExpiresAtUtc);

    private void EndAndBlock(UnblockSession s, DateTime now, string endReason, string auditAction, string details)
    {
        _sessions.End(s.Id, now, endReason);
        ApplyState(globalBlocked: true);
        _audit.Append(null, auditAction, details);
    }

    private void ApplyState(bool globalBlocked)
    {
        var rules = _rules.List();
        _blocker.Apply(globalBlocked, rules);
        foreach (var d in _devices.Enumerate())
        {
            if (d.InstanceId == null) continue;
            var wantEnabled = RuleEvaluator.Evaluate(d, rules, globalBlocked).Decision == DeviceDecision.Allow;
            if (wantEnabled != d.Enabled) _devices.SetEnabled(d.InstanceId, wantEnabled);
        }
    }

    private void TryBlock()
    {
        try { ApplyState(globalBlocked: true); } catch { /* best effort; watchdog will retry */ }
    }

    private int ReadInt(string key, int fallback) =>
        int.TryParse(_settings.Get(key), out var v) && v > 0 ? v : fallback;

    private static void RequireAdmin(Role role)
    {
        if (role != Role.Admin) throw new UnauthorizedAccessException("Admin role required.");
    }
}
