using System.Globalization;
using SAMP.Core;

namespace SAMP.Security;

public enum UninstallVerifyStatus { Ok, Wrong, Locked, NotSet }

public sealed record UninstallVerifyResult(UninstallVerifyStatus Status, DateTime? LockedUntilUtc = null);

/// <summary>
/// Single uninstall password, set at setup and changeable by Admins only.
/// Verification is called by the MSI uninstall guard through the service.
/// </summary>
public sealed class UninstallPasswordService
{
    public const int MaxFailedAttempts = 3;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly ISettingsStore _settings;
    private readonly IAuditLog _audit;
    private readonly PasswordHasher _hasher;
    private readonly PasswordPolicy _policy;
    private readonly IClock _clock;

    public UninstallPasswordService(ISettingsStore settings, IAuditLog audit, PasswordHasher hasher, PasswordPolicy policy, IClock clock)
    {
        _settings = settings;
        _audit = audit;
        _hasher = hasher;
        _policy = policy;
        _clock = clock;
    }

    /// <summary>Throws <see cref="PasswordPolicyException"/> if the candidate would be rejected. Lets setup validate before creating anything.</summary>
    public void EnsureAcceptable(string password)
    {
        var violations = _policy.Validate(password);
        if (violations.Count > 0) throw new PasswordPolicyException(violations);
    }

    public bool IsSet => !string.IsNullOrEmpty(_settings.Get(SettingKeys.UninstallPasswordHash));

    /// <summary>Mandatory during first-run setup; refuses if already set.</summary>
    public void SetInitial(long adminUserId, string password)
    {
        if (IsSet) throw new InvalidOperationException("Uninstall password is already set.");
        Store(adminUserId, password, "uninstall_password.set");
    }

    /// <param name="adminReauthenticated">True when the caller just re-verified the Admin's login password,
    /// which substitutes for supplying the current uninstall password.</param>
    public void Change(Session actingAdmin, string? currentPassword, string newPassword, bool adminReauthenticated = false)
    {
        if (actingAdmin.Role != Role.Admin) throw new UnauthorizedAccessException("Admin role required.");
        if (!IsSet) throw new InvalidOperationException("Uninstall password has not been set.");
        if (!adminReauthenticated)
        {
            var r = Verify(currentPassword ?? "");
            if (r.Status != UninstallVerifyStatus.Ok)
                throw new UnauthorizedAccessException("Current uninstall password is incorrect or locked.");
        }
        Store(actingAdmin.UserId, newPassword, "uninstall_password.change");
    }

    public UninstallVerifyResult Verify(string password)
    {
        var hash = _settings.Get(SettingKeys.UninstallPasswordHash);
        if (string.IsNullOrEmpty(hash)) return new UninstallVerifyResult(UninstallVerifyStatus.NotSet);

        var now = _clock.UtcNow;
        var lockedRaw = _settings.Get(SettingKeys.UninstallLockedUntilUtc);
        if (lockedRaw != null &&
            DateTime.TryParse(lockedRaw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var until) &&
            until > now)
        {
            _audit.Append(null, "uninstall.locked", null);
            return new UninstallVerifyResult(UninstallVerifyStatus.Locked, until);
        }

        if (_hasher.Verify(password, hash))
        {
            _settings.Set(SettingKeys.UninstallFailedAttempts, "0");
            _audit.Append(null, "uninstall.verified", null);
            return new UninstallVerifyResult(UninstallVerifyStatus.Ok);
        }

        var failed = int.Parse(_settings.Get(SettingKeys.UninstallFailedAttempts) ?? "0", CultureInfo.InvariantCulture) + 1;
        _audit.Append(null, "uninstall.failed", $"attempt {failed}");
        if (failed >= MaxFailedAttempts)
        {
            var lockUntil = now + LockoutDuration;
            _settings.Set(SettingKeys.UninstallFailedAttempts, "0");
            _settings.Set(SettingKeys.UninstallLockedUntilUtc, lockUntil.ToString("o", CultureInfo.InvariantCulture));
            return new UninstallVerifyResult(UninstallVerifyStatus.Locked, lockUntil);
        }
        _settings.Set(SettingKeys.UninstallFailedAttempts, failed.ToString(CultureInfo.InvariantCulture));
        return new UninstallVerifyResult(UninstallVerifyStatus.Wrong);
    }

    private void Store(long adminUserId, string password, string action)
    {
        EnsureAcceptable(password);
        _settings.Set(SettingKeys.UninstallPasswordHash, _hasher.Hash(password));
        _settings.Set(SettingKeys.UninstallFailedAttempts, "0");
        _audit.Append(adminUserId, action, null);
    }
}
