using System.Globalization;
using System.Security.Cryptography;
using SAMP.Core;

namespace SAMP.Security;

public enum RecoveryStatus { Ok, InvalidKey, Locked, NotConfigured }

public sealed record RecoveryResult(RecoveryStatus Status, string? NewRecoveryKey = null, DateTime? LockedUntilUtc = null);

/// <summary>
/// One-time offline recovery key created at setup. It can reset a lost Admin password; using it rotates the key.
/// Only an Argon2id hash is stored. Wrong attempts are rate-limited like the uninstall password.
/// </summary>
public sealed class RecoveryKeyService
{
    public const int MaxFailedAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private readonly ISettingsStore _settings;
    private readonly UserService _users;
    private readonly IAuditLog _audit;
    private readonly PasswordHasher _hasher;
    private readonly IClock _clock;

    public RecoveryKeyService(ISettingsStore settings, UserService users, IAuditLog audit, PasswordHasher hasher, IClock clock)
    {
        _settings = settings; _users = users; _audit = audit; _hasher = hasher; _clock = clock;
    }

    public bool IsConfigured => !string.IsNullOrEmpty(_settings.Get(SettingKeys.RecoveryKeyHash));

    /// <summary>Creates and stores the first key. Returned once; it is never retrievable again.</summary>
    public string IssueInitial(long adminUserId)
    {
        if (IsConfigured) throw new InvalidOperationException("A recovery key already exists.");
        return Rotate(adminUserId, "recovery.issue");
    }

    public RecoveryResult ResetAdminPassword(string recoveryKey, string username, string newPassword)
    {
        var stored = _settings.Get(SettingKeys.RecoveryKeyHash);
        if (string.IsNullOrEmpty(stored)) return new RecoveryResult(RecoveryStatus.NotConfigured);

        var now = _clock.UtcNow;
        if (DateTime.TryParse(_settings.Get(SettingKeys.RecoveryLockedUntilUtc), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var until) && until > now)
        {
            _audit.Append(null, "recovery.locked");
            return new RecoveryResult(RecoveryStatus.Locked, LockedUntilUtc: until);
        }

        if (!_hasher.Verify(Normalize(recoveryKey), stored))
        {
            var failed = int.Parse(_settings.Get(SettingKeys.RecoveryFailedAttempts) ?? "0", CultureInfo.InvariantCulture) + 1;
            _audit.Append(null, "recovery.failed", $"attempt {failed}");
            if (failed >= MaxFailedAttempts)
            {
                var lockUntil = now + LockoutDuration;
                _settings.Set(SettingKeys.RecoveryFailedAttempts, "0");
                _settings.Set(SettingKeys.RecoveryLockedUntilUtc, lockUntil.ToString("o", CultureInfo.InvariantCulture));
                return new RecoveryResult(RecoveryStatus.Locked, LockedUntilUtc: lockUntil);
            }
            _settings.Set(SettingKeys.RecoveryFailedAttempts, failed.ToString(CultureInfo.InvariantCulture));
            return new RecoveryResult(RecoveryStatus.InvalidKey);
        }

        // Key is valid: the password change below validates policy; if it throws, the key stays usable.
        var user = _users.RecoverAdminPassword(username, newPassword);
        _settings.Set(SettingKeys.RecoveryFailedAttempts, "0");
        return new RecoveryResult(RecoveryStatus.Ok, Rotate(user.Id, "recovery.used"));
    }

    private string Rotate(long userId, string action)
    {
        var key = Generate();
        _settings.Set(SettingKeys.RecoveryKeyHash, _hasher.Hash(Normalize(key)));
        _audit.Append(userId, action);
        return key;
    }

    /// <summary>160 random bits as 8 groups of 4 base32 characters.</summary>
    public static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        var chars = new char[32];
        int buffer = 0, bits = 0, idx = 0;
        foreach (var b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                chars[idx++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }
        }
        return string.Join('-', Enumerable.Range(0, 8).Select(i => new string(chars, i * 4, 4)));
    }

    public static string Normalize(string key) =>
        new(key.Where(c => c != '-' && !char.IsWhiteSpace(c)).Select(char.ToUpperInvariant).ToArray());
}
