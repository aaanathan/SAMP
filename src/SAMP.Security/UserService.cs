using SAMP.Core;

namespace SAMP.Security;

public enum AuthStatus { Success, InvalidCredentials, Locked, Disabled }

public sealed record AuthResult(AuthStatus Status, User? User = null, DateTime? LockedUntilUtc = null);

public sealed class UserService
{
    public const int MaxFailedAttempts = 5;
    private static readonly TimeSpan MaxLockout = TimeSpan.FromMinutes(60);

    private readonly IUserStore _users;
    private readonly IAuditLog _audit;
    private readonly PasswordHasher _hasher;
    private readonly PasswordPolicy _policy;
    private readonly IClock _clock;
    private readonly string _dummyHash;

    /// <summary>Raised when a user's role, active flag or password changes so sessions can be revoked.</summary>
    public event Action<long>? UserAccessChanged;

    public UserService(IUserStore users, IAuditLog audit, PasswordHasher hasher, PasswordPolicy policy, IClock clock)
    {
        _users = users;
        _audit = audit;
        _hasher = hasher;
        _policy = policy;
        _clock = clock;
        _dummyHash = hasher.Hash("dummy-password-for-timing");
    }

    /// <summary>First-run setup. Allowed only while no users exist.</summary>
    public User CreateInitialAdmin(string username, string displayName, string password)
    {
        if (_users.List().Count > 0) throw new InvalidOperationException("Setup has already been completed.");
        return Create(null, username, displayName, password, Role.Admin, mustChange: false);
    }

    public User CreateUser(long actingUserId, string username, string displayName, string password, Role role, bool mustChangePassword = true)
    {
        RequireAdmin(actingUserId);
        return Create(actingUserId, username, displayName, password, role, mustChangePassword);
    }

    private User Create(long? actingUserId, string username, string displayName, string password, Role role, bool mustChange)
    {
        username = username.Trim();
        if (username.Length < 3) throw new ArgumentException("Username must be at least 3 characters.");
        if (_users.GetByUsername(username) != null) throw new InvalidOperationException("Username already exists.");
        Enforce(_policy.Validate(password, username));

        var now = _clock.UtcNow;
        var hash = _hasher.Hash(password);
        var user = new User
        {
            Username = username,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
            Role = role,
            PasswordHash = hash,
            MustChangePassword = mustChange,
            CreatedAtUtc = now,
        };
        user.Id = _users.Add(user);
        _users.AddPasswordHistory(user.Id, hash, now);
        _audit.Append(actingUserId, "user.create", $"{username} role={role}");
        return user;
    }

    public AuthResult Authenticate(string username, string password)
    {
        var now = _clock.UtcNow;
        var user = _users.GetByUsername(username.Trim());
        if (user == null)
        {
            _hasher.Verify(password, _dummyHash); // equalise timing; don't reveal existence
            _audit.Append(null, "login.failed", $"unknown user '{username.Trim()}'");
            return new AuthResult(AuthStatus.InvalidCredentials);
        }

        if (user.LockedUntilUtc is { } until && until > now)
        {
            _audit.Append(user.Id, "login.locked", null);
            return new AuthResult(AuthStatus.Locked, LockedUntilUtc: until);
        }

        if (!_hasher.Verify(password, user.PasswordHash))
        {
            user.FailedAttempts++;
            if (user.FailedAttempts >= MaxFailedAttempts)
            {
                var minutes = Math.Pow(2, user.FailedAttempts - MaxFailedAttempts);
                var span = TimeSpan.FromMinutes(minutes);
                user.LockedUntilUtc = now + (span > MaxLockout ? MaxLockout : span);
            }
            _users.Update(user);
            _audit.Append(user.Id, "login.failed", $"attempt {user.FailedAttempts}");
            return new AuthResult(AuthStatus.InvalidCredentials);
        }

        if (!user.IsActive)
        {
            _audit.Append(user.Id, "login.disabled", null);
            return new AuthResult(AuthStatus.Disabled);
        }

        user.FailedAttempts = 0;
        user.LockedUntilUtc = null;
        user.LastLoginUtc = now;
        _users.Update(user);
        _audit.Append(user.Id, "login.success", null);
        return new AuthResult(AuthStatus.Success, user);
    }

    /// <summary>User-initiated change; requires the current password.</summary>
    public void ChangePassword(long userId, string currentPassword, string newPassword)
    {
        var user = _users.GetById(userId) ?? throw new KeyNotFoundException("User not found.");
        if (!_hasher.Verify(currentPassword, user.PasswordHash))
        {
            _audit.Append(userId, "password.change_failed", "wrong current password");
            throw new UnauthorizedAccessException("Current password is incorrect.");
        }
        SetPassword(user, newPassword, mustChange: false, actingUserId: userId, action: "password.change");
    }

    /// <summary>Admin reset; forces a change at next login.</summary>
    public void ResetPassword(long actingUserId, long targetUserId, string newPassword)
    {
        RequireAdmin(actingUserId);
        var user = _users.GetById(targetUserId) ?? throw new KeyNotFoundException("User not found.");
        SetPassword(user, newPassword, mustChange: true, actingUserId: actingUserId, action: "password.reset");
    }

    private void SetPassword(User user, string newPassword, bool mustChange, long actingUserId, string action)
    {
        Enforce(_policy.Validate(newPassword, user.Username));
        var recent = _users.GetRecentPasswordHashes(user.Id, _policy.Options.HistoryCount);
        if (recent.Any(h => _hasher.Verify(newPassword, h)))
            throw new PasswordPolicyException(new[] { $"Password was used recently (last {_policy.Options.HistoryCount})." });

        var now = _clock.UtcNow;
        user.PasswordHash = _hasher.Hash(newPassword);
        user.MustChangePassword = mustChange;
        user.FailedAttempts = 0;
        user.LockedUntilUtc = null;
        _users.Update(user);
        _users.AddPasswordHistory(user.Id, user.PasswordHash, now);
        _audit.Append(actingUserId, action, user.Username);
        UserAccessChanged?.Invoke(user.Id);
    }

    /// <summary>
    /// Admin password reset authorised by a verified recovery key (see <see cref="RecoveryKeyService"/>).
    /// Only active Admin accounts can be recovered this way; the account is unlocked and the user is not forced to change again.
    /// </summary>
    public User RecoverAdminPassword(string username, string newPassword)
    {
        var user = _users.GetByUsername(username.Trim());
        if (user is not { Role: Role.Admin, IsActive: true })
            throw new InvalidOperationException("Recovery is only available for active Admin accounts.");
        SetPassword(user, newPassword, mustChange: false, actingUserId: user.Id, action: "password.recovery");
        return user;
    }

    public void SetActive(long actingUserId, long targetUserId, bool active)
    {
        RequireAdmin(actingUserId);
        var user = _users.GetById(targetUserId) ?? throw new KeyNotFoundException("User not found.");
        if (!active) EnsureNotLastAdmin(user);
        user.IsActive = active;
        _users.Update(user);
        _audit.Append(actingUserId, active ? "user.enable" : "user.disable", user.Username);
        if (!active) UserAccessChanged?.Invoke(user.Id);
    }

    public void SetRole(long actingUserId, long targetUserId, Role role)
    {
        RequireAdmin(actingUserId);
        var user = _users.GetById(targetUserId) ?? throw new KeyNotFoundException("User not found.");
        if (user.Role == Role.Admin && role != Role.Admin) EnsureNotLastAdmin(user);
        var old = user.Role;
        user.Role = role;
        _users.Update(user);
        _audit.Append(actingUserId, "user.role", $"{user.Username} {old}->{role}");
        UserAccessChanged?.Invoke(user.Id);
    }

    private void EnsureNotLastAdmin(User user)
    {
        if (user is { Role: Role.Admin, IsActive: true } && _users.CountActiveAdmins() <= 1)
            throw new InvalidOperationException("Cannot disable or demote the last active Admin.");
    }

    private void RequireAdmin(long actingUserId)
    {
        var actor = _users.GetById(actingUserId);
        if (actor is not { Role: Role.Admin, IsActive: true })
            throw new UnauthorizedAccessException("Admin role required.");
    }

    private static void Enforce(IReadOnlyList<string> violations)
    {
        if (violations.Count > 0) throw new PasswordPolicyException(violations);
    }
}
