using System.Text.Json;
using SAMP.Core;
using SAMP.Ipc;
using SAMP.Logging;
using SAMP.Security;
using SAMP.Usb;

namespace SAMP.Service;

public sealed record UserDto(long Id, string Username, string DisplayName, string Role, bool IsActive, bool MustChangePassword,
    DateTime? LockedUntilUtc, DateTime? LastLoginUtc);

/// <summary>
/// The only entry point the UI/installer can reach. Authentication and role checks happen here, never in the client.
/// </summary>
public sealed class ServiceApi : IIpcHandler
{
    private readonly UserService _users;
    private readonly IUserStore _userStore;
    private readonly SessionManager _sessions;
    private readonly UnblockManager _unblock;
    private readonly BlockRuleService _rules;
    private readonly UninstallPasswordService _uninstall;
    private readonly IAuditLog _audit;
    private readonly DeviceLog _deviceLog;
    private readonly ISettingsStore _settings;
    private readonly LogMaintenance _maintenance;
    private readonly RecoveryKeyService _recovery;
    private readonly LoginThrottle _throttle;
    private readonly IntegrityMonitor _integrity;
    private readonly MaintenanceWindow _window;

    public ServiceApi(UserService users, IUserStore userStore, SessionManager sessions, UnblockManager unblock, BlockRuleService rules,
        UninstallPasswordService uninstall, IAuditLog audit, DeviceLog deviceLog, ISettingsStore settings, LogMaintenance maintenance,
        RecoveryKeyService recovery, LoginThrottle throttle, IntegrityMonitor integrity, MaintenanceWindow window)
    {
        _users = users; _userStore = userStore; _sessions = sessions; _unblock = unblock; _rules = rules;
        _uninstall = uninstall; _audit = audit; _deviceLog = deviceLog; _settings = settings; _maintenance = maintenance;
        _recovery = recovery; _throttle = throttle; _integrity = integrity; _window = window;
        _users.UserAccessChanged += id => _sessions.RevokeAllForUser(id);
    }

    public Task<IpcResponse> HandleAsync(IpcRequest req, CancellationToken ct)
    {
        try
        {
            return Task.FromResult(IpcResponse.Success(Dispatch(req)));
        }
        catch (LoginFailure e) { return Task.FromResult(IpcResponse.Fail(e.Code, e.Message)); }
        catch (UnauthorizedAccessException e) { return Task.FromResult(IpcResponse.Fail("unauthorized", e.Message)); }
        catch (PasswordPolicyException e) { return Task.FromResult(IpcResponse.Fail("password_policy", e.Message)); }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or KeyNotFoundException or FormatException or JsonException)
        {
            return Task.FromResult(IpcResponse.Fail("invalid", e.Message));
        }
        catch (Exception e)
        {
            try { _deviceLog.Append("service.error", new { command = req.Command, error = e.GetType().Name }); } catch { /* ignore */ }
            return Task.FromResult(IpcResponse.Fail("error", "Internal error."));
        }
    }

    private object? Dispatch(IpcRequest req)
    {
        var a = new Args(req.Args);
        switch (req.Command)
        {
            // ---- public (no session) ----------------------------------------------------------
            case "setup.status":
                return new { needsSetup = _userStore.List().Count == 0 };

            case "setup.complete":
            {
                // Admin account and the mandatory uninstall password are created together, only once.
                // Validate both secrets first so a rejected uninstall password cannot leave a half-finished setup behind.
                _uninstall.EnsureAcceptable(a.Str("uninstallPassword"));
                var admin = _users.CreateInitialAdmin(a.Str("username"), a.OptStr("displayName") ?? "", a.Str("password"));
                _uninstall.SetInitial(admin.Id, a.Str("uninstallPassword"));
                var recoveryKey = _recovery.IssueInitial(admin.Id); // shown once; only its hash is stored
                _unblock.Reconcile();
                return new { userId = admin.Id, recoveryKey };
            }

            case "login":
            {
                if (_throttle.IsBlocked(out var blockedUntil))
                    throw new LoginFailure("too_many_attempts", $"Too many failed sign-ins. Try again after {blockedUntil:HH:mm:ss} UTC.");
                var r = _users.Authenticate(a.Str("username"), a.Str("password"));
                switch (r.Status)
                {
                    case AuthStatus.Success:
                        var s = _sessions.Create(r.User!);
                        return new { token = s.Token, user = ToDto(r.User!) };
                    case AuthStatus.Locked:
                        throw new LoginFailure("locked", $"Account locked until {r.LockedUntilUtc:u}.");
                    case AuthStatus.Disabled:
                        throw new LoginFailure("disabled", "Account is disabled.");
                    default:
                        _throttle.RecordFailure();
                        throw new LoginFailure("invalid_credentials", "Invalid username or password.");
                }
            }

            case "status.public":
                return new { isBlocked = _unblock.GetStatus().IsBlocked, integrityAlert = _integrity.IsAlerting };

            case "recovery.reset":
            {
                if (_throttle.IsBlocked(out var until))
                    throw new LoginFailure("too_many_attempts", $"Too many failed attempts. Try again after {until:HH:mm:ss} UTC.");
                var r = _recovery.ResetAdminPassword(a.Str("recoveryKey"), a.Str("username"), a.Str("newPassword"));
                switch (r.Status)
                {
                    case RecoveryStatus.Ok:
                        return new { recoveryKey = r.NewRecoveryKey };
                    case RecoveryStatus.Locked:
                        throw new LoginFailure("locked", $"Recovery is locked until {r.LockedUntilUtc:u}.");
                    case RecoveryStatus.NotConfigured:
                        throw new LoginFailure("not_configured", "No recovery key has been set up.");
                    default:
                        _throttle.RecordFailure();
                        throw new LoginFailure("invalid_recovery_key", "The recovery key is not valid.");
                }
            }

            case "maintenance.begin":
            {
                // Called by the installer (upgrade/uninstall). Only a correct uninstall password opens the window.
                var r = _uninstall.Verify(a.Str("password"));
                if (r.Status is UninstallVerifyStatus.Ok or UninstallVerifyStatus.NotSet)
                {
                    _window.Begin();
                    _audit.Append(null, "maintenance.begin", $"open until {_window.OpenUntilUtc:O}");
                }
                return new { status = r.Status.ToString(), lockedUntilUtc = r.LockedUntilUtc };
            }

            case "uninstall.verify":
            {
                // Called by the MSI uninstall guard; lockout lives in UninstallPasswordService.
                var r = _uninstall.Verify(a.Str("password"));
                return new { status = r.Status.ToString(), lockedUntilUtc = r.LockedUntilUtc };
            }
        }

        // ---- everything below requires a valid session --------------------------------------------
        var session = _sessions.RequireRole(req.Token, Role.Viewer);
        var me = _userStore.GetById(session.UserId);
        if (me is not { IsActive: true }) { _sessions.Revoke(session.Token); throw new UnauthorizedAccessException("Account is no longer active."); }
        if (me.MustChangePassword && req.Command is not ("password.change" or "logout" or "me"))
            throw new UnauthorizedAccessException("Password change required.");

        switch (req.Command)
        {
            case "logout":
                _sessions.Revoke(session.Token);
                _audit.Append(session.UserId, "logout");
                return null;

            case "auth.verify":
                // Re-authentication before sensitive actions (e.g. unblock). Shares the login lockout counters.
                return new { ok = _users.Authenticate(me.Username, a.Str("password")).Status == AuthStatus.Success };

            case "me":
                return ToDto(me);

            case "password.change":
                _users.ChangePassword(session.UserId, a.Str("current"), a.Str("new"));
                return null;

            case "status":
            {
                var st = _unblock.GetStatus();
                return new
                {
                    isBlocked = st.IsBlocked,
                    expiresAtUtc = st.ExpiresAtUtc,
                    remainingSeconds = st.Remaining?.TotalSeconds,
                    durationMinutes = _unblock.GetDurationMinutes(),
                    maxMinutes = _unblock.GetMaxMinutes(),
                    integrityAlert = _integrity.IsAlerting,
                };
            }

            case "unblock":
            {
                _sessions.RequireRole(req.Token, Role.Operator);
                var s = _unblock.Unblock(session.UserId, session.Role, a.OptInt("minutes"));
                return new { expiresAtUtc = s.ExpiresAtUtc };
            }

            case "block":
                _sessions.RequireRole(req.Token, Role.Operator);
                _unblock.BlockNow(session.UserId);
                return null;
        }

        // ---- Admin only ----------------------------------------------------------------------------
        _sessions.RequireRole(req.Token, Role.Admin);
        switch (req.Command)
        {
            case "users.list":
                return _userStore.List().Select(ToDto).ToList();

            case "users.create":
                return ToDto(_users.CreateUser(session.UserId, a.Str("username"), a.OptStr("displayName") ?? "", a.Str("password"),
                    ParseRole(a.Str("role")), a.OptBool("mustChangePassword") ?? true));

            case "users.setActive":
                _users.SetActive(session.UserId, a.Long("userId"), a.Bool("active"));
                return null;

            case "users.setRole":
                _users.SetRole(session.UserId, a.Long("userId"), ParseRole(a.Str("role")));
                return null;

            case "users.resetPassword":
                _users.ResetPassword(session.UserId, a.Long("userId"), a.Str("password"));
                return null;

            case "rules.list":
                return _rules.List(session.Role);

            case "rules.add":
                return new { id = _rules.Add(session.UserId, session.Role, a.Rule()) };

            case "rules.update":
                _rules.Update(session.UserId, session.Role, a.Rule());
                return null;

            case "rules.delete":
                _rules.Delete(session.UserId, session.Role, a.Long("id"));
                return null;

            case "settings.get":
                return new
                {
                    durationMinutes = _unblock.GetDurationMinutes(),
                    maxMinutes = _unblock.GetMaxMinutes(),
                    externalLogPath = _maintenance.ExternalPath,
                    uninstallPasswordSet = _uninstall.IsSet,
                    retentionDays = _deviceLog.RetentionDays,
                };

            case "settings.setDuration":
                _unblock.SetDuration(session.UserId, session.Role, a.Int("minutes"), a.OptBool("applyToCurrent") ?? false);
                return null;

            case "settings.setMax":
                _unblock.SetMaxMinutes(session.UserId, session.Role, a.Int("minutes"));
                return null;

            case "settings.setExternalLogPath":
            {
                var path = a.OptStr("path")?.Trim() ?? "";
                if (path.Length > 0 && !Path.IsPathRooted(path)) throw new ArgumentException("External log path must be absolute.");
                _settings.Set(SettingKeys.ExternalLogPath, path);
                _audit.Append(session.UserId, "settings.external_log_path", path.Length == 0 ? "(cleared)" : path);
                return null;
            }

            case "audit.query":
                return _audit.Query(Math.Clamp(a.OptInt("limit") ?? 200, 1, 2000));

            case "audit.verify":
                return _audit.Verify();

            case "integrity.get":
                return new { alerting = _integrity.IsAlerting, details = _integrity.Details };

            case "integrity.acknowledge":
                _integrity.Acknowledge(session.UserId);
                return null;

            case "devicelog.query":
                return _deviceLog.Query(a.OptDate("fromUtc"), a.OptDate("toUtc"), Math.Clamp(a.OptInt("limit") ?? 200, 1, 5000));

            case "devicelog.verify":
                return _deviceLog.Verify();

            case "uninstall.change":
            {
                // Either the current uninstall password, or a fresh re-entry of this Admin's login password.
                var adminPassword = a.OptStr("adminPassword");
                var reauth = false;
                if (adminPassword != null)
                    reauth = _users.Authenticate(me.Username, adminPassword).Status == AuthStatus.Success;
                _uninstall.Change(session, a.OptStr("current"), a.Str("new"), reauth);
                return null;
            }

            default:
                throw new ArgumentException($"Unknown command '{req.Command}'.");
        }
    }

    private static Role ParseRole(string s) =>
        Enum.TryParse<Role>(s, true, out var r) ? r : throw new ArgumentException($"Unknown role '{s}'.");

    private static UserDto ToDto(User u) =>
        new(u.Id, u.Username, u.DisplayName, u.Role.ToString(), u.IsActive, u.MustChangePassword, u.LockedUntilUtc, u.LastLoginUtc);

    /// <summary>Login failures are normal responses, not internal errors.</summary>
    private sealed class LoginFailure(string code, string message) : Exception(message)
    {
        public string Code { get; } = code;
    }
}

public readonly struct Args(JsonElement? root)
{
    private JsonElement? Get(string name) =>
        root is { ValueKind: JsonValueKind.Object } r && r.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v : null;

    public string Str(string name) => OptStr(name) ?? throw new ArgumentException($"'{name}' is required.");
    public string? OptStr(string name) => Get(name) is { ValueKind: JsonValueKind.String } v ? v.GetString() : null;
    public int Int(string name) => OptInt(name) ?? throw new ArgumentException($"'{name}' is required.");
    public int? OptInt(string name) => Get(name) is { ValueKind: JsonValueKind.Number } v && v.TryGetInt32(out var i) ? i : null;
    public long Long(string name) => Get(name) is { ValueKind: JsonValueKind.Number } v && v.TryGetInt64(out var l) ? l : throw new ArgumentException($"'{name}' is required.");
    public bool Bool(string name) => OptBool(name) ?? throw new ArgumentException($"'{name}' is required.");
    public bool? OptBool(string name) => Get(name) is { } v && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;
    public DateTime? OptDate(string name) => OptStr(name) is { } s ? DateTime.Parse(s, null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime() : null;

    public T Obj<T>(string name) =>
        Get(name) is { } v ? v.Deserialize<T>(IpcJson.Options) ?? throw new ArgumentException($"'{name}' is invalid.") : throw new ArgumentException($"'{name}' is required.");

    public BlockRule Rule() => new()
    {
        Id = OptInt("id") ?? 0,
        Name = Str("name"),
        Enabled = OptBool("enabled") ?? true,
        Action = Enum.TryParse<RuleAction>(Str("action"), true, out var ac) ? ac : throw new ArgumentException("Unknown action."),
        MatchType = Enum.TryParse<BlockMatchType>(Str("matchType"), true, out var mt) ? mt : throw new ArgumentException("Unknown match type."),
        Value = Str("value"),
        Scope = Enum.TryParse<RuleScope>(OptStr("scope") ?? "Always", true, out var sc) ? sc : throw new ArgumentException("Unknown scope."),
        Note = OptStr("note"),
    };
}
