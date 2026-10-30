using SAMP.App.Core;
using SAMP.Client;
using SAMP.Core;

namespace SAMP.AppTests;

public sealed class Clock : IClock
{
    public DateTime UtcNow { get; set; } = new(2026, 1, 1, 8, 0, 0, DateTimeKind.Utc);
    public void Advance(TimeSpan t) => UtcNow += t;
}

public sealed class FakeService(Clock clock) : ISampService
{
    public bool NeedsSetup { get; set; }
    public bool Unreachable { get; set; }
    public bool HasSession { get; private set; }
    public bool IsBlocked { get; set; } = true;
    public DateTime? Expires { get; set; }
    public string Role { get; set; } = "Admin";
    public bool MustChange { get; set; }
    public string Password { get; set; } = "pw";
    public int LogoutCalls { get; private set; }
    public int StatusCalls { get; private set; }
    public int? LastUnblockMinutes { get; private set; }
    public (string, string, string, string)? SetupArgs { get; private set; }
    public RuleInfo? SavedRule { get; private set; }
    public event Action? SessionExpired;
    public void RaiseExpired() { HasSession = false; SessionExpired?.Invoke(); }

    private static Result<T> Unreach<T>() => Result<T>.Fail("The SAMP service is not reachable.", "unreachable");
    private static Result<bool> Yes => Result<bool>.Success(true);

    public Task<Result<bool>> NeedsSetupAsync() => Task.FromResult(Unreachable ? Unreach<bool>() : Result<bool>.Success(NeedsSetup));
    public Task<Result<string>> SetupAsync(string u, string d, string p, string up) { SetupArgs = (u, d, p, up); NeedsSetup = false; return Task.FromResult(Result<string>.Success("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")); }
    public string RecoveryKeyValid { get; set; } = "KEY";
    public Task<Result<string>> RecoverAsync(string key, string user, string pw) =>
        Task.FromResult(key == RecoveryKeyValid ? Result<string>.Success("NEWK-NEWK") : Result<string>.Fail("The recovery key is not valid.", "invalid_recovery_key"));
    public bool IntegrityAlerting { get; set; }
    public bool IntegrityAcked { get; private set; }
    public Task<Result<IntegrityInfo>> GetIntegrityAsync() => Task.FromResult(Result<IntegrityInfo>.Success(new(IntegrityAlerting && !IntegrityAcked, "devicelog@7: tampered")));
    public Task<Result<bool>> AcknowledgeIntegrityAsync() { IntegrityAcked = true; return Task.FromResult(Yes); }
    public Task<Result<bool>> IsBlockedPublicAsync() => Task.FromResult(Result<bool>.Success(IsBlocked));

    public Task<Result<LoginInfo>> LoginAsync(string u, string p)
    {
        if (p != Password) return Task.FromResult(Result<LoginInfo>.Fail("Invalid username or password.", "invalid_credentials"));
        HasSession = true;
        return Task.FromResult(Result<LoginInfo>.Success(new LoginInfo("tok", new UserInfo(1, u, u, Role, true, MustChange, null, null))));
    }

    public Task<Result<bool>> LogoutAsync() { LogoutCalls++; HasSession = false; return Task.FromResult(Yes); }
    public Task<Result<bool>> VerifyPasswordAsync(string p) => Task.FromResult(Result<bool>.Success(p == Password));
    public Task<Result<bool>> ChangePasswordAsync(string c, string n)
    {
        if (c != Password) return Task.FromResult(Result<bool>.Fail("Current password is incorrect.", "unauthorized"));
        Password = n; MustChange = false; return Task.FromResult(Yes);
    }

    public Task<Result<StatusInfo>> GetStatusAsync()
    {
        StatusCalls++;
        var rem = Expires is { } e ? (e - clock.UtcNow).TotalSeconds : (double?)null;
        return Task.FromResult(Result<StatusInfo>.Success(new StatusInfo(IsBlocked, Expires, rem, 120, 600, IntegrityAlerting)));
    }

    public Task<Result<bool>> UnblockAsync(int? minutes)
    {
        LastUnblockMinutes = minutes; IsBlocked = false; Expires = clock.UtcNow.AddMinutes(minutes ?? 120); return Task.FromResult(Yes);
    }

    public Task<Result<bool>> BlockAsync() { IsBlocked = true; Expires = null; return Task.FromResult(Yes); }

    public List<UserInfo> Users { get; } = new() { new(1, "admin", "Admin", "Admin", true, false, null, null), new(2, "bob", "Bob", "Operator", true, false, null, null) };
    public Task<Result<List<UserInfo>>> ListUsersAsync() => Task.FromResult(Result<List<UserInfo>>.Success(Users.ToList()));
    public Task<Result<UserInfo>> CreateUserAsync(string u, string d, string p, string r, bool m)
    {
        var x = new UserInfo(Users.Count + 1, u, d, r, true, m, null, null); Users.Add(x); return Task.FromResult(Result<UserInfo>.Success(x));
    }
    public Task<Result<bool>> SetUserActiveAsync(long id, bool a) => Task.FromResult(Yes);
    public Task<Result<bool>> SetUserRoleAsync(long id, string r) => Task.FromResult(Yes);
    public Task<Result<bool>> ResetUserPasswordAsync(long id, string p) => Task.FromResult(Yes);

    public Task<Result<List<RuleInfo>>> ListRulesAsync() => Task.FromResult(Result<List<RuleInfo>>.Success(new()));
    public Task<Result<bool>> SaveRuleAsync(RuleInfo r) { SavedRule = r; return Task.FromResult(Yes); }
    public Task<Result<bool>> DeleteRuleAsync(long id) => Task.FromResult(Yes);

    public Task<Result<SettingsInfo>> GetSettingsAsync() => Task.FromResult(Result<SettingsInfo>.Success(new(120, 600, null, true, 30)));
    public Task<Result<bool>> SetDurationAsync(int m, bool a) => Task.FromResult(Yes);
    public Task<Result<bool>> SetMaxAsync(int m) => Task.FromResult(Yes);
    public Task<Result<bool>> SetExternalLogPathAsync(string p) => Task.FromResult(Yes);
    public Task<Result<bool>> ChangeUninstallPasswordAsync(string? c, string? a, string n) => Task.FromResult(Yes);

    public Task<Result<List<AuditRow>>> QueryAuditAsync(int l) => Task.FromResult(Result<List<AuditRow>>.Success(new()));
    public Task<Result<VerifyInfo>> VerifyAuditAsync() => Task.FromResult(Result<VerifyInfo>.Success(new(true, null, null, null, null, 3)));
    public List<DeviceLogRow> LogRows { get; } = new();
    public Task<Result<List<DeviceLogRow>>> QueryDeviceLogAsync(DateTime? f, DateTime? t, int l) => Task.FromResult(Result<List<DeviceLogRow>>.Success(LogRows.ToList()));
    public Task<Result<VerifyInfo>> VerifyDeviceLogAsync() => Task.FromResult(Result<VerifyInfo>.Success(new(false, null, 7, "Record content does not match its signature.", new(), 10)));
}

public class ShellTests
{
    private readonly Clock _clock = new();
    private readonly FakeService _svc;
    private readonly ShellViewModel _shell;

    public ShellTests()
    {
        _svc = new FakeService(_clock);
        _shell = new ShellViewModel(_svc, _clock);
    }

    private async Task SignIn(string role = "Admin")
    {
        _svc.Role = role;
        await _shell.InitializeAsync();
        _shell.Login.Username = "alice";
        _shell.Login.Password = "pw";
        await _shell.Login.SignInCommand.ExecuteAsync(null);
    }

    [Fact]
    public async Task First_run_shows_setup_then_login_after_it_completes()
    {
        _svc.NeedsSetup = true;
        await _shell.InitializeAsync();
        Assert.Equal(ShellState.Setup, _shell.State);

        _shell.Setup.Password = "Aaaa-bbbb-1234!"; _shell.Setup.ConfirmPassword = "different";
        _shell.Setup.UninstallPassword = _shell.Setup.ConfirmUninstallPassword = "Uninstall-9999!";
        await _shell.Setup.CompleteCommand.ExecuteAsync(null);
        Assert.Equal(ShellState.Setup, _shell.State);
        Assert.Contains("do not match", _shell.Setup.ErrorMessage);

        _shell.Setup.Password = _shell.Setup.ConfirmPassword = "Aaaa-bbbb-1234!";
        _shell.Setup.UninstallPassword = _shell.Setup.ConfirmUninstallPassword = "Aaaa-bbbb-1234!";
        await _shell.Setup.CompleteCommand.ExecuteAsync(null);
        Assert.Contains("different", _shell.Setup.ErrorMessage);

        _shell.Setup.UninstallPassword = _shell.Setup.ConfirmUninstallPassword = "Uninstall-9999!";
        await _shell.Setup.CompleteCommand.ExecuteAsync(null);
        // the recovery key is shown once and the admin must confirm before moving on
        Assert.Equal(ShellState.Setup, _shell.State);
        Assert.True(_shell.Setup.ShowRecoveryKey);
        Assert.Equal("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", _shell.Setup.RecoveryKey);
        await _shell.Setup.AcknowledgeRecoveryCommand.ExecuteAsync(null);
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Null(_shell.Setup.RecoveryKey);
        Assert.Equal("Uninstall-9999!", _svc.SetupArgs!.Value.Item4);
        Assert.Equal("", _shell.Setup.Password); // secrets wiped
    }

    [Fact]
    public async Task Nothing_but_login_is_available_before_signing_in()
    {
        await _shell.InitializeAsync();
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Empty(_shell.NavItems);
        Assert.Null(_shell.Dashboard);
        Assert.Contains("blocked", _shell.Login.UsbStateText);
    }

    [Fact]
    public async Task Service_down_is_reported_not_crashed()
    {
        _svc.Unreachable = true;
        await _shell.InitializeAsync();
        Assert.Equal(ShellState.ServiceUnavailable, _shell.State);
        Assert.Contains("not reachable", _shell.Notice);
    }

    [Fact]
    public async Task Screen_follows_state_and_unavailable_service_is_retried_automatically()
    {
        _svc.Unreachable = true;
        await _shell.InitializeAsync();
        Assert.Same(_shell.Unavailable, _shell.Screen);

        _svc.Unreachable = false;
        _clock.Advance(TimeSpan.FromSeconds(11));
        await _shell.TickAsync();
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Same(_shell.Login, _shell.Screen);

        _shell.Login.Username = "a"; _shell.Login.Password = "pw";
        await _shell.Login.SignInCommand.ExecuteAsync(null);
        Assert.Same(_shell, _shell.Screen);
    }

    [Fact]
    public async Task Auto_block_warnings_reach_the_tray_notification()
    {
        var msgs = new List<string>();
        _shell.Notification += msgs.Add;
        _svc.IsBlocked = false; _svc.Expires = _clock.UtcNow.AddMinutes(30);
        await SignIn();
        _clock.Advance(TimeSpan.FromMinutes(21));
        _shell.NotifyActivity();
        await _shell.TickAsync();
        Assert.Single(msgs);
    }

    [Fact]
    public async Task Forgot_password_flow_uses_the_recovery_key_and_shows_the_replacement_once()
    {
        await _shell.InitializeAsync();
        _shell.Login.ForgotPasswordCommand.Execute(null);
        Assert.Equal(ShellState.Recovery, _shell.State);
        Assert.Same(_shell.Recovery, _shell.Screen);

        _shell.Recovery.Username = "admin"; _shell.Recovery.RecoveryKey = "WRONG";
        _shell.Recovery.NewPassword = _shell.Recovery.ConfirmPassword = "New-pass-1234!";
        await _shell.Recovery.ResetCommand.ExecuteAsync(null);
        Assert.Equal("The recovery key is not valid.", _shell.Recovery.ErrorMessage);
        Assert.False(_shell.Recovery.ShowNewKey);

        _shell.Recovery.RecoveryKey = "KEY";
        _shell.Recovery.NewPassword = _shell.Recovery.ConfirmPassword = "New-pass-1234!";
        await _shell.Recovery.ResetCommand.ExecuteAsync(null);
        Assert.True(_shell.Recovery.ShowNewKey);
        Assert.Equal("NEWK-NEWK", _shell.Recovery.NewRecoveryKey);
        await _shell.Recovery.DoneCommand.ExecuteAsync(null);
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Null(_shell.Recovery.NewRecoveryKey);
    }

    [Fact]
    public async Task Integrity_alert_shows_on_dashboard_and_admin_can_acknowledge_it()
    {
        _svc.IntegrityAlerting = true;
        await SignIn();
        await _shell.Dashboard!.LoadAsync();
        Assert.True(_shell.Dashboard.IntegrityAlert);

        var audit = new AuditViewModel(_svc);
        await audit.LoadAsync();
        Assert.True(audit.HasIntegrityAlert);
        await audit.AcknowledgeIntegrityCommand.ExecuteAsync(null);
        Assert.False(audit.HasIntegrityAlert);
        Assert.Equal("Integrity alert acknowledged.", audit.InfoMessage);
    }

    [Fact]
    public async Task Wrong_password_stays_on_login_clears_the_password_and_shows_the_error()
    {
        await _shell.InitializeAsync();
        _shell.Login.Username = "alice"; _shell.Login.Password = "nope";
        await _shell.Login.SignInCommand.ExecuteAsync(null);
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Equal("Invalid username or password.", _shell.Login.ErrorMessage);
        Assert.Equal("", _shell.Login.Password);
    }

    [Fact]
    public async Task Admin_sees_every_page_operator_only_dashboard_and_account()
    {
        await SignIn("Admin");
        Assert.Equal(ShellState.Main, _shell.State);
        Assert.Equal(["Dashboard", "Users", "Device Rules", "Device Log", "Audit Log", "Settings", "My Account"], _shell.NavItems.Select(n => n.Title).ToArray());

        await _shell.LogoutAsync();
        await SignIn("Operator");
        Assert.Equal(["Dashboard", "My Account"], _shell.NavItems.Select(n => n.Title).ToArray());
        Assert.Null(_shell.DeviceLog);
        Assert.Null(_shell.Rules);
    }

    [Fact]
    public async Task Logout_calls_the_service_clears_everything_and_returns_to_login()
    {
        await SignIn();
        await _shell.LogoutAsync();
        Assert.Equal(1, _svc.LogoutCalls);
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Empty(_shell.NavItems);
        Assert.Null(_shell.CurrentUser);
        Assert.Equal("", _shell.Login.Username);
    }

    [Fact]
    public async Task Idle_timeout_signs_out_but_activity_postpones_it()
    {
        await SignIn();
        _clock.Advance(TimeSpan.FromMinutes(14));
        _shell.NotifyActivity();
        _clock.Advance(TimeSpan.FromMinutes(14));
        await _shell.TickAsync();
        Assert.Equal(ShellState.Main, _shell.State);

        _clock.Advance(TimeSpan.FromMinutes(2));
        await _shell.TickAsync();
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Contains("inactivity", _shell.Notice);
        Assert.Equal(1, _svc.LogoutCalls);
    }

    [Fact]
    public async Task Windows_lock_signs_out()
    {
        await SignIn();
        await _shell.OnSessionLockedAsync();
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Contains("locked", _shell.Notice);
    }

    [Fact]
    public async Task Service_side_session_end_returns_to_login_without_another_logout_call()
    {
        await SignIn();
        _svc.RaiseExpired();
        await Task.Yield();
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.Equal(0, _svc.LogoutCalls);
        Assert.Contains("session has ended", _shell.Notice);
    }

    [Fact]
    public async Task Forced_password_change_blocks_main_ui_then_requires_a_fresh_login()
    {
        _svc.MustChange = true;
        await SignIn("Operator");
        Assert.Equal(ShellState.ChangePassword, _shell.State);
        Assert.Empty(_shell.NavItems);

        _shell.ForcedChange.Current = "pw"; _shell.ForcedChange.New = "New-pass-1234!"; _shell.ForcedChange.Confirm = "New-pass-1234!";
        await _shell.ForcedChange.ChangeCommand.ExecuteAsync(null);
        Assert.Equal(ShellState.Login, _shell.State);
        Assert.False(_svc.HasSession);
        Assert.Contains("Password changed", _shell.Notice);
    }

    [Fact]
    public async Task Change_password_validates_matching_and_reports_service_errors()
    {
        _svc.MustChange = true;
        await SignIn("Operator");
        _shell.ForcedChange.Current = "wrong"; _shell.ForcedChange.New = "New-pass-1234!"; _shell.ForcedChange.Confirm = "other";
        await _shell.ForcedChange.ChangeCommand.ExecuteAsync(null);
        Assert.Contains("do not match", _shell.ForcedChange.ErrorMessage);

        _shell.ForcedChange.Current = "wrong"; _shell.ForcedChange.New = "New-pass-1234!"; _shell.ForcedChange.Confirm = "New-pass-1234!";
        await _shell.ForcedChange.ChangeCommand.ExecuteAsync(null);
        Assert.Equal("Current password is incorrect.", _shell.ForcedChange.ErrorMessage);
        Assert.Equal(ShellState.ChangePassword, _shell.State);
    }

    [Fact]
    public async Task Device_log_row_can_seed_a_rule_and_navigates_to_rules()
    {
        _svc.LogRows.Add(new DeviceLogRow(5, _clock.UtcNow, "device.connected",
            "{\"vendorId\":\"0951\",\"productId\":\"1666\",\"serial\":\"S1\"}"));
        _svc.LogRows.Add(new DeviceLogRow(6, _clock.UtcNow, "heartbeat", "{}"));
        await SignIn();
        var log = _shell.DeviceLog!;
        await log.LoadAsync();
        Assert.Equal(2, log.Rows.Count);

        log.SelectedRow = log.Rows[1];
        log.CreateRuleFromSelectedCommand.Execute(null);
        Assert.Contains("not a device event", log.ErrorMessage);

        log.SelectedRow = log.Rows[0];
        log.CreateRuleFromSelectedCommand.Execute(null);
        Assert.Equal("Device Rules", _shell.SelectedNav!.Title);
        Assert.Equal("Serial", _shell.Rules!.MatchType);
        Assert.Equal("0951:1666:S1", _shell.Rules.Value);
    }

    [Fact]
    public async Task Device_log_filter_and_verify_failure_message()
    {
        _svc.LogRows.Add(new DeviceLogRow(1, _clock.UtcNow, "device.connected", "{\"name\":\"SanDisk\"}"));
        _svc.LogRows.Add(new DeviceLogRow(2, _clock.UtcNow, "heartbeat", "{}"));
        await SignIn();
        var log = _shell.DeviceLog!;
        await log.LoadAsync();
        log.Filter = "sandisk";
        Assert.Single(log.Rows);
        await log.VerifyCommand.ExecuteAsync(null);
        Assert.Contains("INTEGRITY FAILURE at record 7", log.VerifyText);
    }
}

public class DashboardTests
{
    private readonly Clock _clock = new();
    private readonly FakeService _svc;
    private DashboardViewModel Make(string role)
    {
        var u = new UserInfo(1, "u", "U", role, true, false, null, null);
        return new DashboardViewModel(_svc, _clock, u);
    }

    public DashboardTests() => _svc = new FakeService(_clock);

    [Fact]
    public async Task Unblock_requires_reauth_and_a_correct_password()
    {
        var d = Make("Operator");
        await d.LoadAsync();
        Assert.True(d.IsBlocked);
        Assert.Equal(120, d.SelectedMinutes);

        await d.UnblockCommand.ExecuteAsync(null);
        Assert.Contains("Re-enter your password", d.ErrorMessage);

        d.ReauthPassword = "wrong";
        await d.UnblockCommand.ExecuteAsync(null);
        Assert.Equal("Password is incorrect.", d.ErrorMessage);
        Assert.True(_svc.IsBlocked);
        Assert.Equal("", d.ReauthPassword);

        d.ReauthPassword = "pw";
        await d.UnblockCommand.ExecuteAsync(null);
        Assert.False(d.IsBlocked);
        Assert.Equal(120, _svc.LastUnblockMinutes);
        Assert.Contains("UNBLOCKED", d.StatusText);
        Assert.Equal("Blocks automatically in 02:00:00", d.CountdownText);
    }

    [Fact]
    public async Task Viewer_cannot_change_state()
    {
        var d = Make("Viewer");
        await d.LoadAsync();
        Assert.False(d.CanChangeState);
        d.ReauthPassword = "pw";
        await d.UnblockCommand.ExecuteAsync(null);
        Assert.True(_svc.IsBlocked);
        await d.BlockNowCommand.ExecuteAsync(null);
    }

    [Fact]
    public async Task Selectable_duration_is_capped_by_role()
    {
        var op = Make("Operator"); await op.LoadAsync();
        Assert.Equal(120, op.MaxSelectableMinutes);
        var admin = Make("Admin"); await admin.LoadAsync();
        Assert.Equal(600, admin.MaxSelectableMinutes);

        op.SelectedMinutes = 121; op.ReauthPassword = "pw";
        await op.UnblockCommand.ExecuteAsync(null);
        Assert.Contains("between 5 and 120", op.ErrorMessage);
        Assert.True(_svc.IsBlocked);
    }

    [Fact]
    public async Task Countdown_ticks_down_and_warns_at_ten_minutes_and_one_minute_once_each()
    {
        var d = Make("Admin");
        var warnings = new List<string>();
        d.Warning += warnings.Add;
        _svc.IsBlocked = false;
        _svc.Expires = _clock.UtcNow.AddMinutes(12);
        await d.LoadAsync();
        Assert.Equal("Blocks automatically in 00:12:00", d.CountdownText);

        _clock.Advance(TimeSpan.FromMinutes(2) + TimeSpan.FromSeconds(1));
        await d.TickAsync(); await d.TickAsync();
        Assert.Single(warnings);
        Assert.Contains("10 minutes", warnings[0]);

        _clock.Advance(TimeSpan.FromMinutes(9));
        await d.TickAsync(); await d.TickAsync();
        Assert.Equal(2, warnings.Count);
        Assert.Contains("1 minute", warnings[1]);
    }

    [Fact]
    public async Task At_expiry_the_dashboard_rereads_state_and_shows_blocked()
    {
        var d = Make("Admin");
        _svc.IsBlocked = false;
        _svc.Expires = _clock.UtcNow.AddMinutes(1);
        await d.LoadAsync();

        _svc.IsBlocked = true; _svc.Expires = null; // the service auto-blocked
        _clock.Advance(TimeSpan.FromMinutes(1));
        await d.TickAsync();
        Assert.True(d.IsBlocked);
        Assert.Equal("", d.CountdownText);
    }

    [Fact]
    public async Task Status_is_polled_every_fifteen_seconds_not_every_tick()
    {
        var d = Make("Admin");
        await d.LoadAsync();
        var calls = _svc.StatusCalls;
        _clock.Advance(TimeSpan.FromSeconds(5)); await d.TickAsync();
        Assert.Equal(calls, _svc.StatusCalls);
        _clock.Advance(TimeSpan.FromSeconds(11)); await d.TickAsync();
        Assert.Equal(calls + 1, _svc.StatusCalls);
    }
}

public class AdminScreenTests
{
    private readonly FakeService _svc = new(new Clock());

    [Fact]
    public async Task Users_create_requires_fields_and_reloads()
    {
        var vm = new UsersViewModel(_svc);
        await vm.LoadAsync();
        Assert.Equal(2, vm.Users.Count);
        await vm.CreateCommand.ExecuteAsync(null);
        Assert.NotNull(vm.ErrorMessage);

        vm.NewUsername = "carol"; vm.NewPassword = "Temp-pass-1234!";
        await vm.CreateCommand.ExecuteAsync(null);
        Assert.Equal(3, vm.Users.Count);
        Assert.Equal("", vm.NewPassword);
    }

    [Fact]
    public async Task Rules_prefill_without_serial_warns_it_matches_all_of_that_model()
    {
        var vm = new RulesViewModel(_svc);
        vm.PrefillFrom("0951", "1666", null);
        Assert.Equal("VendorProduct", vm.MatchType);
        Assert.Equal("0951:1666", vm.Value);
        Assert.Contains("no serial", vm.InfoMessage);

        vm.Action = "Allow";
        await vm.SaveCommand.ExecuteAsync(null);
        Assert.Equal("Allow", _svc.SavedRule!.Action);
        Assert.Equal("0951:1666", _svc.SavedRule.Value);
    }

    [Fact]
    public async Task Settings_uninstall_password_change_validates_input_and_wipes_secrets()
    {
        var vm = new SettingsViewModel(_svc);
        await vm.LoadAsync();
        Assert.Equal(120, vm.DurationMinutes);
        Assert.True(vm.UninstallPasswordSet);

        vm.NewUninstallPassword = "A"; vm.ConfirmUninstallPassword = "B";
        await vm.ChangeUninstallPasswordCommand.ExecuteAsync(null);
        Assert.Contains("do not match", vm.ErrorMessage);

        vm.ConfirmUninstallPassword = "A";
        await vm.ChangeUninstallPasswordCommand.ExecuteAsync(null);
        Assert.Contains("Enter the current uninstall password", vm.ErrorMessage);

        vm.CurrentUninstallPassword = "old";
        await vm.ChangeUninstallPasswordCommand.ExecuteAsync(null);
        Assert.Equal("Uninstall password changed.", vm.InfoMessage);
        Assert.Equal("", vm.NewUninstallPassword);
        Assert.Equal("", vm.CurrentUninstallPassword);
    }
}
