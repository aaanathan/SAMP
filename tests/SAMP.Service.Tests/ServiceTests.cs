using System.Text.Json;
using SAMP.Core;
using SAMP.Ipc;
using SAMP.Logging;
using SAMP.Security;
using SAMP.Service;
using SAMP.Usb;

namespace SAMP.Tests;

public sealed class ApiEnv : IDisposable
{
    public const string Pw = "Correct-Horse-9!";
    public const string UninstallPw = "Uninstall-Me-42!";
    public TestEnv E { get; } = new();
    public FakeBlocker Blocker { get; } = new();
    public FakeDevices Devices { get; } = new();
    public DeviceLog Log { get; }
    public UnblockManager Manager { get; }
    public SessionManager Sessions { get; }
    public ServiceApi Api { get; }
    public MonitorApi Monitor { get; }
    public LogMaintenance Maintenance { get; }
    public RecoveryKeyService Recovery { get; }
    public LoginThrottle Throttle { get; }
    public IntegrityMonitor Integrity { get; }
    public MaintenanceWindow Window { get; }
    public List<bool> RestrictionCalls { get; } = new();
    public string? LastRecoveryKey { get; private set; }

    public ApiEnv()
    {
        var logKey = new byte[32].Select((_, i) => (byte)(i + 7)).ToArray();
        Log = new DeviceLog(Path.Combine(E.Dir, "logs"), logKey, E.Clock, [new FileAnchorSink(Path.Combine(E.Dir, "anchors", "a.log"))]);
        var audit = new MirroringAuditLog(E.Audit, Log);
        var users = new UserService(E.Users, audit, E.Hasher, E.Policy, E.Clock);
        var uninstall = new UninstallPasswordService(E.Settings, audit, E.Hasher, E.Policy, E.Clock);
        Manager = new UnblockManager(E.Sessions, E.Rules, Blocker, Devices, E.Settings, audit, E.Clock);
        var rules = new BlockRuleService(E.Rules, Manager, audit, E.Clock);
        Sessions = new SessionManager(E.Clock);
        Maintenance = new LogMaintenance(Log, E.Settings);
        Recovery = new RecoveryKeyService(E.Settings, users, audit, E.Hasher, E.Clock);
        Throttle = new LoginThrottle(E.Clock);
        Integrity = new IntegrityMonitor(Log, audit, E.Settings);
        Window = new MaintenanceWindow(E.Clock, r => RestrictionCalls.Add(r));
        Api = new ServiceApi(users, E.Users, Sessions, Manager, rules, uninstall, audit, Log, E.Settings, Maintenance, Recovery, Throttle, Integrity, Window);
        Monitor = new MonitorApi(Manager, Devices, Log);
    }

    public IpcResponse Call(string cmd, string? token = null, object? args = null) =>
        Api.HandleAsync(new IpcRequest(cmd, token, args == null ? null : JsonSerializer.SerializeToElement(args, IpcJson.Options)), default).Result;

    public IpcResponse CallMonitor(string cmd, object? args = null) =>
        Monitor.HandleAsync(new IpcRequest(cmd, null, args == null ? null : JsonSerializer.SerializeToElement(args, IpcJson.Options)), default).Result;

    public void Setup()
    {
        var r = Call("setup.complete", args: new { username = "admin", displayName = "Admin", password = Pw, uninstallPassword = UninstallPw });
        Assert.True(r.Ok, r.Error);
        LastRecoveryKey = r.Data!.Value.GetProperty("recoveryKey").GetString();
    }

    public string Login(string user, string pw = Pw)
    {
        var r = Call("login", args: new { username = user, password = pw });
        Assert.True(r.Ok, r.Error);
        return r.Data!.Value.GetProperty("token").GetString()!;
    }

    public string AdminToken() { Setup(); return Login("admin"); }

    public string OperatorToken(string adminToken, string name = "oper")
    {
        Assert.True(Call("users.create", adminToken, new { username = name, displayName = "Op", password = Pw, role = "Operator", mustChangePassword = false }).Ok);
        return Login(name);
    }

    public void Dispose() { Log.Dispose(); E.Dispose(); }
}

public class ServiceApiTests : IDisposable
{
    private readonly ApiEnv _a = new();
    public void Dispose() => _a.Dispose();

    [Fact]
    public void Setup_runs_once_and_requires_a_valid_uninstall_password()
    {
        Assert.True(_a.Call("setup.status").Data!.Value.GetProperty("needsSetup").GetBoolean());
        var weak = _a.Call("setup.complete", args: new { username = "admin", password = ApiEnv.Pw, uninstallPassword = "weak" });
        Assert.Equal("password_policy", weak.Code);

        _a.Setup();
        Assert.False(_a.Call("setup.status").Data!.Value.GetProperty("needsSetup").GetBoolean());
        Assert.False(_a.Call("setup.complete", args: new { username = "evil", password = ApiEnv.Pw, uninstallPassword = ApiEnv.UninstallPw }).Ok);
    }

    [Fact]
    public void Nothing_works_without_a_session_except_the_public_commands()
    {
        _a.Setup();
        foreach (var cmd in new[] { "status", "unblock", "block", "users.list", "devicelog.query", "settings.get", "me" })
            Assert.Equal("unauthorized", _a.Call(cmd).Code);
        Assert.Equal("unauthorized", _a.Call("status", "forged-token").Code);
        Assert.True(_a.Call("status.public").Ok);
    }

    [Fact]
    public void Login_failures_return_typed_codes_and_lockout_applies()
    {
        _a.Setup();
        Assert.Equal("invalid_credentials", _a.Call("login", args: new { username = "admin", password = "nope" }).Code);
        Assert.Equal("invalid_credentials", _a.Call("login", args: new { username = "ghost", password = "nope" }).Code);
        for (var i = 0; i < 4; i++) _a.Call("login", args: new { username = "admin", password = "nope" });
        Assert.Equal("locked", _a.Call("login", args: new { username = "admin", password = ApiEnv.Pw }).Code);
    }

    [Fact]
    public void Logout_revokes_the_token_immediately()
    {
        var t = _a.AdminToken();
        Assert.True(_a.Call("status", t).Ok);
        Assert.True(_a.Call("logout", t).Ok);
        Assert.Equal("unauthorized", _a.Call("status", t).Code);
    }

    [Fact]
    public void Idle_timeout_ends_the_session()
    {
        var t = _a.AdminToken();
        _a.E.Clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal("unauthorized", _a.Call("status", t).Code);
    }

    [Fact]
    public void Operator_can_unblock_and_block_but_not_use_admin_commands_or_see_logs()
    {
        var admin = _a.AdminToken();
        var op = _a.OperatorToken(admin);

        Assert.True(_a.Call("unblock", op).Ok);
        Assert.False(_a.Blocker.Blocked);
        Assert.False(_a.Call("status", op).Data!.Value.GetProperty("isBlocked").GetBoolean());
        Assert.True(_a.Call("block", op).Ok);
        Assert.True(_a.Blocker.Blocked);

        foreach (var cmd in new[] { "users.list", "rules.list", "settings.get", "audit.query", "devicelog.query", "devicelog.verify", "audit.verify" })
            Assert.Equal("unauthorized", _a.Call(cmd, op).Code);
        Assert.Equal("unauthorized", _a.Call("uninstall.change", op, new { current = ApiEnv.UninstallPw, @new = "Another-Pass-88!" }).Code);
        Assert.Equal("unauthorized", _a.Call("settings.setDuration", op, new { minutes = 10 }).Code);
    }

    [Fact]
    public void Viewer_cannot_unblock()
    {
        var admin = _a.AdminToken();
        _a.Call("users.create", admin, new { username = "view", password = ApiEnv.Pw, role = "Viewer", mustChangePassword = false });
        var v = _a.Login("view");
        Assert.True(_a.Call("status", v).Ok);
        Assert.Equal("unauthorized", _a.Call("unblock", v).Code);
    }

    [Fact]
    public void Admin_reads_the_device_log_which_mirrors_audit_events_and_verifies()
    {
        var admin = _a.AdminToken();
        _a.Call("unblock", admin, new { minutes = 30 });
        var q = _a.Call("devicelog.query", admin, new { limit = 50 });
        Assert.True(q.Ok);
        Assert.Contains(q.Data!.Value.EnumerateArray(), r => r.GetProperty("payload").GetString()!.Contains("usb.unblock"));
        Assert.True(_a.Call("devicelog.verify", admin).Data!.Value.GetProperty("isValid").GetBoolean());
        Assert.True(_a.Call("audit.verify", admin).Data!.Value.GetProperty("isValid").GetBoolean());
    }

    [Fact]
    public void Disabling_a_user_kills_their_sessions()
    {
        var admin = _a.AdminToken();
        var op = _a.OperatorToken(admin);
        var id = _a.E.Users.GetByUsername("oper")!.Id;
        Assert.True(_a.Call("users.setActive", admin, new { userId = id, active = false }).Ok);
        Assert.Equal("unauthorized", _a.Call("status", op).Code);
    }

    [Fact]
    public void Must_change_password_blocks_everything_but_password_change()
    {
        var admin = _a.AdminToken();
        _a.Call("users.create", admin, new { username = "newbie", password = ApiEnv.Pw, role = "Operator" }); // mustChange defaults true
        var t = _a.Login("newbie");
        Assert.Equal("unauthorized", _a.Call("unblock", t).Code);
        Assert.True(_a.Call("password.change", t, new { current = ApiEnv.Pw, @new = "Brand-New-Pass-5!" }).Ok);
        // a password change revokes every session of that user: they must sign in again with the new password
        Assert.Equal("unauthorized", _a.Call("unblock", t).Code);
        var t2 = _a.Login("newbie", "Brand-New-Pass-5!");
        Assert.True(_a.Call("unblock", t2).Ok);
    }

    [Fact]
    public void Admin_changes_duration_and_it_is_used_for_the_next_window()
    {
        var admin = _a.AdminToken();
        Assert.Equal(120, _a.Call("settings.get", admin).Data!.Value.GetProperty("durationMinutes").GetInt32());
        Assert.True(_a.Call("settings.setDuration", admin, new { minutes = 45 }).Ok);
        var r = _a.Call("unblock", admin);
        var left = _a.Call("status", admin).Data!.Value.GetProperty("remainingSeconds").GetDouble();
        Assert.Equal(45 * 60, left, 1);
        Assert.Equal("invalid", _a.Call("settings.setDuration", admin, new { minutes = 3 }).Code);
    }

    [Fact]
    public void Rules_api_validates_and_applies_to_os_policy()
    {
        var admin = _a.AdminToken();
        var bad = _a.Call("rules.add", admin, new { name = "x", action = "Block", matchType = "VendorId", value = "zz" });
        Assert.Equal("invalid", bad.Code);
        var before = _a.Blocker.ApplyCount;
        Assert.True(_a.Call("rules.add", admin, new { name = "ban", action = "Block", matchType = "VendorId", value = "0951" }).Ok);
        Assert.True(_a.Blocker.ApplyCount > before);
        Assert.Single(_a.Call("rules.list", admin).Data!.Value.EnumerateArray());
    }

    [Fact]
    public void Uninstall_verify_is_public_but_locks_out_and_change_is_admin_only()
    {
        var admin = _a.AdminToken();
        Assert.Equal("Wrong", _a.Call("uninstall.verify", args: new { password = "x" }).Data!.Value.GetProperty("status").GetString());
        Assert.Equal("Ok", _a.Call("uninstall.verify", args: new { password = ApiEnv.UninstallPw }).Data!.Value.GetProperty("status").GetString());

        Assert.True(_a.Call("uninstall.change", admin, new { current = ApiEnv.UninstallPw, @new = "Another-Pass-88!" }).Ok);
        Assert.Equal("Ok", _a.Call("uninstall.verify", args: new { password = "Another-Pass-88!" }).Data!.Value.GetProperty("status").GetString());

        // forgot the uninstall password: Admin re-enters their login password instead
        Assert.True(_a.Call("uninstall.change", admin, new { adminPassword = ApiEnv.Pw, @new = ApiEnv.UninstallPw }).Ok);
        Assert.Equal("unauthorized", _a.Call("uninstall.change", admin, new { current = "wrong", @new = "Yet-Another-Pw-1!" }).Code);

        for (var i = 0; i < 3; i++) _a.Call("uninstall.verify", args: new { password = "bad" });
        Assert.Equal("Locked", _a.Call("uninstall.verify", args: new { password = ApiEnv.UninstallPw }).Data!.Value.GetProperty("status").GetString());
    }

    [Fact]
    public void External_log_path_must_be_absolute()
    {
        var admin = _a.AdminToken();
        Assert.Equal("invalid", _a.Call("settings.setExternalLogPath", admin, new { path = "relative/dir" }).Code);
        var abs = Path.Combine(_a.E.Dir, "ext");
        Assert.True(_a.Call("settings.setExternalLogPath", admin, new { path = abs }).Ok);
        Assert.Equal(abs, _a.Call("settings.get", admin).Data!.Value.GetProperty("externalLogPath").GetString());
    }

    [Fact]
    public void Responses_never_contain_password_hashes()
    {
        var admin = _a.AdminToken();
        var json = _a.Call("users.list", admin).Data!.Value.GetRawText();
        Assert.DoesNotContain("argon2", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("passwordHash", json, StringComparison.OrdinalIgnoreCase);
    }
}

public class MonitorApiTests : IDisposable
{
    private readonly ApiEnv _a = new();
    public void Dispose() => _a.Dispose();

    private static object Stick(bool enabled = true) => new
    {
        device = new { instanceId = @"USB\VID_0951&PID_1666\S1", vendorId = "0951", productId = "1666", serial = "S1", classCode = "08", name = "Stick", massStorage = true, enabled },
        windowsUser = "PC\\alice",
    };

    [Fact]
    public void Mass_storage_arriving_while_blocked_is_disabled_and_logged_with_decision()
    {
        _a.Manager.Reconcile();
        var r = _a.CallMonitor("device.arrived", Stick());
        Assert.True(r.Ok, r.Error);
        Assert.Equal("Block", r.Data!.Value.GetProperty("decision").GetString());
        Assert.Contains(_a.Devices.Calls, c => c.Id.Contains("S1") && !c.Enabled);

        var rec = _a.Log.Query(null, null, 10).First(x => x.EventType == "device.connected");
        Assert.Contains("\"serial\":\"S1\"", rec.Payload);
        Assert.Contains("\"windowsUser\":\"PC\\\\alice\"", rec.Payload);
        Assert.Contains("\"insideUnblockSession\":false", rec.Payload);
    }

    [Fact]
    public void During_an_unblock_session_the_device_is_allowed_and_log_says_so()
    {
        var admin = _a.AdminToken();
        _a.Call("unblock", admin);
        var r = _a.CallMonitor("device.arrived", Stick());
        Assert.Equal("Allow", r.Data!.Value.GetProperty("decision").GetString());
        Assert.DoesNotContain(_a.Devices.Calls, c => !c.Enabled);
        Assert.Contains("\"insideUnblockSession\":true", _a.Log.Query(null, null, 1)[0].Payload);
    }

    [Fact]
    public void Removal_present_snapshot_and_unknown_commands()
    {
        Assert.True(_a.CallMonitor("device.removed", Stick()).Ok);
        Assert.True(_a.CallMonitor("device.present", Stick(enabled: false)).Ok);
        Assert.False(_a.CallMonitor("nope").Ok);
        Assert.False(_a.CallMonitor("device.arrived", new { }).Ok);
        Assert.True(_a.Log.Verify().IsValid);
    }
}

public class LogMaintenanceTests : IDisposable
{
    private readonly ApiEnv _a = new();
    public void Dispose() => _a.Dispose();

    [Fact]
    public void Replicates_closed_days_to_the_external_path_and_only_prunes_after_copy()
    {
        var ext = Path.Combine(_a.E.Dir, "ext");
        _a.E.Settings.Set(SettingKeys.ExternalLogPath, ext);
        _a.E.Clock.UtcNow = new DateTime(2026, 1, 1, 9, 0, 0, DateTimeKind.Utc);
        _a.Log.Append("old");
        _a.E.Clock.Advance(TimeSpan.FromDays(40));
        _a.Log.Append("recent");

        _a.Maintenance.Run();
        Assert.Single(Directory.GetFiles(ext, "*.db"));
        Assert.Single(_a.Log.Days()); // the old file was pruned only because the copy exists
        Assert.True(_a.Log.Verify().IsValid);
    }

    [Fact]
    public void Unreachable_external_path_does_not_stop_local_logging_and_keeps_old_files()
    {
        var blocker = Path.Combine(_a.E.Dir, "afile");
        File.WriteAllText(blocker, "x"); // a file where a directory is expected
        _a.E.Settings.Set(SettingKeys.ExternalLogPath, Path.Combine(blocker, "sub"));
        _a.E.Clock.UtcNow = new DateTime(2026, 1, 1, 9, 0, 0, DateTimeKind.Utc);
        _a.Log.Append("old");
        _a.E.Clock.Advance(TimeSpan.FromDays(40));
        _a.Log.Append("recent");

        _a.Maintenance.Run();
        Assert.Equal(2, _a.Log.Days().Count);
        Assert.Contains(_a.Log.Query(null, null, 20), r => r.EventType == "log.replicate_failed");
    }
}

public class PipeTests : IDisposable
{
    private readonly ApiEnv _a = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _name = "samp-test-" + Guid.NewGuid().ToString("N");
    private readonly Task _server;

    public PipeTests()
    {
        _server = new PipeServer(_name, _a.Api, PipeAccessMode.AuthenticatedUsers).RunAsync(_cts.Token);
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _server.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        _a.Dispose();
    }

    [Fact]
    public async Task Full_round_trip_login_status_unblock_over_a_named_pipe()
    {
        _a.Setup();
        var c = new PipeClient(_name);
        var login = await c.SendAsync("login", null, new { username = "admin", password = ApiEnv.Pw });
        Assert.True(login.Ok, login.Error);
        var token = login.Data!.Value.GetProperty("token").GetString();

        var st = await c.SendAsync("status", token);
        Assert.True(st.Data!.Value.GetProperty("isBlocked").GetBoolean());
        Assert.True((await c.SendAsync("unblock", token)).Ok);
        Assert.False((await c.SendAsync("status", token)).Data!.Value.GetProperty("isBlocked").GetBoolean());
        Assert.Equal("unauthorized", (await c.SendAsync("status", null)).Code);
    }

    [Fact]
    public async Task Malformed_input_gets_a_bad_request_and_the_server_keeps_working()
    {
        await using (var raw = new System.IO.Pipes.NamedPipeClientStream(".", _name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous))
        {
            await raw.ConnectAsync(5000);
            using var w = new StreamWriter(raw, leaveOpen: true) { AutoFlush = true };
            using var r = new StreamReader(raw, leaveOpen: true);
            await w.WriteLineAsync("this is not json");
            var line = await r.ReadLineAsync();
            Assert.Contains("bad_request", line);
        }
        Assert.True((await new PipeClient(_name).SendAsync("setup.status")).Ok);
    }
}

public class ClientContractTests : IDisposable
{
    private readonly ApiEnv _a = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _name = "samp-client-" + Guid.NewGuid().ToString("N");
    private readonly Task _server;
    private readonly SAMP.Client.PipeSampService _c;

    public ClientContractTests()
    {
        _server = new PipeServer(_name, _a.Api, PipeAccessMode.AuthenticatedUsers).RunAsync(_cts.Token);
        _c = new SAMP.Client.PipeSampService(new PipeClient(_name));
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _server.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        _a.Dispose();
    }

    [Fact]
    public async Task Typed_client_works_end_to_end_against_the_real_service_api()
    {
        Assert.True((await _c.NeedsSetupAsync()).Value);
        var bad = await _c.SetupAsync("admin", "Admin", ApiEnv.Pw, "weak");
        Assert.False(bad.Ok);
        Assert.Equal("password_policy", bad.Code);
        Assert.True((await _c.SetupAsync("admin", "Admin", ApiEnv.Pw, ApiEnv.UninstallPw)).Ok);
        Assert.False((await _c.NeedsSetupAsync()).Value);

        var login = await _c.LoginAsync("admin", ApiEnv.Pw);
        Assert.True(login.Ok, login.Error);
        Assert.True(login.Value!.User.IsAdmin);
        Assert.True(_c.HasSession);

        Assert.True((await _c.VerifyPasswordAsync(ApiEnv.Pw)).Value);
        Assert.False((await _c.VerifyPasswordAsync("wrong")).Value);

        var st = await _c.GetStatusAsync();
        Assert.True(st.Value!.IsBlocked);
        Assert.Equal(120, st.Value.DurationMinutes);
        Assert.True((await _c.UnblockAsync(30)).Ok);
        var after = (await _c.GetStatusAsync()).Value!;
        Assert.False(after.IsBlocked);
        Assert.InRange(after.RemainingSeconds!.Value, 29 * 60, 30 * 60);
        Assert.True((await _c.BlockAsync()).Ok);

        var created = await _c.CreateUserAsync("oper", "Op", ApiEnv.Pw, "Operator", false);
        Assert.True(created.Ok, created.Error);
        Assert.Equal(2, (await _c.ListUsersAsync()).Value!.Count);

        Assert.True((await _c.SaveRuleAsync(new(0, "ban", true, "Block", "VendorId", "0951", "Always", null))).Ok);
        var rules = (await _c.ListRulesAsync()).Value!;
        Assert.Equal("VendorId", rules.Single().MatchType); // enums round-trip as names
        Assert.Equal("Block", rules.Single().Action);

        var settings = (await _c.GetSettingsAsync()).Value!;
        Assert.True(settings.UninstallPasswordSet);
        Assert.True((await _c.SetDurationAsync(45, false)).Ok);

        Assert.True((await _c.QueryAuditAsync(50)).Value!.Count > 0);
        Assert.True((await _c.VerifyAuditAsync()).Value!.IsValid);
        Assert.True((await _c.QueryDeviceLogAsync(null, null, 50)).Value!.Count > 0);
        Assert.True((await _c.VerifyDeviceLogAsync()).Value!.IsValid);

        Assert.True((await _c.LogoutAsync()).Ok);
        Assert.False(_c.HasSession);
    }

    [Fact]
    public async Task Insufficient_role_does_not_end_the_session_but_revocation_does()
    {
        _a.Setup();
        var adminToken = _a.Login("admin");
        _a.OperatorToken(adminToken);
        var expired = 0;
        _c.SessionExpired += () => expired++;

        Assert.True((await _c.LoginAsync("oper", ApiEnv.Pw)).Ok);
        var denied = await _c.ListUsersAsync();
        Assert.Equal("unauthorized", denied.Code);
        Assert.Equal(0, expired);
        Assert.True(_c.HasSession);

        _a.Sessions.RevokeAllForUser(_a.E.Users.GetByUsername("oper")!.Id);
        await _c.GetStatusAsync();
        Assert.Equal(1, expired);
        Assert.False(_c.HasSession);
    }

    [Fact]
    public async Task Unreachable_service_gives_a_friendly_error()
    {
        var down = new SAMP.Client.PipeSampService(new PipeClient("samp-does-not-exist", TimeSpan.FromMilliseconds(300)));
        var r = await down.NeedsSetupAsync();
        Assert.False(r.Ok);
        Assert.Equal("unreachable", r.Code);
    }
}

public class Phase4Tests : IDisposable
{
    private readonly ApiEnv _a = new();
    public void Dispose() => _a.Dispose();

    [Fact]
    public void Setup_returns_a_recovery_key_and_recovery_reset_works_through_the_api()
    {
        _a.Setup();
        var key = _a.LastRecoveryKey!;
        Assert.Matches("^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$", key);

        var bad = _a.Call("recovery.reset", args: new { recoveryKey = "AAAA-AAAA", username = "admin", newPassword = "Recovered-Pass-77!" });
        Assert.Equal("invalid_recovery_key", bad.Code);

        var ok = _a.Call("recovery.reset", args: new { recoveryKey = key, username = "admin", newPassword = "Recovered-Pass-77!" });
        Assert.True(ok.Ok, ok.Error);
        Assert.NotEqual(key, ok.Data!.Value.GetProperty("recoveryKey").GetString());
        Assert.Equal("invalid_credentials", _a.Call("login", args: new { username = "admin", password = ApiEnv.Pw }).Code);
        Assert.True(_a.Call("login", args: new { username = "admin", password = "Recovered-Pass-77!" }).Ok);
    }

    [Fact]
    public void Recovery_revokes_existing_sessions_of_that_admin()
    {
        var token = _a.AdminToken();
        _a.Call("recovery.reset", args: new { recoveryKey = _a.LastRecoveryKey, username = "admin", newPassword = "Recovered-Pass-77!" });
        Assert.Equal("unauthorized", _a.Call("status", token).Code);
    }

    [Fact]
    public void Global_login_throttle_stops_guessing_across_unknown_usernames_then_recovers()
    {
        _a.Setup();
        for (var i = 0; i < 10; i++)
            Assert.Equal("invalid_credentials", _a.Call("login", args: new { username = "user" + i, password = "x" }).Code);
        // blocked now, even for the correct credentials
        Assert.Equal("too_many_attempts", _a.Call("login", args: new { username = "admin", password = ApiEnv.Pw }).Code);
        Assert.Equal("too_many_attempts", _a.Call("recovery.reset", args: new { recoveryKey = _a.LastRecoveryKey, username = "admin", newPassword = "Recovered-Pass-77!" }).Code);

        _a.E.Clock.Advance(TimeSpan.FromSeconds(31));
        Assert.True(_a.Call("login", args: new { username = "admin", password = ApiEnv.Pw }).Ok);
    }

    [Fact]
    public void Integrity_monitor_alerts_on_tampering_surfaces_it_and_needs_admin_acknowledgement()
    {
        var admin = _a.AdminToken();
        _a.Integrity.Check();
        Assert.False(_a.Call("status.public").Data!.Value.GetProperty("integrityAlert").GetBoolean());

        // attacker alters the newest day file after the service rolled to a new day (so it is closed)
        _a.Log.Append("device.connected", new { serial = "A" });
        _a.E.Clock.Advance(TimeSpan.FromDays(1));
        _a.Log.Append("device.connected", new { serial = "B" });
        var yesterday = Path.Combine(_a.E.Dir, "logs", DeviceLog.FileName(DateOnly.FromDateTime(_a.E.Clock.UtcNow.AddDays(-1))));
        File.Delete(yesterday);
        admin = _a.Login("admin"); // a day passed: the old session timed out

        _a.Integrity.Check();
        Assert.True(_a.Call("status.public").Data!.Value.GetProperty("integrityAlert").GetBoolean());
        Assert.True(_a.Call("status", admin).Data!.Value.GetProperty("integrityAlert").GetBoolean());
        Assert.Contains("devicelog", _a.Call("integrity.get", admin).Data!.Value.GetProperty("details").GetString());
        Assert.Contains(_a.Log.Query(null, null, 50), r => r.EventType == "integrity.failed");

        var op = _a.OperatorToken(admin);
        Assert.Equal("unauthorized", _a.Call("integrity.acknowledge", op).Code);
        Assert.True(_a.Call("integrity.acknowledge", admin).Ok);
        Assert.False(_a.Call("status.public").Data!.Value.GetProperty("integrityAlert").GetBoolean());

        // same unchanged damage does not re-alert, new damage would
        _a.Integrity.Check();
        Assert.False(_a.Integrity.IsAlerting);
    }

    [Fact]
    public void Unclean_shutdown_is_recorded_at_the_next_start()
    {
        StartupChecks.RecordStart(_a.Log);            // first ever start: nothing to report
        Assert.DoesNotContain(_a.Log.Query(null, null, 20), r => r.EventType == "service.unclean_shutdown");

        _a.Log.Heartbeat();                           // ...then the process dies without "service.stop"
        StartupChecks.RecordStart(_a.Log);
        Assert.Contains(_a.Log.Query(null, null, 20), r => r.EventType == "service.unclean_shutdown");

        _a.Log.Append("service.stop");                // clean stop: no report
        StartupChecks.RecordStart(_a.Log);
        Assert.Equal(1, _a.Log.Query(null, null, 50).Count(r => r.EventType == "service.unclean_shutdown"));
    }

    [Fact]
    public void Audit_mirroring_survives_a_failing_device_log()
    {
        var admin = _a.AdminToken();
        _a.Log.Dispose(); // simulate the log file becoming unusable
        var r = _a.Call("unblock", admin);
        Assert.True(r.Ok, r.Error);           // the action still completes and is in the audit table
        Assert.Contains(_a.E.Audit.Query(10), x => x.Action == "usb.unblock");
    }

    [Fact]
    public void Service_sddl_gives_admins_read_only_and_system_full_control()
    {
        var sddl = ServiceSecurity.RestrictedSddl;
        Assert.Contains("(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)", sddl);
        // the relaxed descriptor used during maintenance lets Administrators stop and delete
        var relaxedAdmins = ServiceSecurity.RelaxedSddl.Split('(').First(x => x.EndsWith(";;;BA)"));
        Assert.Contains("WP", relaxedAdmins);
        Assert.Contains("SD", relaxedAdmins);
        var admins = sddl.Split('(').First(x => x.EndsWith(";;;BA)"));
        Assert.DoesNotContain("WP", admins);   // no stop
        Assert.DoesNotContain("SD", admins);   // no delete
        Assert.DoesNotContain("DC", admins);   // no config change
        Assert.DoesNotContain("WD", admins);   // no DACL change
    }
}

public class PipeTimeoutTests
{
    [Fact]
    public async Task Silent_clients_are_dropped_and_do_not_block_others()
    {
        using var a = new ApiEnv();
        using var cts = new CancellationTokenSource();
        var name = "samp-timeout-" + Guid.NewGuid().ToString("N");
        var server = new PipeServer(name, a.Api, PipeAccessMode.AuthenticatedUsers, TimeSpan.FromMilliseconds(300)).RunAsync(cts.Token);

        await using var idle = new System.IO.Pipes.NamedPipeClientStream(".", name, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous);
        await idle.ConnectAsync(5000);
        await Task.Delay(800); // never sends anything

        using var reader = new StreamReader(idle);
        var eof = await Task.WhenAny(reader.ReadLineAsync(), Task.Delay(3000));
        Assert.True(eof.IsCompleted);                       // server closed the idle connection
        Assert.True((await new PipeClient(name).SendAsync("setup.status")).Ok);

        cts.Cancel();
        try { await server.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception e) when (e is TimeoutException or AggregateException or OperationCanceledException) { }
    }
}

public class UninstallGuardTests : IDisposable
{
    private readonly ApiEnv _a = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly string _name = "samp-guard-" + Guid.NewGuid().ToString("N");
    private readonly Task _server;

    public UninstallGuardTests()
    {
        _server = new PipeServer(_name, _a.Api, PipeAccessMode.AuthenticatedUsers).RunAsync(_cts.Token);
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _server.Wait(TimeSpan.FromSeconds(5)); } catch (AggregateException) { }
        _a.Dispose();
    }

    private Task<(int Code, string Message)> Verify(string? pw, Func<bool>? start = null, int retries = 0) =>
        SAMP.UninstallGuard.GuardRunner.VerifyAsync(pw, new PipeClient(_name, TimeSpan.FromSeconds(2)), start, retries, TimeSpan.FromMilliseconds(10));

    [Fact]
    public void Password_file_is_read_as_utf8_trimmed_and_then_destroyed()
    {
        var f = Path.Combine(_a.E.Dir, "pw.txt");
        File.WriteAllText(f, "Pässwörd-42!\r\n");
        Assert.Equal("Pässwörd-42!", SAMP.UninstallGuard.GuardRunner.ReadAndDestroyPasswordFile(f));
        Assert.False(File.Exists(f));
        Assert.Null(SAMP.UninstallGuard.GuardRunner.ReadAndDestroyPasswordFile(f));   // missing
        File.WriteAllText(f, "\r\n");
        Assert.Null(SAMP.UninstallGuard.GuardRunner.ReadAndDestroyPasswordFile(f));   // empty
        Assert.False(File.Exists(f));
    }

    [Fact]
    public async Task A_correct_password_opens_the_maintenance_window_through_the_guard()
    {
        _a.Setup();
        Assert.Equal(0, (await Verify(ApiEnv.UninstallPw)).Code);
        Assert.True(_a.Window.IsOpen);
        Assert.False((await Verify("wrong")).Code == 0);
    }

    [Fact]
    public async Task Correct_password_lets_the_uninstall_continue()
    {
        _a.Setup();
        Assert.Equal(0, (await Verify(ApiEnv.UninstallPw)).Code);
    }

    [Fact]
    public async Task Wrong_or_missing_password_aborts_with_a_message()
    {
        _a.Setup();
        var wrong = await Verify("nope");
        Assert.Equal(1, wrong.Code);
        Assert.Contains("incorrect", wrong.Message);
        Assert.Equal(1, (await Verify(null)).Code);
        Assert.Equal(1, (await Verify("")).Code);
    }

    [Fact]
    public async Task Three_wrong_attempts_lock_even_the_correct_password_for_the_silent_uninstall_too()
    {
        _a.Setup();
        await Verify("a"); await Verify("b");
        Assert.Equal(2, (await Verify("c")).Code);
        Assert.Equal(2, (await Verify(ApiEnv.UninstallPw)).Code);
    }

    [Fact]
    public async Task Uninstall_is_allowed_when_setup_never_completed()
    {
        Assert.Equal(0, (await Verify("anything")).Code);
    }

    [Fact]
    public async Task Unreachable_service_fails_closed_and_the_guard_tries_to_start_it_once()
    {
        var starts = 0;
        var r = await SAMP.UninstallGuard.GuardRunner.VerifyAsync(ApiEnv.UninstallPw,
            new PipeClient("samp-nobody-home", TimeSpan.FromMilliseconds(200)), () => { starts++; return true; }, retries: 2, TimeSpan.FromMilliseconds(10));
        Assert.Equal(3, r.Code);
        Assert.Equal(1, starts);
        Assert.Contains("not running", r.Message);
    }
}


public class MaintenanceTests : IDisposable
{
    private readonly ApiEnv _a = new();
    public void Dispose() => _a.Dispose();

    [Fact]
    public void Correct_password_opens_the_window_wrong_or_locked_does_not()
    {
        _a.Setup();
        var wrong = _a.Call("maintenance.begin", args: new { password = "nope" });
        Assert.Equal("Wrong", wrong.Data!.Value.GetProperty("status").GetString());
        Assert.False(_a.Window.IsOpen);
        Assert.Empty(_a.RestrictionCalls);

        var ok = _a.Call("maintenance.begin", args: new { password = ApiEnv.UninstallPw });
        Assert.Equal("Ok", ok.Data!.Value.GetProperty("status").GetString());
        Assert.True(_a.Window.IsOpen);
        Assert.Equal([false], _a.RestrictionCalls);   // restriction lifted
        Assert.Contains(_a.E.Audit.Query(10), x => x.Action == "maintenance.begin");
    }

    [Fact]
    public void Lockout_applies_to_maintenance_attempts_too()
    {
        _a.Setup();
        for (var i = 0; i < 3; i++) _a.Call("maintenance.begin", args: new { password = "bad" });
        var r = _a.Call("maintenance.begin", args: new { password = ApiEnv.UninstallPw });
        Assert.Equal("Locked", r.Data!.Value.GetProperty("status").GetString());
        Assert.False(_a.Window.IsOpen);
    }

    [Fact]
    public void Window_closes_itself_and_restores_the_restriction()
    {
        _a.Setup();
        _a.Call("maintenance.begin", args: new { password = ApiEnv.UninstallPw });
        _a.E.Clock.Advance(TimeSpan.FromMinutes(14));
        _a.Window.Tick();
        Assert.True(_a.Window.IsOpen);

        _a.E.Clock.Advance(TimeSpan.FromMinutes(2));
        _a.Window.Tick();
        Assert.False(_a.Window.IsOpen);
        Assert.Equal([false, true], _a.RestrictionCalls);
        _a.Window.Tick();                              // idempotent
        Assert.Equal(2, _a.RestrictionCalls.Count);
    }

    [Fact]
    public void Before_setup_the_window_may_open_because_nothing_is_protected_yet()
    {
        var r = _a.Call("maintenance.begin", args: new { password = "anything" });
        Assert.Equal("NotSet", r.Data!.Value.GetProperty("status").GetString());
        Assert.True(_a.Window.IsOpen);
    }
}
