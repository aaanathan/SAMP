using SAMP.Core;
using SAMP.Security;

namespace SAMP.Tests;

public class PasswordHasherTests
{
    private readonly PasswordHasher _h = new(new Argon2Options(1024, 1, 1));

    [Fact]
    public void Hash_then_verify_roundtrips_and_uses_unique_salts()
    {
        var a = _h.Hash("Secret-Pass-123!");
        var b = _h.Hash("Secret-Pass-123!");
        Assert.NotEqual(a, b);
        Assert.StartsWith("$argon2id$", a);
        Assert.True(_h.Verify("Secret-Pass-123!", a));
        Assert.False(_h.Verify("secret-pass-123!", a));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("$argon2id$v=19$m=x,t=1,p=1$AAAA$AAAA")]
    public void Verify_rejects_malformed_hashes(string encoded) => Assert.False(_h.Verify("x", encoded));
}

public class PasswordPolicyTests
{
    private readonly PasswordPolicy _p = new();

    [Fact] public void Accepts_strong_password() => Assert.Empty(_p.Validate("Correct-Horse-9!", "admin"));
    [Fact] public void Rejects_short() => Assert.NotEmpty(_p.Validate("Ab1!", "u"));
    [Fact] public void Rejects_single_class() => Assert.NotEmpty(_p.Validate("alllowercaseletters", "u"));
    [Fact] public void Rejects_username_inside_password() => Assert.NotEmpty(_p.Validate("Admin-Password-1!", "admin"));
}

public class SessionManagerTests
{
    private static User U(Role r = Role.Operator) => new() { Id = 7, Username = "bob", Role = r };

    [Fact]
    public void Idle_timeout_expires_and_activity_slides_window()
    {
        var clock = new FakeClock();
        var m = new SessionManager(clock, TimeSpan.FromMinutes(15));
        var s = m.Create(U());

        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.NotNull(m.Validate(s.Token));
        clock.Advance(TimeSpan.FromMinutes(10)); // 10 min since last activity: still valid
        Assert.NotNull(m.Validate(s.Token));
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Null(m.Validate(s.Token));
    }

    [Fact]
    public void Revoke_and_unknown_tokens_are_rejected()
    {
        var m = new SessionManager(new FakeClock());
        var s = m.Create(U());
        m.Revoke(s.Token);
        Assert.Null(m.Validate(s.Token));
        Assert.Null(m.Validate("nope"));
        Assert.Null(m.Validate(null));
    }

    [Fact]
    public void RequireRole_enforces_minimum_role()
    {
        var m = new SessionManager(new FakeClock());
        var op = m.Create(U(Role.Operator));
        Assert.Throws<UnauthorizedAccessException>(() => m.RequireRole(op.Token, Role.Admin));
        Assert.Equal(7, m.RequireRole(op.Token, Role.Operator).UserId);
        Assert.Throws<UnauthorizedAccessException>(() => m.RequireRole("bad", Role.Viewer));
    }

    [Fact]
    public void RevokeAllForUser_drops_every_session_of_that_user()
    {
        var m = new SessionManager(new FakeClock());
        var a = m.Create(U());
        var b = m.Create(U());
        m.RevokeAllForUser(7);
        Assert.Null(m.Validate(a.Token));
        Assert.Null(m.Validate(b.Token));
    }
}

public class UserServiceTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();

    [Fact]
    public void Initial_admin_can_be_created_only_once()
    {
        _e.Admin();
        Assert.Throws<InvalidOperationException>(() => _e.UserService.CreateInitialAdmin("other", "x", TestEnv.StrongPassword));
    }

    [Fact]
    public void Weak_password_is_rejected()
    {
        Assert.Throws<PasswordPolicyException>(() => _e.UserService.CreateInitialAdmin("admin", "A", "short"));
    }

    [Fact]
    public void Login_success_and_wrong_password()
    {
        _e.Admin();
        Assert.Equal(AuthStatus.Success, _e.UserService.Authenticate("ADMIN", TestEnv.StrongPassword).Status); // case-insensitive
        Assert.Equal(AuthStatus.InvalidCredentials, _e.UserService.Authenticate("admin", "wrong").Status);
        Assert.Equal(AuthStatus.InvalidCredentials, _e.UserService.Authenticate("ghost", "wrong").Status);
    }

    [Fact]
    public void Five_failures_lock_the_account_with_backoff_and_it_unlocks_later()
    {
        _e.Admin();
        for (var i = 0; i < 5; i++) _e.UserService.Authenticate("admin", "bad");

        var locked = _e.UserService.Authenticate("admin", TestEnv.StrongPassword);
        Assert.Equal(AuthStatus.Locked, locked.Status); // correct password is refused while locked

        // a failed attempt right after the first lock expires is the 6th failure: lock doubles to 2 minutes
        _e.Clock.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        Assert.Equal(AuthStatus.InvalidCredentials, _e.UserService.Authenticate("admin", "bad").Status);
        _e.Clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Equal(AuthStatus.Locked, _e.UserService.Authenticate("admin", TestEnv.StrongPassword).Status);
        _e.Clock.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(AuthStatus.Success, _e.UserService.Authenticate("admin", TestEnv.StrongPassword).Status);
    }

    [Fact]
    public void Disabled_user_cannot_log_in()
    {
        var admin = _e.Admin();
        var bob = _e.UserService.CreateUser(admin.Id, "bobby", "Bob", TestEnv.StrongPassword, Role.Operator);
        _e.UserService.SetActive(admin.Id, bob.Id, false);
        Assert.Equal(AuthStatus.Disabled, _e.UserService.Authenticate("bobby", TestEnv.StrongPassword).Status);
    }

    [Fact]
    public void Non_admin_cannot_manage_users()
    {
        var admin = _e.Admin();
        var bob = _e.UserService.CreateUser(admin.Id, "bobby", "Bob", TestEnv.StrongPassword, Role.Operator);
        Assert.Throws<UnauthorizedAccessException>(() =>
            _e.UserService.CreateUser(bob.Id, "eve1", "Eve", TestEnv.StrongPassword, Role.Admin));
        Assert.Throws<UnauthorizedAccessException>(() => _e.UserService.SetRole(bob.Id, bob.Id, Role.Admin));
    }

    [Fact]
    public void Last_active_admin_cannot_be_disabled_or_demoted()
    {
        var admin = _e.Admin();
        Assert.Throws<InvalidOperationException>(() => _e.UserService.SetActive(admin.Id, admin.Id, false));
        Assert.Throws<InvalidOperationException>(() => _e.UserService.SetRole(admin.Id, admin.Id, Role.Operator));

        var second = _e.UserService.CreateUser(admin.Id, "admin2", "Two", TestEnv.StrongPassword, Role.Admin);
        _e.UserService.SetRole(admin.Id, second.Id, Role.Operator); // fine: another admin remains
    }

    [Fact]
    public void Change_password_requires_current_and_blocks_reuse()
    {
        var admin = _e.Admin();
        Assert.Throws<UnauthorizedAccessException>(() => _e.UserService.ChangePassword(admin.Id, "wrong", "New-Password-77!"));
        _e.UserService.ChangePassword(admin.Id, TestEnv.StrongPassword, "New-Password-77!");
        Assert.Equal(AuthStatus.Success, _e.UserService.Authenticate("admin", "New-Password-77!").Status);
        Assert.Throws<PasswordPolicyException>(() => _e.UserService.ChangePassword(admin.Id, "New-Password-77!", TestEnv.StrongPassword));
    }

    [Fact]
    public void Reset_forces_change_and_raises_access_changed()
    {
        var admin = _e.Admin();
        var bob = _e.UserService.CreateUser(admin.Id, "bobby", "Bob", TestEnv.StrongPassword, Role.Operator);
        long? changed = null;
        _e.UserService.UserAccessChanged += id => changed = id;
        _e.UserService.ResetPassword(admin.Id, bob.Id, "Reset-Password-55!");
        Assert.Equal(bob.Id, changed);
        Assert.True(_e.Users.GetById(bob.Id)!.MustChangePassword);
    }
}

public class UninstallPasswordTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();
    private const string Pw = "Uninstall-Me-42!";

    private Session AdminSession(User u) => new SessionManager(_e.Clock).Create(u);

    [Fact]
    public void Verify_before_set_reports_not_set()
    {
        Assert.False(_e.Uninstall.IsSet);
        Assert.Equal(UninstallVerifyStatus.NotSet, _e.Uninstall.Verify("x").Status);
    }

    [Fact]
    public void Set_initial_once_then_verify()
    {
        var admin = _e.Admin();
        _e.Uninstall.SetInitial(admin.Id, Pw);
        Assert.Equal(UninstallVerifyStatus.Ok, _e.Uninstall.Verify(Pw).Status);
        Assert.Equal(UninstallVerifyStatus.Wrong, _e.Uninstall.Verify("nope").Status);
        Assert.Throws<InvalidOperationException>(() => _e.Uninstall.SetInitial(admin.Id, Pw));
    }

    [Fact]
    public void Three_failures_lock_for_15_minutes_even_for_correct_password()
    {
        var admin = _e.Admin();
        _e.Uninstall.SetInitial(admin.Id, Pw);
        _e.Uninstall.Verify("a"); _e.Uninstall.Verify("b");
        Assert.Equal(UninstallVerifyStatus.Locked, _e.Uninstall.Verify("c").Status);
        Assert.Equal(UninstallVerifyStatus.Locked, _e.Uninstall.Verify(Pw).Status);
        _e.Clock.Advance(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(1));
        Assert.Equal(UninstallVerifyStatus.Ok, _e.Uninstall.Verify(Pw).Status);
    }

    [Fact]
    public void Only_admin_can_change_and_needs_current_password()
    {
        var admin = _e.Admin();
        var op = _e.UserService.CreateUser(admin.Id, "bobby", "Bob", TestEnv.StrongPassword, Role.Operator);
        _e.Uninstall.SetInitial(admin.Id, Pw);

        Assert.Throws<UnauthorizedAccessException>(() => _e.Uninstall.Change(AdminSession(op), Pw, "Another-Pass-88!"));
        Assert.Throws<UnauthorizedAccessException>(() => _e.Uninstall.Change(AdminSession(admin), "wrong", "Another-Pass-88!"));

        _e.Uninstall.Change(AdminSession(admin), Pw, "Another-Pass-88!");
        Assert.Equal(UninstallVerifyStatus.Ok, _e.Uninstall.Verify("Another-Pass-88!").Status);
        Assert.Equal(UninstallVerifyStatus.Wrong, _e.Uninstall.Verify(Pw).Status);

        // admin re-authenticated path (e.g. forgotten uninstall password)
        _e.Uninstall.Change(AdminSession(admin), null, Pw, adminReauthenticated: true);
        Assert.Equal(UninstallVerifyStatus.Ok, _e.Uninstall.Verify(Pw).Status);
    }
}

public class RecoveryKeyTests : IDisposable
{
    private readonly TestEnv _e = new();
    private readonly RecoveryKeyService _r;
    public RecoveryKeyTests() => _r = new RecoveryKeyService(_e.Settings, _e.UserService, _e.Audit, _e.Hasher, _e.Clock);
    public void Dispose() => _e.Dispose();

    private const string NewPw = "Recovered-Pass-77!";

    [Fact]
    public void Generated_keys_have_160_bits_in_grouped_base32_and_are_unique()
    {
        var k = RecoveryKeyService.Generate();
        Assert.Matches("^([A-Z2-7]{4}-){7}[A-Z2-7]{4}$", k);
        Assert.NotEqual(k, RecoveryKeyService.Generate());
    }

    [Fact]
    public void Only_a_hash_is_stored_and_issue_works_once()
    {
        var admin = _e.Admin();
        var key = _r.IssueInitial(admin.Id);
        Assert.True(_r.IsConfigured);
        Assert.DoesNotContain(RecoveryKeyService.Normalize(key), _e.Settings.Get(SettingKeys.RecoveryKeyHash));
        Assert.Throws<InvalidOperationException>(() => _r.IssueInitial(admin.Id));
    }

    [Fact]
    public void Valid_key_resets_the_admin_password_unlocks_the_account_and_rotates_the_key()
    {
        var admin = _e.Admin();
        var key = _r.IssueInitial(admin.Id);
        for (var i = 0; i < 5; i++) _e.UserService.Authenticate("admin", "bad"); // account locked
        long? revoked = null;
        _e.UserService.UserAccessChanged += id => revoked = id;

        var res = _r.ResetAdminPassword(key.ToLowerInvariant().Replace("-", " "), "ADMIN", NewPw); // forgiving input
        Assert.Equal(RecoveryStatus.Ok, res.Status);
        Assert.NotEqual(key, res.NewRecoveryKey);
        Assert.Equal(admin.Id, revoked);
        Assert.Equal(AuthStatus.Success, _e.UserService.Authenticate("admin", NewPw).Status);
        Assert.Equal(AuthStatus.InvalidCredentials, _e.UserService.Authenticate("admin", TestEnv.StrongPassword).Status);

        // the used key is void, the new one works
        Assert.Equal(RecoveryStatus.InvalidKey, _r.ResetAdminPassword(key, "admin", "Another-Pass-88!").Status);
        Assert.Equal(RecoveryStatus.Ok, _r.ResetAdminPassword(res.NewRecoveryKey!, "admin", "Another-Pass-88!").Status);
    }

    [Fact]
    public void Wrong_keys_lock_recovery_after_five_attempts_even_for_the_right_key()
    {
        var admin = _e.Admin();
        var key = _r.IssueInitial(admin.Id);
        for (var i = 0; i < 4; i++) Assert.Equal(RecoveryStatus.InvalidKey, _r.ResetAdminPassword("AAAA-AAAA", "admin", NewPw).Status);
        Assert.Equal(RecoveryStatus.Locked, _r.ResetAdminPassword("AAAA-AAAA", "admin", NewPw).Status);
        Assert.Equal(RecoveryStatus.Locked, _r.ResetAdminPassword(key, "admin", NewPw).Status);
        _e.Clock.Advance(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(1));
        Assert.Equal(RecoveryStatus.Ok, _r.ResetAdminPassword(key, "admin", NewPw).Status);
    }

    [Fact]
    public void A_weak_new_password_does_not_consume_the_key()
    {
        var admin = _e.Admin();
        var key = _r.IssueInitial(admin.Id);
        Assert.Throws<PasswordPolicyException>(() => _r.ResetAdminPassword(key, "admin", "short"));
        Assert.Equal(RecoveryStatus.Ok, _r.ResetAdminPassword(key, "admin", NewPw).Status);
    }

    [Fact]
    public void Recovery_only_works_for_active_admins_and_when_configured()
    {
        Assert.Equal(RecoveryStatus.NotConfigured, _r.ResetAdminPassword("X", "admin", NewPw).Status);
        var admin = _e.Admin();
        var key = _r.IssueInitial(admin.Id);
        var op = _e.UserService.CreateUser(admin.Id, "oper", "Op", TestEnv.StrongPassword, Role.Operator);
        Assert.Throws<InvalidOperationException>(() => _r.ResetAdminPassword(key, "oper", NewPw));
        Assert.Throws<InvalidOperationException>(() => _r.ResetAdminPassword(key, "ghost", NewPw));
        _ = op;
    }
}
