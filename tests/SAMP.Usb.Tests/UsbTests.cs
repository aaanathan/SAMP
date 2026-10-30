using SAMP.Core;
using SAMP.Usb;

namespace SAMP.Tests;

public class RuleEvaluatorTests
{
    private static DeviceInfo Stick(string vid = "0951", string pid = "1666", string? serial = "SER1") =>
        new(@"USB\VID_" + vid + "&PID_" + pid + "\\" + serial, vid, pid, serial, "08", null, "Stick", true);

    private static BlockRule R(BlockMatchType t, string v, RuleAction a, RuleScope s = RuleScope.Always, long id = 1) =>
        new() { Id = id, Name = "r" + id, MatchType = t, Value = v, Action = a, Scope = s };

    [Fact]
    public void Mass_storage_follows_global_state_without_rules()
    {
        Assert.Equal(DeviceDecision.Block, RuleEvaluator.Evaluate(Stick(), [], globalBlocked: true).Decision);
        Assert.Equal(DeviceDecision.Allow, RuleEvaluator.Evaluate(Stick(), [], globalBlocked: false).Decision);
    }

    [Fact]
    public void Non_mass_storage_is_untouched()
    {
        var kbd = new DeviceInfo(null, "046D", "C31C", null, "03", null, "Keyboard", false);
        Assert.Equal(DeviceDecision.Allow, RuleEvaluator.Evaluate(kbd, [], true).Decision);
    }

    [Fact]
    public void Serial_allow_beats_class_block_and_most_specific_wins()
    {
        var rules = new[]
        {
            R(BlockMatchType.DeviceClass, "08", RuleAction.Block, id: 1),
            R(BlockMatchType.VendorId, "0951", RuleAction.Block, id: 2),
            R(BlockMatchType.Serial, "0951:1666:ser1", RuleAction.Allow, id: 3),
        };
        var e = RuleEvaluator.Evaluate(Stick(), rules, true);
        Assert.Equal(DeviceDecision.Allow, e.Decision);
        Assert.Equal(3, e.RuleId);
        // another serial of the same model is still blocked
        Assert.Equal(DeviceDecision.Block, RuleEvaluator.Evaluate(Stick(serial: "OTHER"), rules, true).Decision);
    }

    [Fact]
    public void Block_beats_allow_at_equal_specificity()
    {
        var rules = new[]
        {
            R(BlockMatchType.VendorProduct, "0951:1666", RuleAction.Allow, id: 1),
            R(BlockMatchType.VendorProduct, "0951:1666", RuleAction.Block, id: 2),
        };
        Assert.Equal(DeviceDecision.Block, RuleEvaluator.Evaluate(Stick(), rules, false).Decision);
    }

    [Fact]
    public void Explicit_block_rule_stays_in_force_while_unblocked_unless_only_when_locked()
    {
        var always = new[] { R(BlockMatchType.VendorId, "0951", RuleAction.Block) };
        var locked = new[] { R(BlockMatchType.VendorId, "0951", RuleAction.Block, RuleScope.OnlyWhenLocked) };
        Assert.Equal(DeviceDecision.Block, RuleEvaluator.Evaluate(Stick(), always, globalBlocked: false).Decision);
        Assert.Equal(DeviceDecision.Allow, RuleEvaluator.Evaluate(Stick(), locked, globalBlocked: false).Decision);
    }

    [Fact]
    public void Disabled_rules_and_serial_rules_on_serialless_devices_do_not_match()
    {
        var disabled = R(BlockMatchType.VendorId, "0951", RuleAction.Block); disabled.Enabled = false;
        Assert.Equal(DeviceDecision.Allow, RuleEvaluator.Evaluate(Stick(), [disabled], false).Decision);
        var serialRule = R(BlockMatchType.Serial, "0951:1666:SER1", RuleAction.Block);
        Assert.False(RuleEvaluator.Matches(serialRule, Stick(serial: null)));
    }

    [Theory]
    [InlineData(BlockMatchType.VendorId, "0951", true)]
    [InlineData(BlockMatchType.VendorId, "951", true)]
    [InlineData(BlockMatchType.VendorId, "ZZZZ", false)]
    [InlineData(BlockMatchType.VendorProduct, "0951:1666", true)]
    [InlineData(BlockMatchType.VendorProduct, "0951", false)]
    [InlineData(BlockMatchType.Serial, "0951:1666", false)]
    [InlineData(BlockMatchType.Serial, "0951:1666:ABC", true)]
    [InlineData(BlockMatchType.DeviceClass, "08", true)]
    [InlineData(BlockMatchType.DeviceClass, "{4d36e967-e325-11ce-bfc1-08002be10318}", true)]
    [InlineData(BlockMatchType.DeviceClass, "xyz", false)]
    public void Validator(BlockMatchType t, string v, bool ok)
    {
        var err = RuleValidator.Validate(new BlockRule { Name = "n", MatchType = t, Value = v });
        Assert.Equal(ok, err == null);
    }
}

public class PolicyCompilerAndBlockerTests
{
    [Fact]
    public void Global_block_denies_mass_storage_and_sets_class_wide_switches()
    {
        var reg = new FakeRegistry();
        var b = new RegistryUsbBlocker(reg);
        b.Apply(true, []);
        Assert.True(b.IsGloballyBlocked());
        Assert.Equal(4, reg.GetDword(RegistryUsbBlocker.UsbStorKey, "Start"));
        Assert.Equal(1, reg.GetDword(RegistryUsbBlocker.RemovableStorageKey, "Deny_Read"));

        b.Apply(false, []);
        Assert.False(b.IsGloballyBlocked());
        Assert.Equal(3, reg.GetDword(RegistryUsbBlocker.UsbStorKey, "Start"));
        Assert.Null(reg.GetDword(RegistryUsbBlocker.RemovableStorageKey, "Deny_Read"));
    }

    [Fact]
    public void Allow_rules_use_layered_policy_and_avoid_class_wide_switches()
    {
        var reg = new FakeRegistry();
        var b = new RegistryUsbBlocker(reg);
        b.Apply(true, [new BlockRule { Name = "ok", MatchType = BlockMatchType.Serial, Value = "0951:1666:S1", Action = RuleAction.Allow }]);
        Assert.Equal(1, reg.GetDword(RegistryUsbBlocker.RestrictionsKey, "AllowDenyLayered"));
        Assert.Contains(@"USB\VID_0951&PID_1666\S1", reg.GetStringValues(RegistryUsbBlocker.RestrictionsKey + @"\AllowInstanceIDs"));
        Assert.Equal(3, reg.GetDword(RegistryUsbBlocker.UsbStorKey, "Start"));
        Assert.True(b.IsGloballyBlocked());
    }

    [Fact]
    public void Rules_compile_to_expected_lists_and_only_when_locked_rules_drop_out_when_unblocked()
    {
        var rules = new[]
        {
            new BlockRule { Name = "a", MatchType = BlockMatchType.VendorId, Value = "0951", Action = RuleAction.Block },
            new BlockRule { Name = "b", MatchType = BlockMatchType.VendorProduct, Value = "1234:abcd", Action = RuleAction.Block, Scope = RuleScope.OnlyWhenLocked },
            new BlockRule { Name = "c", MatchType = BlockMatchType.DeviceClass, Value = "{4d36e967-e325-11ce-bfc1-08002be10318}", Action = RuleAction.Block },
        };
        var locked = DeviceInstallPolicy.Compile(rules, true);
        Assert.Contains(@"USB\VID_0951", locked.DenyDeviceIds);
        Assert.Contains(@"USB\VID_1234&PID_ABCD", locked.DenyDeviceIds);
        Assert.Contains("{4D36E967-E325-11CE-BFC1-08002BE10318}", locked.DenyClasses);
        Assert.Contains(DeviceInstallPolicy.MassStorageCompatibleId, locked.DenyDeviceIds);

        var open = DeviceInstallPolicy.Compile(rules, false);
        Assert.DoesNotContain(DeviceInstallPolicy.MassStorageCompatibleId, open.DenyDeviceIds);
        Assert.DoesNotContain(@"USB\VID_1234&PID_ABCD", open.DenyDeviceIds);
        Assert.Contains(@"USB\VID_0951", open.DenyDeviceIds);
    }

    [Fact]
    public void Apply_is_idempotent_and_removes_stale_entries()
    {
        var reg = new FakeRegistry();
        var b = new RegistryUsbBlocker(reg);
        var rule = new BlockRule { Name = "a", MatchType = BlockMatchType.VendorId, Value = "0951", Action = RuleAction.Block };
        b.Apply(true, [rule]); b.Apply(true, [rule]);
        Assert.Equal(2, reg.GetStringValues(RegistryUsbBlocker.RestrictionsKey + @"\DenyDeviceIDs").Count);
        b.Apply(true, []);
        Assert.Single(reg.GetStringValues(RegistryUsbBlocker.RestrictionsKey + @"\DenyDeviceIDs"));
    }
}

public class UnblockManagerTests : IDisposable
{
    private readonly TestEnv _e = new();
    private readonly FakeBlocker _blocker = new();
    private readonly FakeDevices _devices = new();
    private readonly UnblockManager _m;
    private readonly User _admin;

    public UnblockManagerTests()
    {
        _m = Create();
        _admin = _e.Admin();
    }

    private UnblockManager Create() => new(_e.Sessions, _e.Rules, _blocker, _devices, _e.Settings, _e.Audit, _e.Clock);
    public void Dispose() => _e.Dispose();

    [Fact]
    public void Default_window_is_two_hours_and_auto_blocks_exactly_at_expiry()
    {
        var s = _m.Unblock(_admin.Id, Role.Admin);
        Assert.False(_blocker.Blocked);
        Assert.Equal(TimeSpan.FromHours(2), s.ExpiresAtUtc - s.UnblockedAtUtc);

        _e.Clock.Advance(TimeSpan.FromMinutes(119) + TimeSpan.FromSeconds(30));
        _m.Tick();
        Assert.False(_blocker.Blocked);
        Assert.False(_m.GetStatus().IsBlocked);

        _e.Clock.Advance(TimeSpan.FromSeconds(30)); // 120:00
        _m.Tick();
        Assert.True(_blocker.Blocked);
        Assert.True(_m.GetStatus().IsBlocked);
        Assert.Contains(_e.Audit.Query(20), a => a.Action == "usb.autoblock");
    }

    [Fact]
    public void Closing_the_ui_or_logging_out_does_not_matter_only_the_manager_state()
    {
        // The manager has no dependency on sessions/login; a restart of the host re-derives state from the DB.
        _m.Unblock(_admin.Id, Role.Admin);
        _e.Clock.Advance(TimeSpan.FromMinutes(60));
        var restarted = Create();
        restarted.Reconcile();
        Assert.False(_blocker.Blocked);
        Assert.Equal(TimeSpan.FromMinutes(60), restarted.GetStatus().Remaining);
        _e.Clock.Advance(TimeSpan.FromMinutes(61));
        restarted.Tick();
        Assert.True(_blocker.Blocked);
    }

    [Fact]
    public void Reconcile_after_downtime_past_expiry_blocks_immediately()
    {
        _m.Unblock(_admin.Id, Role.Admin);
        _e.Clock.Advance(TimeSpan.FromHours(5)); // machine was off / asleep
        Create().Reconcile();
        Assert.True(_blocker.Blocked);
        Assert.Null(_e.Sessions.GetActive());
    }

    [Fact]
    public void Reconcile_without_session_asserts_blocked()
    {
        _blocker.Blocked = false;
        Create().Reconcile();
        Assert.True(_blocker.Blocked);
    }

    [Fact]
    public void Clock_rollback_during_session_blocks_and_audits()
    {
        _m.Unblock(_admin.Id, Role.Admin);
        _e.Clock.Advance(TimeSpan.FromMinutes(30));
        _m.Tick();
        _e.Clock.Advance(TimeSpan.FromHours(-1)); // user sets clock back to extend the window
        _m.Tick();
        Assert.True(_blocker.Blocked);
        Assert.Contains(_e.Audit.Query(20), a => a.Action == "tamper.clock_rollback");
    }

    [Fact]
    public void Clock_rollback_across_restart_is_detected_via_watermark()
    {
        _m.Unblock(_admin.Id, Role.Admin);
        _e.Clock.Advance(TimeSpan.FromMinutes(30));
        _m.Tick();
        _e.Clock.Advance(TimeSpan.FromHours(-1));
        Create().Reconcile();
        Assert.True(_blocker.Blocked);
    }

    [Fact]
    public void Drift_without_session_is_reblocked()
    {
        _m.Reconcile();
        _blocker.Blocked = false; // someone flipped the registry by hand
        _m.Tick();
        Assert.True(_blocker.Blocked);
        Assert.Contains(_e.Audit.Query(20), a => a.Action == "tamper.drift");
    }

    [Fact]
    public void Cannot_start_second_window_while_active_and_manual_block_ends_it()
    {
        _m.Unblock(_admin.Id, Role.Admin);
        Assert.Throws<InvalidOperationException>(() => _m.Unblock(_admin.Id, Role.Admin));
        _m.BlockNow(_admin.Id);
        Assert.True(_blocker.Blocked);
        _m.Unblock(_admin.Id, Role.Admin); // allowed again
    }

    [Fact]
    public void Duration_is_admin_configurable_with_bounds_and_applies_to_new_sessions_only()
    {
        var op = _e.UserService.CreateUser(_admin.Id, "oper", "Op", TestEnv.StrongPassword, Role.Operator);
        Assert.Throws<UnauthorizedAccessException>(() => _m.SetDuration(op.Id, Role.Operator, 30));
        Assert.Throws<ArgumentOutOfRangeException>(() => _m.SetDuration(_admin.Id, Role.Admin, 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => _m.SetDuration(_admin.Id, Role.Admin, 1441));

        var first = _m.Unblock(_admin.Id, Role.Admin);
        _m.SetDuration(_admin.Id, Role.Admin, 30);
        Assert.Equal(first.ExpiresAtUtc, _e.Sessions.GetActive()!.ExpiresAtUtc); // running window untouched

        _m.BlockNow(_admin.Id);
        var next = _m.Unblock(_admin.Id, Role.Admin);
        Assert.Equal(TimeSpan.FromMinutes(30), next.ExpiresAtUtc - next.UnblockedAtUtc);
    }

    [Fact]
    public void Apply_to_current_only_shortens_never_extends()
    {
        var s = _m.Unblock(_admin.Id, Role.Admin);
        _m.SetDuration(_admin.Id, Role.Admin, 600, applyToCurrentSession: true);
        Assert.Equal(s.ExpiresAtUtc, _e.Sessions.GetActive()!.ExpiresAtUtc);
        _m.SetDuration(_admin.Id, Role.Admin, 10, applyToCurrentSession: true);
        Assert.Equal(s.UnblockedAtUtc.AddMinutes(10), _e.Sessions.GetActive()!.ExpiresAtUtc);
    }

    [Fact]
    public void Operator_cannot_exceed_configured_duration_but_may_choose_shorter()
    {
        var op = _e.UserService.CreateUser(_admin.Id, "oper", "Op", TestEnv.StrongPassword, Role.Operator);
        Assert.Throws<ArgumentOutOfRangeException>(() => _m.Unblock(op.Id, Role.Operator, 121));
        var s = _m.Unblock(op.Id, Role.Operator, 15);
        Assert.Equal(TimeSpan.FromMinutes(15), s.ExpiresAtUtc - s.UnblockedAtUtc);
        Assert.Throws<UnauthorizedAccessException>(() => _m.Unblock(op.Id, Role.Viewer));
    }

    [Fact]
    public void Max_duration_caps_the_configured_value()
    {
        _m.SetMaxMinutes(_admin.Id, Role.Admin, 60);
        Assert.Equal(60, _m.GetDurationMinutes());
        Assert.Throws<ArgumentOutOfRangeException>(() => _m.SetDuration(_admin.Id, Role.Admin, 90));
    }

    [Fact]
    public void Failed_apply_rolls_back_the_session_and_stays_blocked()
    {
        _blocker.FailNext = true;
        Assert.Throws<InvalidOperationException>(() => _m.Unblock(_admin.Id, Role.Admin));
        Assert.Null(_e.Sessions.GetActive());
        Assert.True(_blocker.Blocked);
    }

    [Fact]
    public void Attached_devices_are_enabled_or_disabled_according_to_rules()
    {
        var stick = new DeviceInfo("USB\\A", "0951", "1666", "S1", "08", null, "Stick", true);
        var banned = new DeviceInfo("USB\\B", "dead", "beef", "S2", "08", null, "Banned", true);
        _devices.Devices.AddRange([stick, banned]);
        _e.Rules.Add(new BlockRule { Name = "ban", MatchType = BlockMatchType.VendorId, Value = "DEAD", Action = RuleAction.Block, CreatedAtUtc = _e.Clock.UtcNow });

        _m.Reconcile(); // blocked: both disabled
        Assert.All(_devices.Devices, d => Assert.False(d.Enabled));

        _m.Unblock(_admin.Id, Role.Admin); // stick enabled, banned stays disabled
        Assert.True(_devices.Devices.Single(d => d.InstanceId == "USB\\A").Enabled);
        Assert.False(_devices.Devices.Single(d => d.InstanceId == "USB\\B").Enabled);

        _e.Clock.Advance(TimeSpan.FromHours(2));
        _m.Tick(); // auto-block disables the stick again
        Assert.False(_devices.Devices.Single(d => d.InstanceId == "USB\\A").Enabled);
    }

    [Fact]
    public void Hotplug_evaluation_uses_current_state()
    {
        var stick = new DeviceInfo("USB\\A", "0951", "1666", "S1", "08", null, "Stick", true);
        _m.Reconcile();
        Assert.Equal(DeviceDecision.Block, _m.EvaluateDevice(stick).Decision);
        _m.Unblock(_admin.Id, Role.Admin);
        Assert.Equal(DeviceDecision.Allow, _m.EvaluateDevice(stick).Decision);
    }
}

public class BlockRuleServiceTests : IDisposable
{
    private readonly TestEnv _e = new();
    private readonly FakeBlocker _blocker = new();
    private readonly BlockRuleService _svc;
    private readonly User _admin;

    public BlockRuleServiceTests()
    {
        var m = new UnblockManager(_e.Sessions, _e.Rules, _blocker, new FakeDevices(), _e.Settings, _e.Audit, _e.Clock);
        _svc = new BlockRuleService(_e.Rules, m, _e.Audit, _e.Clock);
        _admin = _e.Admin();
    }
    public void Dispose() => _e.Dispose();

    private static BlockRule Rule() => new() { Name = "n", MatchType = BlockMatchType.VendorId, Value = "0951", Action = RuleAction.Block };

    [Fact]
    public void Only_admin_can_manage_rules()
    {
        Assert.Throws<UnauthorizedAccessException>(() => _svc.Add(2, Role.Operator, Rule()));
        Assert.Throws<UnauthorizedAccessException>(() => _svc.List(Role.Operator));
    }

    [Fact]
    public void Add_validates_rejects_duplicates_audits_and_reapplies()
    {
        Assert.Throws<ArgumentException>(() => _svc.Add(_admin.Id, Role.Admin, new BlockRule { Name = "x", MatchType = BlockMatchType.VendorId, Value = "nope" }));
        var before = _blocker.ApplyCount;
        _svc.Add(_admin.Id, Role.Admin, Rule());
        Assert.True(_blocker.ApplyCount > before);
        Assert.Throws<InvalidOperationException>(() => _svc.Add(_admin.Id, Role.Admin, Rule()));
        Assert.Contains(_e.Audit.Query(10), a => a.Action == "rule.add");
        Assert.Single(_svc.List(Role.Admin));
    }
}

public class FaultInjectionTests : IDisposable
{
    private readonly TestEnv _e = new();
    private readonly FakeBlocker _blocker = new();
    private readonly FakeDevices _devices = new();
    private readonly UnblockManager _m;
    private readonly User _admin;

    public FaultInjectionTests()
    {
        _m = new UnblockManager(_e.Sessions, _e.Rules, _blocker, _devices, _e.Settings, _e.Audit, _e.Clock);
        _admin = _e.Admin();
    }
    public void Dispose() => _e.Dispose();

    [Fact]
    public void Registry_failure_at_expiry_is_retried_on_the_next_tick_and_ends_blocked()
    {
        _m.Unblock(_admin.Id, Role.Admin, 10);
        _e.Clock.Advance(TimeSpan.FromMinutes(10));
        _blocker.FailAlways = true;
        Assert.Throws<InvalidOperationException>(() => _m.Tick()); // OS policy could not be written

        Assert.Null(_e.Sessions.GetActive());   // the window is over regardless
        Assert.True(_m.GetStatus().IsBlocked);  // and the service reports it as blocked

        _blocker.Blocked = false;               // OS still carries the unblocked state
        _blocker.FailAlways = false;
        _m.Tick();                              // drift path re-applies the block
        Assert.True(_blocker.Blocked);
    }

    [Fact]
    public void Unreadable_policy_state_is_treated_as_not_blocked_and_reapplied()
    {
        _m.Reconcile();
        _blocker.Blocked = false;
        _blocker.FailRead = true;
        var before = _blocker.ApplyCount;
        _m.Tick();
        Assert.True(_blocker.ApplyCount > before);
        Assert.True(_blocker.Blocked);
    }

    [Fact]
    public void Reconcile_failure_leaves_no_active_session_after_expiry()
    {
        _m.Unblock(_admin.Id, Role.Admin, 5);
        _e.Clock.Advance(TimeSpan.FromHours(1));
        _blocker.FailAlways = true;
        var restarted = new UnblockManager(_e.Sessions, _e.Rules, _blocker, _devices, _e.Settings, _e.Audit, _e.Clock);
        Assert.Throws<InvalidOperationException>(() => restarted.Reconcile());
        Assert.Null(_e.Sessions.GetActive());
    }

    [Fact]
    public void Device_controller_failure_during_apply_does_not_leave_a_dangling_session()
    {
        _devices.Devices.Add(new DeviceInfo("USB\\X", "0951", "1666", "S", "08", null, "Stick", true, Enabled: false));
        var m = new UnblockManager(_e.Sessions, _e.Rules, new FakeBlocker { Blocked = true }, new ThrowingDevices(), _e.Settings, _e.Audit, _e.Clock);
        Assert.ThrowsAny<Exception>(() => m.Unblock(_admin.Id, Role.Admin));
        Assert.Null(_e.Sessions.GetActive());
    }

    private sealed class ThrowingDevices : IDeviceController
    {
        public IReadOnlyList<DeviceInfo> Enumerate() => new[] { new DeviceInfo("USB\\X", "0951", "1666", "S", "08", null, "Stick", true, Enabled: false) };
        public void SetEnabled(string instanceId, bool enabled) => throw new InvalidOperationException("pnputil failed");
    }
}
