using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SAMP.Client;

namespace SAMP.App.Core;

public sealed partial class UsersViewModel(ISampService svc) : ViewModelBase
{
    public static IReadOnlyList<string> Roles { get; } = new[] { "Admin", "Operator", "Viewer" };

    [ObservableProperty] private UserInfo? _selectedUser;
    [ObservableProperty] private string _newUsername = "";
    [ObservableProperty] private string _newDisplayName = "";
    [ObservableProperty] private string _newPassword = "";
    [ObservableProperty] private string _newRole = "Operator";
    [ObservableProperty] private string _resetPassword = "";

    public ObservableCollection<UserInfo> Users { get; } = new();

    public override async Task LoadAsync()
    {
        await RunAsync(svc.ListUsersAsync, list =>
        {
            var selectedId = SelectedUser?.Id;
            Users.Clear();
            foreach (var u in list) Users.Add(u);
            SelectedUser = Users.FirstOrDefault(u => u.Id == selectedId);
        });
    }

    [RelayCommand]
    private async Task CreateAsync()
    {
        if (string.IsNullOrWhiteSpace(NewUsername) || string.IsNullOrEmpty(NewPassword)) { ErrorMessage = "Username and an initial password are required."; return; }
        var ok = await RunAsync(() => svc.CreateUserAsync(NewUsername.Trim(), NewDisplayName, NewPassword, NewRole, true), _ => { },
            "User created. They must change the password at first sign-in.");
        NewPassword = "";
        if (!ok) return;
        NewUsername = NewDisplayName = "";
        await ReloadAsync();
    }

    [RelayCommand]
    private async Task ToggleActiveAsync()
    {
        if (SelectedUser == null) return;
        if (await RunAsync(() => svc.SetUserActiveAsync(SelectedUser.Id, !SelectedUser.IsActive), _ => { })) await ReloadAsync();
    }

    [RelayCommand]
    private async Task SetRoleAsync(string role)
    {
        if (SelectedUser == null) return;
        if (await RunAsync(() => svc.SetUserRoleAsync(SelectedUser.Id, role), _ => { })) await ReloadAsync();
    }

    [RelayCommand]
    private async Task ResetPasswordAsync()
    {
        if (SelectedUser == null) { ErrorMessage = "Select a user first."; return; }
        if (string.IsNullOrEmpty(ResetPassword)) { ErrorMessage = "Enter a temporary password."; return; }
        await RunAsync(() => svc.ResetUserPasswordAsync(SelectedUser.Id, ResetPassword), _ => { },
            "Password reset. The user must change it at next sign-in.");
        ResetPassword = "";
    }
}

public sealed partial class RulesViewModel(ISampService svc) : ViewModelBase
{
    public static IReadOnlyList<string> Actions { get; } = new[] { "Block", "Allow" };
    public static IReadOnlyList<string> MatchTypes { get; } = new[] { "DeviceClass", "VendorId", "VendorProduct", "Serial" };
    public static IReadOnlyList<string> Scopes { get; } = new[] { "Always", "OnlyWhenLocked" };

    [ObservableProperty] private RuleInfo? _selectedRule;
    [ObservableProperty] private long _editId;
    [ObservableProperty] private string _name = "";
    [ObservableProperty] private bool _enabled = true;
    [ObservableProperty] private string _action = "Block";
    [ObservableProperty] private string _matchType = "VendorProduct";
    [ObservableProperty] private string _value = "";
    [ObservableProperty] private string _scope = "Always";
    [ObservableProperty] private string? _note;

    public ObservableCollection<RuleInfo> Rules { get; } = new();

    partial void OnSelectedRuleChanged(RuleInfo? value)
    {
        if (value == null) return;
        (EditId, Name, Enabled, Action, MatchType, Value, Scope, Note) = (value.Id, value.Name, value.Enabled, value.Action, value.MatchType, value.Value, value.Scope, value.Note);
    }

    public override async Task LoadAsync() =>
        await RunAsync(svc.ListRulesAsync, list =>
        {
            Rules.Clear();
            foreach (var r in list) Rules.Add(r);
        });

    /// <summary>Fills the form from a device seen in the device log (serial rule when a serial is known).</summary>
    public void PrefillFrom(string? vendorId, string? productId, string? serial)
    {
        NewRule();
        if (!string.IsNullOrWhiteSpace(serial)) { MatchType = "Serial"; Value = $"{vendorId}:{productId}:{serial}"; }
        else { MatchType = "VendorProduct"; Value = $"{vendorId}:{productId}"; }
        Name = $"Device {vendorId}:{productId}";
        InfoMessage = string.IsNullOrWhiteSpace(serial)
            ? "This device reports no serial number, so the rule matches every device with this vendor/product."
            : null;
    }

    [RelayCommand]
    private void NewRule()
    {
        SelectedRule = null;
        (EditId, Name, Enabled, Action, MatchType, Value, Scope, Note) = (0, "", true, "Block", "VendorProduct", "", "Always", null);
        Clear();
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        var rule = new RuleInfo(EditId, Name, Enabled, Action, MatchType, Value, Scope, Note);
        if (await RunAsync(() => svc.SaveRuleAsync(rule), _ => { }, "Rule saved and applied."))
        {
            await LoadAsync();
            NewRule();
            InfoMessage = "Rule saved and applied.";
        }
    }

    [RelayCommand]
    private async Task DeleteAsync()
    {
        if (SelectedRule == null) return;
        if (await RunAsync(() => svc.DeleteRuleAsync(SelectedRule.Id), _ => { }, "Rule deleted."))
        {
            await LoadAsync();
            NewRule();
            InfoMessage = "Rule deleted.";
        }
    }
}

public sealed partial class DeviceLogViewModel(ISampService svc) : ViewModelBase
{
    [ObservableProperty] private DateTime? _from = null;
    [ObservableProperty] private DateTime? _to = null;
    [ObservableProperty] private int _limit = 200;
    [ObservableProperty] private string _filter = "";
    [ObservableProperty] private DeviceLogRow? _selectedRow;
    [ObservableProperty] private string? _verifyText;

    public ObservableCollection<DeviceLogRow> Rows { get; } = new();
    private List<DeviceLogRow> _all = new();

    /// <summary>(vendorId, productId, serial) — the shell navigates to the rules page.</summary>
    public event Action<string?, string?, string?>? RuleRequested;

    partial void OnFilterChanged(string value) => ApplyFilter();

    public override async Task LoadAsync() =>
        await RunAsync(() => svc.QueryDeviceLogAsync(From?.ToUniversalTime(), To?.ToUniversalTime(), Limit), list =>
        {
            _all = list;
            ApplyFilter();
        });

    private void ApplyFilter()
    {
        Rows.Clear();
        foreach (var r in _all.Where(r => string.IsNullOrWhiteSpace(Filter) ||
                                         r.EventType.Contains(Filter, StringComparison.OrdinalIgnoreCase) ||
                                         r.Payload.Contains(Filter, StringComparison.OrdinalIgnoreCase)))
            Rows.Add(r);
    }

    [RelayCommand]
    private async Task VerifyAsync() =>
        await RunAsync(svc.VerifyDeviceLogAsync, v => VerifyText = VerifyFormatter.Format("Device log", v));

    [RelayCommand]
    private void CreateRuleFromSelected()
    {
        if (SelectedRow == null) { ErrorMessage = "Select a device event first."; return; }
        try
        {
            using var doc = JsonDocument.Parse(SelectedRow.Payload);
            string? Get(string n) => doc.RootElement.TryGetProperty(n, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString() : null;
            var vid = Get("vendorId"); var pid = Get("productId");
            if (vid == null || pid == null) { ErrorMessage = "This entry is not a device event."; return; }
            RuleRequested?.Invoke(vid, pid, Get("serial"));
        }
        catch (JsonException)
        {
            ErrorMessage = "This entry is not a device event.";
        }
    }
}

public sealed partial class AuditViewModel(ISampService svc) : ViewModelBase
{
    [ObservableProperty] private string? _integrityDetails;

    public bool HasIntegrityAlert => IntegrityDetails != null;
    partial void OnIntegrityDetailsChanged(string? value) => OnPropertyChanged(nameof(HasIntegrityAlert));

    [RelayCommand]
    private async Task AcknowledgeIntegrityAsync()
    {
        if (await RunAsync(() => svc.AcknowledgeIntegrityAsync(), _ => { }, "Integrity alert acknowledged."))
            await ReloadAsync();
    }

    [ObservableProperty] private int _limit = 200;
    [ObservableProperty] private string? _verifyText;
    public ObservableCollection<AuditRow> Rows { get; } = new();

    public override async Task LoadAsync()
    {
        await RunAsync(() => svc.QueryAuditAsync(Limit), list =>
        {
            Rows.Clear();
            foreach (var r in list) Rows.Add(r);
        });
        var i = await svc.GetIntegrityAsync();
        IntegrityDetails = i is { Ok: true, Value.Alerting: true } ? i.Value!.Details : null;
    }

    [RelayCommand]
    private async Task VerifyAsync() =>
        await RunAsync(svc.VerifyAuditAsync, v => VerifyText = VerifyFormatter.Format("Audit log", v));
}

public static class VerifyFormatter
{
    public static string Format(string what, VerifyInfo v)
    {
        if (!v.IsValid) return $"{what}: INTEGRITY FAILURE at record {v.BrokenAt}. {v.Reason}";
        var warn = v.Warnings is { Count: > 0 } w ? $" {w.Count} warning(s): {string.Join(" ", w.Take(3))}" : "";
        return $"{what}: integrity verified.{warn}";
    }
}

public sealed partial class SettingsViewModel(ISampService svc) : ViewModelBase
{
    [ObservableProperty] private int _durationMinutes = 120;
    [ObservableProperty] private int _maxMinutes = 1440;
    [ObservableProperty] private bool _applyToCurrent;
    [ObservableProperty] private string _externalLogPath = "";
    [ObservableProperty] private bool _uninstallPasswordSet;
    [ObservableProperty] private int _retentionDays;

    [ObservableProperty] private string _currentUninstallPassword = "";
    [ObservableProperty] private string _adminLoginPassword = "";
    [ObservableProperty] private string _newUninstallPassword = "";
    [ObservableProperty] private string _confirmUninstallPassword = "";

    public override async Task LoadAsync() =>
        await RunAsync(svc.GetSettingsAsync, s =>
        {
            DurationMinutes = s.DurationMinutes;
            MaxMinutes = s.MaxMinutes;
            ExternalLogPath = s.ExternalLogPath ?? "";
            UninstallPasswordSet = s.UninstallPasswordSet;
            RetentionDays = s.RetentionDays;
        });

    [RelayCommand]
    private async Task SaveDurationAsync()
    {
        if (await RunAsync(() => svc.SetDurationAsync(DurationMinutes, ApplyToCurrent), _ => { }, "Auto-block duration saved."))
            await ReloadAsync();
    }

    [RelayCommand]
    private async Task SaveMaxAsync()
    {
        if (await RunAsync(() => svc.SetMaxAsync(MaxMinutes), _ => { }, "Maximum duration saved."))
            await ReloadAsync();
    }

    [RelayCommand]
    private async Task SaveExternalPathAsync() =>
        await RunAsync(() => svc.SetExternalLogPathAsync(ExternalLogPath), _ => { },
            string.IsNullOrWhiteSpace(ExternalLogPath) ? "External log copy disabled." : "External log location saved.");

    [RelayCommand]
    private async Task ChangeUninstallPasswordAsync()
    {
        Clear();
        if (NewUninstallPassword != ConfirmUninstallPassword) { ErrorMessage = "The new uninstall passwords do not match."; return; }
        if (CurrentUninstallPassword.Length == 0 && AdminLoginPassword.Length == 0)
        {
            ErrorMessage = "Enter the current uninstall password, or your own login password if it was forgotten.";
            return;
        }
        var current = CurrentUninstallPassword.Length > 0 ? CurrentUninstallPassword : null;
        var admin = AdminLoginPassword.Length > 0 ? AdminLoginPassword : null;
        var ok = await RunAsync(() => svc.ChangeUninstallPasswordAsync(current, admin, NewUninstallPassword), _ => { }, "Uninstall password changed.");
        CurrentUninstallPassword = AdminLoginPassword = NewUninstallPassword = ConfirmUninstallPassword = "";
        if (ok) await ReloadAsync();
    }
}
