using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SAMP.Client;

namespace SAMP.App.Core;

public sealed partial class SetupViewModel(ISampService svc, ShellViewModel shell) : ViewModelBase
{
    [ObservableProperty] private string _username = "admin";
    [ObservableProperty] private string _displayName = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private string _confirmPassword = "";
    [ObservableProperty] private string _uninstallPassword = "";
    [ObservableProperty] private string _confirmUninstallPassword = "";
    [ObservableProperty] private string? _recoveryKey;

    public bool ShowRecoveryKey => RecoveryKey != null;
    partial void OnRecoveryKeyChanged(string? value) => OnPropertyChanged(nameof(ShowRecoveryKey));

    [RelayCommand]
    private async Task AcknowledgeRecoveryAsync()
    {
        RecoveryKey = null; // not kept in memory once the admin confirms it was stored
        await shell.SetupCompletedAsync();
    }

    [RelayCommand]
    private async Task CompleteAsync()
    {
        Clear();
        if (string.IsNullOrWhiteSpace(Username)) { ErrorMessage = "Enter a username for the administrator."; return; }
        if (Password != ConfirmPassword) { ErrorMessage = "The administrator passwords do not match."; return; }
        if (UninstallPassword != ConfirmUninstallPassword) { ErrorMessage = "The uninstall passwords do not match."; return; }
        if (UninstallPassword == Password) { ErrorMessage = "The uninstall password must be different from the login password."; return; }

        string? key = null;
        var ok = await RunAsync(() => svc.SetupAsync(Username, DisplayName, Password, UninstallPassword), k => key = k);
        Password = ConfirmPassword = UninstallPassword = ConfirmUninstallPassword = "";
        // The account exists now; the key is shown exactly once and the admin must confirm having stored it.
        if (ok) RecoveryKey = key;
    }
}

public sealed partial class LoginViewModel(ISampService svc, ShellViewModel shell) : ViewModelBase
{
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private string _usbStateText = "";

    public void Reset()
    {
        Username = "";
        Password = "";
        Clear();
    }

    public async Task RefreshPublicStatusAsync()
    {
        var r = await svc.IsBlockedPublicAsync();
        UsbStateText = !r.Ok ? "" : r.Value ? "USB storage is blocked." : "USB storage is currently unblocked.";
    }

    [RelayCommand]
    private void ForgotPassword() => shell.ShowRecovery();

    [RelayCommand]
    private async Task SignInAsync()
    {
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrEmpty(Password))
        {
            ErrorMessage = "Enter your username and password.";
            return;
        }
        UserInfo? user = null;
        var ok = await RunAsync(() => svc.LoginAsync(Username.Trim(), Password), r => user = r.User);
        Password = ""; // never keep the password around, success or not
        if (ok && user != null) shell.OnLoggedIn(user);
    }
}

/// <summary>Used for the forced change after an Admin reset and for the voluntary "My Account" page.</summary>
public sealed partial class ChangePasswordViewModel(ISampService svc, ShellViewModel shell, bool forced) : ViewModelBase
{
    [ObservableProperty] private string _current = "";
    [ObservableProperty] private string _new = "";
    [ObservableProperty] private string _confirm = "";

    public bool IsForced { get; } = forced;

    public void Reset()
    {
        Current = New = Confirm = "";
        Clear();
    }

    [RelayCommand]
    private async Task ChangeAsync()
    {
        Clear();
        if (New != Confirm) { ErrorMessage = "The new passwords do not match."; return; }
        if (New == Current) { ErrorMessage = "Choose a password different from the current one."; return; }
        var ok = await RunAsync(() => svc.ChangePasswordAsync(Current, New));
        Current = New = Confirm = "";
        if (ok) await shell.PasswordChangedAsync();
    }
}

public sealed partial class RecoveryViewModel(ISampService svc, ShellViewModel shell) : ViewModelBase
{
    [ObservableProperty] private string _recoveryKey = "";
    [ObservableProperty] private string _username = "";
    [ObservableProperty] private string _newPassword = "";
    [ObservableProperty] private string _confirmPassword = "";
    [ObservableProperty] private string? _newRecoveryKey;

    public bool ShowNewKey => NewRecoveryKey != null;
    partial void OnNewRecoveryKeyChanged(string? value) => OnPropertyChanged(nameof(ShowNewKey));

    public void Reset()
    {
        RecoveryKey = Username = NewPassword = ConfirmPassword = "";
        NewRecoveryKey = null;
        Clear();
    }

    [RelayCommand]
    private async Task ResetAsync()
    {
        Clear();
        if (string.IsNullOrWhiteSpace(RecoveryKey) || string.IsNullOrWhiteSpace(Username)) { ErrorMessage = "Enter the administrator username and the recovery key."; return; }
        if (NewPassword != ConfirmPassword) { ErrorMessage = "The new passwords do not match."; return; }
        string? next = null;
        var ok = await RunAsync(() => svc.RecoverAsync(RecoveryKey, Username.Trim(), NewPassword), k => next = k);
        RecoveryKey = NewPassword = ConfirmPassword = "";
        if (ok) NewRecoveryKey = next; // the old key is now void; the admin must store this one
    }

    [RelayCommand]
    private async Task DoneAsync()
    {
        Reset();
        await shell.RecoveryFinishedAsync();
    }

    [RelayCommand]
    private async Task BackAsync()
    {
        Reset();
        await shell.RecoveryFinishedAsync(notice: null);
    }
}
