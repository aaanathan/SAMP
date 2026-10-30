using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SAMP.Client;
using SAMP.Core;

namespace SAMP.App.Core;

public enum ShellState { Starting, ServiceUnavailable, Setup, Login, Recovery, ChangePassword, Main }

public sealed record NavItem(string Title, ViewModelBase Content);

/// <summary>
/// Owns the whole UI lifecycle. Nothing but Setup/Login is reachable without a session; logout, idle timeout,
/// Windows lock/logoff and a service-side session end all funnel into <see cref="SignOutAsync"/>.
/// </summary>
public sealed partial class ShellViewModel : ViewModelBase
{
    public static readonly TimeSpan DefaultIdleTimeout = TimeSpan.FromMinutes(15);

    private readonly ISampService _svc;
    private readonly IClock _clock;
    private readonly TimeSpan _idleTimeout;
    private DateTime _lastActivity;

    [ObservableProperty] private ShellState _state = ShellState.Starting;
    [ObservableProperty] private UserInfo? _currentUser;
    [ObservableProperty] private NavItem? _selectedNav;
    [ObservableProperty] private string? _notice;

    public ObservableCollection<NavItem> NavItems { get; } = new();
    public ServiceUnavailableViewModel Unavailable { get; }
    private DateTime _lastRetry;

    /// <summary>What the window shows. Main is the shell itself (navigation + current page).</summary>
    public object? Screen => State switch
    {
        ShellState.Setup => Setup,
        ShellState.Login => Login,
        ShellState.Recovery => Recovery,
        ShellState.ChangePassword => ForcedChange,
        ShellState.ServiceUnavailable => Unavailable,
        ShellState.Main => this,
        _ => "Starting…",
    };

    /// <summary>Toast/tray messages such as the 10-minute and 1-minute auto-block warnings.</summary>
    public event Action<string>? Notification;

    partial void OnStateChanged(ShellState value) => OnPropertyChanged(nameof(Screen));
    public SetupViewModel Setup { get; }
    public LoginViewModel Login { get; }
    public ChangePasswordViewModel ForcedChange { get; }
    public RecoveryViewModel Recovery { get; }
    public DashboardViewModel? Dashboard { get; private set; }
    public DeviceLogViewModel? DeviceLog { get; private set; }
    public RulesViewModel? Rules { get; private set; }

    /// <summary>The view sets this to marshal service callbacks onto the UI thread.</summary>
    public Action<Action> UiInvoke { get; set; } = a => a();

    public ShellViewModel(ISampService svc, IClock clock, TimeSpan? idleTimeout = null)
    {
        _svc = svc;
        _clock = clock;
        _idleTimeout = idleTimeout ?? DefaultIdleTimeout;
        _lastActivity = clock.UtcNow;
        Setup = new SetupViewModel(svc, this);
        Login = new LoginViewModel(svc, this);
        Recovery = new RecoveryViewModel(svc, this);
        ForcedChange = new ChangePasswordViewModel(svc, this, forced: true);
        Unavailable = new ServiceUnavailableViewModel(this);
        _svc.SessionExpired += () => UiInvoke(() => _ = HandleSessionEndedAsync());
    }

    partial void OnSelectedNavChanged(NavItem? value)
    {
        if (value != null) _ = value.Content.LoadAsync();
    }

    [RelayCommand]
    public async Task InitializeAsync()
    {
        State = ShellState.Starting;
        var r = await _svc.NeedsSetupAsync();
        if (!r.Ok) { Notice = r.Error; _lastRetry = _clock.UtcNow; State = ShellState.ServiceUnavailable; return; }
        Notice = null;
        State = r.Value ? ShellState.Setup : ShellState.Login;
        if (State == ShellState.Login) await Login.RefreshPublicStatusAsync();
    }

    internal void ShowRecovery()
    {
        Recovery.Reset();
        Notice = null;
        State = ShellState.Recovery;
    }

    internal async Task RecoveryFinishedAsync(string? notice = "Password reset. Sign in with your new password.")
    {
        Notice = notice;
        State = ShellState.Login;
        await Login.RefreshPublicStatusAsync();
    }

    internal async Task SetupCompletedAsync()
    {
        Notice = "Setup complete. Sign in with the administrator account.";
        State = ShellState.Login;
        await Login.RefreshPublicStatusAsync();
    }

    internal void OnLoggedIn(UserInfo user)
    {
        CurrentUser = user;
        _lastActivity = _clock.UtcNow;
        Notice = null;
        if (user.MustChangePassword)
        {
            ForcedChange.Reset();
            State = ShellState.ChangePassword;
            return;
        }
        BuildMain(user);
        State = ShellState.Main;
    }

    internal async Task PasswordChangedAsync()
    {
        // The service revokes every session of a user whose password changed, so sign in again.
        await _svc.LogoutAsync();
        TearDown();
        Notice = "Password changed. Sign in with your new password.";
        State = ShellState.Login;
        await Login.RefreshPublicStatusAsync();
    }

    private void BuildMain(UserInfo user)
    {
        TearDown();
        Dashboard = new DashboardViewModel(_svc, _clock, user);
        Dashboard.Warning += m => Notification?.Invoke(m);
        NavItems.Add(new NavItem("Dashboard", Dashboard));
        if (user.IsAdmin)
        {
            Rules = new RulesViewModel(_svc);
            DeviceLog = new DeviceLogViewModel(_svc);
            DeviceLog.RuleRequested += (vid, pid, serial) =>
            {
                Rules.PrefillFrom(vid, pid, serial);
                SelectedNav = NavItems.First(n => n.Content == Rules);
            };
            NavItems.Add(new NavItem("Users", new UsersViewModel(_svc)));
            NavItems.Add(new NavItem("Device Rules", Rules));
            NavItems.Add(new NavItem("Device Log", DeviceLog));
            NavItems.Add(new NavItem("Audit Log", new AuditViewModel(_svc)));
            NavItems.Add(new NavItem("Settings", new SettingsViewModel(_svc)));
        }
        NavItems.Add(new NavItem("My Account", new ChangePasswordViewModel(_svc, this, forced: false)));
        SelectedNav = NavItems[0];
    }

    private void TearDown()
    {
        NavItems.Clear();
        SelectedNav = null;
        Dashboard = null;
        Rules = null;
        DeviceLog = null;
        CurrentUser = null;
    }

    // ---- sign-out paths ----------------------------------------------------------------------------

    [RelayCommand]
    public Task LogoutAsync() => SignOutAsync("You have been signed out.");

    /// <summary>Windows session locked / user logged off / fast-user-switch.</summary>
    public Task OnSessionLockedAsync() => SignOutAsync("Signed out because the Windows session was locked.");

    public async Task SignOutAsync(string notice)
    {
        if (State is not (ShellState.Main or ShellState.ChangePassword)) return;
        await _svc.LogoutAsync();
        TearDown();
        Login.Reset();
        Notice = notice;
        State = ShellState.Login;
        await Login.RefreshPublicStatusAsync();
    }

    private Task HandleSessionEndedAsync()
    {
        if (State is not (ShellState.Main or ShellState.ChangePassword)) return Task.CompletedTask;
        TearDown();
        Login.Reset();
        Notice = "Your session has ended. Please sign in again.";
        State = ShellState.Login;
        return Login.RefreshPublicStatusAsync();
    }

    // ---- idle handling -----------------------------------------------------------------------------

    /// <summary>Call on any user input.</summary>
    public void NotifyActivity() => _lastActivity = _clock.UtcNow;

    /// <summary>Call about once a second from a UI timer.</summary>
    public async Task TickAsync()
    {
        if (State == ShellState.ServiceUnavailable && _clock.UtcNow - _lastRetry >= TimeSpan.FromSeconds(10))
        {
            _lastRetry = _clock.UtcNow;
            await InitializeAsync();
            return;
        }
        if (State != ShellState.Main) return;
        if (_clock.UtcNow - _lastActivity >= _idleTimeout)
        {
            await SignOutAsync("Signed out due to inactivity.");
            return;
        }
        if (Dashboard != null) await Dashboard.TickAsync();
    }
}
