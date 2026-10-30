using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SAMP.Client;
using SAMP.Core;

namespace SAMP.App.Core;

public sealed partial class DashboardViewModel : ViewModelBase
{
    public static readonly TimeSpan TenMinutes = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan OneMinute = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan RefreshEvery = TimeSpan.FromSeconds(15);

    private readonly ISampService _svc;
    private readonly IClock _clock;
    private DateTime? _expiresUtc;
    private DateTime _lastRefresh = DateTime.MinValue;
    private bool _warned10, _warned1;

    [ObservableProperty] private bool _isBlocked = true;
    [ObservableProperty] private string _statusText = "Loading…";
    [ObservableProperty] private string _countdownText = "";
    [ObservableProperty] private int _selectedMinutes = UnblockManagerDefaults.Minutes;
    [ObservableProperty] private int _maxSelectableMinutes = UnblockManagerDefaults.Minutes;
    [ObservableProperty] private string _reauthPassword = "";
    [ObservableProperty] private bool _integrityAlert;

    public UserInfo User { get; }
    public bool CanChangeState => User.CanUnblock;

    /// <summary>Raised once at 10 minutes and once at 1 minute remaining, for toast/tray notifications.</summary>
    public event Action<string>? Warning;

    public DashboardViewModel(ISampService svc, IClock clock, UserInfo user)
    {
        _svc = svc;
        _clock = clock;
        User = user;
    }

    public override async Task LoadAsync() => await RefreshAsync();

    public async Task RefreshAsync()
    {
        _lastRefresh = _clock.UtcNow;
        var r = await _svc.GetStatusAsync();
        if (!r.Ok) { ErrorMessage = r.Error; return; }
        var s = r.Value!;
        IsBlocked = s.IsBlocked;
        IntegrityAlert = s.IntegrityAlert;
        _expiresUtc = s.IsBlocked ? null : s.ExpiresAtUtc;
        MaxSelectableMinutes = User.IsAdmin ? s.MaxMinutes : s.DurationMinutes;
        if (IsBlocked)
        {
            _warned10 = _warned1 = false;
            if (SelectedMinutes <= 0 || SelectedMinutes > MaxSelectableMinutes) SelectedMinutes = Math.Min(s.DurationMinutes, MaxSelectableMinutes);
        }
        UpdateTexts();
    }

    /// <summary>Called every second by the UI timer; the countdown is derived locally, state is re-read every 15 s.</summary>
    public async Task TickAsync()
    {
        var now = _clock.UtcNow;
        if (_expiresUtc is { } exp)
        {
            var left = exp - now;
            if (left <= OneMinute && !_warned1) { _warned1 = true; _warned10 = true; Warning?.Invoke("USB storage will be blocked in less than 1 minute."); }
            else if (left <= TenMinutes && left > OneMinute && !_warned10) { _warned10 = true; Warning?.Invoke($"USB storage will be blocked in {Math.Ceiling(left.TotalMinutes):0} minutes."); }
            if (left <= TimeSpan.Zero) { await RefreshAsync(); return; }
        }
        if (now - _lastRefresh >= RefreshEvery) await RefreshAsync();
        UpdateTexts();
    }

    private void UpdateTexts()
    {
        if (IsBlocked)
        {
            StatusText = "USB storage is BLOCKED";
            CountdownText = "";
            return;
        }
        var left = (_expiresUtc ?? _clock.UtcNow) - _clock.UtcNow;
        if (left < TimeSpan.Zero) left = TimeSpan.Zero;
        StatusText = "USB storage is UNBLOCKED";
        CountdownText = $"Blocks automatically in {(int)left.TotalHours:00}:{left.Minutes:00}:{left.Seconds:00}";
    }

    [RelayCommand]
    private async Task UnblockAsync()
    {
        Clear();
        if (!CanChangeState) { ErrorMessage = "Your role cannot change USB access."; return; }
        if (string.IsNullOrEmpty(ReauthPassword)) { ErrorMessage = "Re-enter your password to unblock USB storage."; return; }
        if (SelectedMinutes < 5 || SelectedMinutes > MaxSelectableMinutes)
        {
            ErrorMessage = $"Choose between 5 and {MaxSelectableMinutes} minutes.";
            return;
        }

        var pw = ReauthPassword;
        ReauthPassword = "";
        bool? valid = null;
        if (!await RunAsync(() => _svc.VerifyPasswordAsync(pw), v => valid = v)) return;
        if (valid != true) { ErrorMessage = "Password is incorrect."; return; }

        if (await RunAsync(() => _svc.UnblockAsync(SelectedMinutes), _ => { }, "USB storage unblocked."))
            await RefreshAsync();
    }

    [RelayCommand]
    private async Task BlockNowAsync()
    {
        if (!CanChangeState) { ErrorMessage = "Your role cannot change USB access."; return; }
        if (await RunAsync(() => _svc.BlockAsync(), _ => { }, "USB storage blocked."))
            await RefreshAsync();
    }
}

internal static class UnblockManagerDefaults
{
    public const int Minutes = 120;
}
