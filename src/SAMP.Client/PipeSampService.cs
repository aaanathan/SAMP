using System.Text.Json;
using SAMP.Ipc;

namespace SAMP.Client;

public sealed class PipeSampService(PipeClient pipe) : ISampService
{
    public const string DefaultPipeName = "samp-ui";
    private string? _token;

    public PipeSampService() : this(new PipeClient(DefaultPipeName)) { }

    public bool HasSession => _token != null;
    public event Action? SessionExpired;

    private async Task<Result<T>> CallAsync<T>(string command, object? args = null, Func<JsonElement?, T>? map = null)
    {
        IpcResponse r;
        try
        {
            r = await pipe.SendAsync(command, _token, args).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException)
        {
            return Result<T>.Fail("The SAMP service is not reachable.", "unreachable");
        }

        if (!r.Ok)
        {
            if (r.Code == "unauthorized" && _token != null && command is not ("logout" or "auth.verify"))
            {
                // "unauthorized" for a held token can also mean insufficient role; the status call below tells them apart.
                if (await StillLoggedInAsync().ConfigureAwait(false) == false)
                {
                    _token = null;
                    SessionExpired?.Invoke();
                }
            }
            return Result<T>.Fail(r.Error, r.Code);
        }

        try
        {
            return Result<T>.Success(map != null ? map(r.Data) : r.Data is { } d ? d.Deserialize<T>(IpcJson.Options)! : default!);
        }
        catch (JsonException)
        {
            return Result<T>.Fail("Unexpected response from service.", "bad_response");
        }
    }

    /// <summary>true = session alive, false = rejected, null = service unreachable.</summary>
    private async Task<bool?> StillLoggedInAsync()
    {
        try { return (await pipe.SendAsync("me", _token).ConfigureAwait(false)).Ok; }
        catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException) { return null; }
    }

    private static bool True(JsonElement? _) => true;

    public Task<Result<bool>> NeedsSetupAsync() =>
        CallAsync("setup.status", map: d => d!.Value.GetProperty("needsSetup").GetBoolean());

    public Task<Result<string>> SetupAsync(string username, string displayName, string password, string uninstallPassword) =>
        CallAsync("setup.complete", new { username, displayName, password, uninstallPassword },
            d => d!.Value.GetProperty("recoveryKey").GetString()!);

    public Task<Result<string>> RecoverAsync(string recoveryKey, string username, string newPassword) =>
        CallAsync("recovery.reset", new { recoveryKey, username, newPassword }, d => d!.Value.GetProperty("recoveryKey").GetString()!);

    public Task<Result<IntegrityInfo>> GetIntegrityAsync() => CallAsync<IntegrityInfo>("integrity.get");
    public Task<Result<bool>> AcknowledgeIntegrityAsync() => CallAsync("integrity.acknowledge", map: True);

    public Task<Result<bool>> IsBlockedPublicAsync() =>
        CallAsync("status.public", map: d => d!.Value.GetProperty("isBlocked").GetBoolean());

    public async Task<Result<LoginInfo>> LoginAsync(string username, string password)
    {
        _token = null;
        var r = await CallAsync<LoginInfo>("login", new { username, password }).ConfigureAwait(false);
        if (r.Ok) _token = r.Value!.Token;
        return r;
    }

    public async Task<Result<bool>> LogoutAsync()
    {
        var r = await CallAsync("logout", map: True).ConfigureAwait(false);
        _token = null; // always drop locally, even if the service was unreachable
        return r;
    }

    public Task<Result<bool>> VerifyPasswordAsync(string password) =>
        CallAsync("auth.verify", new { password }, d => d!.Value.GetProperty("ok").GetBoolean());

    public Task<Result<bool>> ChangePasswordAsync(string current, string @new) =>
        CallAsync("password.change", new { current, @new }, True);

    public Task<Result<StatusInfo>> GetStatusAsync() => CallAsync<StatusInfo>("status");
    public Task<Result<bool>> UnblockAsync(int? minutes) => CallAsync("unblock", new { minutes }, True);
    public Task<Result<bool>> BlockAsync() => CallAsync("block", map: True);

    public Task<Result<List<UserInfo>>> ListUsersAsync() => CallAsync<List<UserInfo>>("users.list");

    public Task<Result<UserInfo>> CreateUserAsync(string username, string displayName, string password, string role, bool mustChangePassword) =>
        CallAsync<UserInfo>("users.create", new { username, displayName, password, role, mustChangePassword });

    public Task<Result<bool>> SetUserActiveAsync(long userId, bool active) => CallAsync("users.setActive", new { userId, active }, True);
    public Task<Result<bool>> SetUserRoleAsync(long userId, string role) => CallAsync("users.setRole", new { userId, role }, True);
    public Task<Result<bool>> ResetUserPasswordAsync(long userId, string password) => CallAsync("users.resetPassword", new { userId, password }, True);

    public Task<Result<List<RuleInfo>>> ListRulesAsync() => CallAsync<List<RuleInfo>>("rules.list");

    public Task<Result<bool>> SaveRuleAsync(RuleInfo r)
    {
        var args = new { id = r.Id, name = r.Name, enabled = r.Enabled, action = r.Action, matchType = r.MatchType, value = r.Value, scope = r.Scope, note = r.Note };
        return CallAsync(r.Id == 0 ? "rules.add" : "rules.update", args, True);
    }

    public Task<Result<bool>> DeleteRuleAsync(long id) => CallAsync("rules.delete", new { id }, True);

    public Task<Result<SettingsInfo>> GetSettingsAsync() => CallAsync<SettingsInfo>("settings.get");
    public Task<Result<bool>> SetDurationAsync(int minutes, bool applyToCurrent) => CallAsync("settings.setDuration", new { minutes, applyToCurrent }, True);
    public Task<Result<bool>> SetMaxAsync(int minutes) => CallAsync("settings.setMax", new { minutes }, True);
    public Task<Result<bool>> SetExternalLogPathAsync(string path) => CallAsync("settings.setExternalLogPath", new { path }, True);

    public Task<Result<bool>> ChangeUninstallPasswordAsync(string? current, string? adminPassword, string @new) =>
        CallAsync("uninstall.change", new { current, adminPassword, @new }, True);

    public Task<Result<List<AuditRow>>> QueryAuditAsync(int limit) => CallAsync<List<AuditRow>>("audit.query", new { limit });
    public Task<Result<VerifyInfo>> VerifyAuditAsync() => CallAsync<VerifyInfo>("audit.verify");

    public Task<Result<List<DeviceLogRow>>> QueryDeviceLogAsync(DateTime? fromUtc, DateTime? toUtc, int limit) =>
        CallAsync<List<DeviceLogRow>>("devicelog.query", new { fromUtc = fromUtc?.ToString("o"), toUtc = toUtc?.ToString("o"), limit });

    public Task<Result<VerifyInfo>> VerifyDeviceLogAsync() => CallAsync<VerifyInfo>("devicelog.verify");
}
