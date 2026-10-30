namespace SAMP.Client;

/// <summary>Everything the UI can ask of the service. The session token is held inside the implementation.</summary>
public interface ISampService
{
    bool HasSession { get; }
    /// <summary>Raised when the service rejects the session (idle timeout, revoked, account disabled).</summary>
    event Action? SessionExpired;

    Task<Result<bool>> NeedsSetupAsync();
    /// <summary>Returns the one-time recovery key.</summary>
    Task<Result<string>> SetupAsync(string username, string displayName, string password, string uninstallPassword);
    /// <summary>Resets an Admin password with the recovery key; returns the replacement recovery key.</summary>
    Task<Result<string>> RecoverAsync(string recoveryKey, string username, string newPassword);
    Task<Result<bool>> IsBlockedPublicAsync();

    Task<Result<LoginInfo>> LoginAsync(string username, string password);
    Task<Result<bool>> LogoutAsync();
    Task<Result<bool>> VerifyPasswordAsync(string password);
    Task<Result<bool>> ChangePasswordAsync(string current, string @new);

    Task<Result<StatusInfo>> GetStatusAsync();
    Task<Result<bool>> UnblockAsync(int? minutes);
    Task<Result<bool>> BlockAsync();

    Task<Result<List<UserInfo>>> ListUsersAsync();
    Task<Result<UserInfo>> CreateUserAsync(string username, string displayName, string password, string role, bool mustChangePassword);
    Task<Result<bool>> SetUserActiveAsync(long userId, bool active);
    Task<Result<bool>> SetUserRoleAsync(long userId, string role);
    Task<Result<bool>> ResetUserPasswordAsync(long userId, string password);

    Task<Result<List<RuleInfo>>> ListRulesAsync();
    Task<Result<bool>> SaveRuleAsync(RuleInfo rule);
    Task<Result<bool>> DeleteRuleAsync(long id);

    Task<Result<SettingsInfo>> GetSettingsAsync();
    Task<Result<bool>> SetDurationAsync(int minutes, bool applyToCurrent);
    Task<Result<bool>> SetMaxAsync(int minutes);
    Task<Result<bool>> SetExternalLogPathAsync(string path);
    Task<Result<bool>> ChangeUninstallPasswordAsync(string? current, string? adminPassword, string @new);

    Task<Result<IntegrityInfo>> GetIntegrityAsync();
    Task<Result<bool>> AcknowledgeIntegrityAsync();
    Task<Result<List<AuditRow>>> QueryAuditAsync(int limit);
    Task<Result<VerifyInfo>> VerifyAuditAsync();
    Task<Result<List<DeviceLogRow>>> QueryDeviceLogAsync(DateTime? fromUtc, DateTime? toUtc, int limit);
    Task<Result<VerifyInfo>> VerifyDeviceLogAsync();
}
