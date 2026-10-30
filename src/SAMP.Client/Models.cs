namespace SAMP.Client;

public sealed record Result<T>(bool Ok, T? Value, string? Error, string? Code)
{
    public static Result<T> Success(T value) => new(true, value, null, null);
    public static Result<T> Fail(string? error, string? code = null) => new(false, default, error ?? "Request failed.", code);
}

public sealed record UserInfo(long Id, string Username, string DisplayName, string Role, bool IsActive, bool MustChangePassword,
    DateTime? LockedUntilUtc, DateTime? LastLoginUtc)
{
    public bool IsAdmin => Role == "Admin";
    public bool CanUnblock => Role is "Admin" or "Operator";
}

public sealed record LoginInfo(string Token, UserInfo User);

public sealed record StatusInfo(bool IsBlocked, DateTime? ExpiresAtUtc, double? RemainingSeconds, int DurationMinutes, int MaxMinutes, bool IntegrityAlert = false);

public sealed record IntegrityInfo(bool Alerting, string? Details);

public sealed record SettingsInfo(int DurationMinutes, int MaxMinutes, string? ExternalLogPath, bool UninstallPasswordSet, int RetentionDays);

public sealed record RuleInfo(long Id, string Name, bool Enabled, string Action, string MatchType, string Value, string Scope, string? Note);

public sealed record AuditRow(long Id, DateTime TimestampUtc, long? UserId, string Action, string? Details);

public sealed record DeviceLogRow(long Seq, DateTime TimestampUtc, string EventType, string Payload);

public sealed record VerifyInfo(bool IsValid, long? FirstBrokenId, long? FirstBrokenSeq, string? Reason, List<string>? Warnings, long? RecordCount)
{
    public long? BrokenAt => FirstBrokenSeq ?? FirstBrokenId;
}
