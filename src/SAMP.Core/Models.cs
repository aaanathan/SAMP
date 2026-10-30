namespace SAMP.Core;

public enum Role
{
    Viewer = 0,
    Operator = 1,
    Admin = 2,
}

public sealed class User
{
    public long Id { get; set; }
    public string Username { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public Role Role { get; set; }
    public string PasswordHash { get; set; } = "";
    public bool IsActive { get; set; } = true;
    public bool MustChangePassword { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime? LockedUntilUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? LastLoginUtc { get; set; }
}

public sealed record AuditEntry(
    long Id,
    DateTime TimestampUtc,
    long? UserId,
    string Action,
    string? Details,
    string PrevHash,
    string Hash);

public sealed record AuditVerifyResult(bool IsValid, long? FirstBrokenId, string? Reason)
{
    public static AuditVerifyResult Ok { get; } = new(true, null, null);
}
