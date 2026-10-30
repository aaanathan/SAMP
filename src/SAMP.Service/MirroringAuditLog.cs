using SAMP.Core;
using SAMP.Logging;

namespace SAMP.Service;

/// <summary>Writes every audit event to the encrypted audit table and mirrors it into the tamper-evident device log.</summary>
public sealed class MirroringAuditLog(IAuditLog inner, DeviceLog deviceLog) : IAuditLog
{
    public void Append(long? userId, string action, string? details = null)
    {
        inner.Append(userId, action, details);
        try { deviceLog.Append("audit", new { userId, action, details }); }
        catch (Exception) { /* the audit table already has it; the log gap will show in verification */ }
    }

    public IReadOnlyList<AuditEntry> Query(int limit) => inner.Query(limit);
    public AuditVerifyResult Verify() => inner.Verify();
}
