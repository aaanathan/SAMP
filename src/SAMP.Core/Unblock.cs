namespace SAMP.Core;

public sealed class UnblockSession
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public DateTime UnblockedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    /// <summary>Watermark updated each watchdog tick; used to detect the clock being set backwards.</summary>
    public DateTime LastSeenUtc { get; set; }
    public DateTime? EndedAtUtc { get; set; }
    public string? EndReason { get; set; }
}

public sealed record UnblockStatus(bool IsBlocked, long? SessionId, DateTime? ExpiresAtUtc, TimeSpan? Remaining, long? UserId = null);

public interface IUnblockSessionStore
{
    long Add(UnblockSession s);
    UnblockSession? GetActive();
    void End(long id, DateTime atUtc, string reason);
    void Touch(long id, DateTime lastSeenUtc);
    void SetExpiry(long id, DateTime expiresAtUtc);
}

public interface IBlockRuleStore
{
    IReadOnlyList<BlockRule> List();
    long Add(BlockRule r);
    void Update(BlockRule r);
    void Delete(long id);
}

/// <summary>Applies the effective policy to the OS (registry/device-install restrictions).</summary>
public interface IUsbBlocker
{
    void Apply(bool globalBlocked, IReadOnlyList<BlockRule> rules);
    /// <summary>True when the OS currently carries the global mass-storage block.</summary>
    bool IsGloballyBlocked();
}

/// <summary>Enumerates and enables/disables already-attached devices.</summary>
public interface IDeviceController
{
    IReadOnlyList<DeviceInfo> Enumerate();
    void SetEnabled(string instanceId, bool enabled);
}
