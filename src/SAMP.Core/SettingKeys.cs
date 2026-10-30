namespace SAMP.Core;

public static class SettingKeys
{
    public const string UninstallPasswordHash = "uninstall.password_hash";
    public const string UninstallFailedAttempts = "uninstall.failed_attempts";
    public const string UninstallLockedUntilUtc = "uninstall.locked_until_utc";
    public const string RecoveryKeyHash = "recovery.key_hash";
    public const string RecoveryFailedAttempts = "recovery.failed_attempts";
    public const string RecoveryLockedUntilUtc = "recovery.locked_until_utc";
    public const string IntegrityAlert = "integrity.alert";
    public const string UnblockDurationMinutes = "usb.unblock_duration_minutes";
    public const string MaxUnblockMinutes = "usb.max_unblock_minutes";
    public const string ExternalLogPath = "log.external_path";
    public const string LogRetentionDays = "log.retention_days";
}
