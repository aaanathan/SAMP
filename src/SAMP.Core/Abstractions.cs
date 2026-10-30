namespace SAMP.Core;

public interface IClock
{
    DateTime UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTime UtcNow => DateTime.UtcNow;
}

public interface IUserStore
{
    User? GetById(long id);
    User? GetByUsername(string username);
    IReadOnlyList<User> List();
    long Add(User user);
    void Update(User user);
    int CountActiveAdmins();
    IReadOnlyList<string> GetRecentPasswordHashes(long userId, int count);
    void AddPasswordHistory(long userId, string hash, DateTime changedAtUtc);
}

public interface ISettingsStore
{
    string? Get(string key);
    void Set(string key, string value);
}

public interface IAuditLog
{
    void Append(long? userId, string action, string? details = null);
    IReadOnlyList<AuditEntry> Query(int limit);
    AuditVerifyResult Verify();
}
