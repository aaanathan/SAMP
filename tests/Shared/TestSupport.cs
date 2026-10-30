using SAMP.Core;
using SAMP.Data;
using SAMP.Security;

namespace SAMP.Tests;

public sealed class FakeClock : IClock
{
    public DateTime UtcNow { get; set; } = new(2026, 1, 1, 8, 0, 0, DateTimeKind.Utc);
    public void Advance(TimeSpan t) => UtcNow += t;
}

/// <summary>Identity protector so tests run on any OS (production uses DPAPI).</summary>
public sealed class PassthroughKeyProtector : IKeyProtector
{
    public byte[] Protect(byte[] plain) => plain.ToArray();
    public byte[] Unprotect(byte[] protectedData) => protectedData.ToArray();
}

public sealed class TestEnv : IDisposable
{
    public const string StrongPassword = "Correct-Horse-9!";
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "samp-tests-" + Guid.NewGuid().ToString("N"));
    public string DbPath => Path.Combine(Dir, "samp.db");
    public byte[] Key { get; }
    public FakeClock Clock { get; } = new();
    public SqlCipherDatabase Db { get; }
    public SqliteUserStore Users { get; }
    public SqliteSettingsStore Settings { get; }
    public SqliteAuditLog Audit { get; }
    public SqliteUnblockSessionStore Sessions { get; }
    public SqliteBlockRuleStore Rules { get; }
    public PasswordHasher Hasher { get; } = new(new Argon2Options(MemoryKb: 1024, Iterations: 1, Parallelism: 1));
    public PasswordPolicy Policy { get; } = new();
    public UserService UserService { get; }
    public UninstallPasswordService Uninstall { get; }

    public TestEnv()
    {
        Directory.CreateDirectory(Dir);
        Key = DatabaseKeyStore.LoadOrCreate(Path.Combine(Dir, "samp.key"), new PassthroughKeyProtector());
        Db = new SqlCipherDatabase(DbPath, Key);
        Users = new SqliteUserStore(Db);
        Settings = new SqliteSettingsStore(Db);
        Audit = new SqliteAuditLog(Db, Clock);
        Sessions = new SqliteUnblockSessionStore(Db);
        Rules = new SqliteBlockRuleStore(Db);
        UserService = new UserService(Users, Audit, Hasher, Policy, Clock);
        Uninstall = new UninstallPasswordService(Settings, Audit, Hasher, Policy, Clock);
    }

    public User Admin() => UserService.CreateInitialAdmin("admin", "Administrator", StrongPassword);

    public void Dispose()
    {
        Db.Dispose();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}
