using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SAMP.Core;

namespace SAMP.Data;

public sealed class SqliteUserStore(SqlCipherDatabase db) : IUserStore
{
    private const string Columns =
        "Id, Username, DisplayName, Role, PasswordHash, IsActive, MustChangePassword, FailedAttempts, LockedUntilUtc, CreatedAtUtc, LastLoginUtc";

    public User? GetById(long id) => db.With(c =>
    {
        using var cmd = c.Cmd($"SELECT {Columns} FROM Users WHERE Id = $id;", ("$id", id));
        using var r = cmd.ExecuteReader();
        return r.Read() ? Map(r) : null;
    });

    public User? GetByUsername(string username) => db.With(c =>
    {
        using var cmd = c.Cmd($"SELECT {Columns} FROM Users WHERE Username = $u;", ("$u", username));
        using var r = cmd.ExecuteReader();
        return r.Read() ? Map(r) : null;
    });

    public IReadOnlyList<User> List() => db.With(c =>
    {
        var list = new List<User>();
        using var cmd = c.Cmd($"SELECT {Columns} FROM Users ORDER BY Username;");
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Map(r));
        return (IReadOnlyList<User>)list;
    });

    public long Add(User u) => db.With(c =>
    {
        using var cmd = c.Cmd(
            """
            INSERT INTO Users (Username, DisplayName, Role, PasswordHash, IsActive, MustChangePassword, FailedAttempts, LockedUntilUtc, CreatedAtUtc, LastLoginUtc)
            VALUES ($u, $d, $r, $p, $a, $m, $f, $l, $c, $ll);
            SELECT last_insert_rowid();
            """,
            ("$u", u.Username), ("$d", u.DisplayName), ("$r", (int)u.Role), ("$p", u.PasswordHash),
            ("$a", u.IsActive ? 1 : 0), ("$m", u.MustChangePassword ? 1 : 0), ("$f", u.FailedAttempts),
            ("$l", u.LockedUntilUtc?.Iso()), ("$c", u.CreatedAtUtc.Iso()), ("$ll", u.LastLoginUtc?.Iso()));
        return Convert.ToInt64(cmd.ExecuteScalar());
    });

    public void Update(User u) => db.With(c =>
    {
        using var cmd = c.Cmd(
            """
            UPDATE Users SET DisplayName=$d, Role=$r, PasswordHash=$p, IsActive=$a, MustChangePassword=$m,
                FailedAttempts=$f, LockedUntilUtc=$l, LastLoginUtc=$ll WHERE Id=$id;
            """,
            ("$id", u.Id), ("$d", u.DisplayName), ("$r", (int)u.Role), ("$p", u.PasswordHash),
            ("$a", u.IsActive ? 1 : 0), ("$m", u.MustChangePassword ? 1 : 0), ("$f", u.FailedAttempts),
            ("$l", u.LockedUntilUtc?.Iso()), ("$ll", u.LastLoginUtc?.Iso()));
        cmd.ExecuteNonQuery();
    });

    public int CountActiveAdmins() => db.With(c =>
    {
        using var cmd = c.Cmd("SELECT COUNT(*) FROM Users WHERE Role = $r AND IsActive = 1;", ("$r", (int)Role.Admin));
        return Convert.ToInt32(cmd.ExecuteScalar());
    });

    public IReadOnlyList<string> GetRecentPasswordHashes(long userId, int count) => db.With(c =>
    {
        var list = new List<string>();
        using var cmd = c.Cmd("SELECT Hash FROM PasswordHistory WHERE UserId = $u ORDER BY Id DESC LIMIT $n;", ("$u", userId), ("$n", count));
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(r.GetString(0));
        return (IReadOnlyList<string>)list;
    });

    public void AddPasswordHistory(long userId, string hash, DateTime changedAtUtc) => db.With(c =>
    {
        using var cmd = c.Cmd("INSERT INTO PasswordHistory (UserId, Hash, ChangedAtUtc) VALUES ($u, $h, $t);",
            ("$u", userId), ("$h", hash), ("$t", changedAtUtc.Iso()));
        cmd.ExecuteNonQuery();
    });

    private static User Map(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0),
        Username = r.GetString(1),
        DisplayName = r.GetString(2),
        Role = (Role)r.GetInt32(3),
        PasswordHash = r.GetString(4),
        IsActive = r.GetInt32(5) == 1,
        MustChangePassword = r.GetInt32(6) == 1,
        FailedAttempts = r.GetInt32(7),
        LockedUntilUtc = r.IsDBNull(8) ? null : SqliteExtensions.ParseUtc(r.GetString(8)),
        CreatedAtUtc = SqliteExtensions.ParseUtc(r.GetString(9)),
        LastLoginUtc = r.IsDBNull(10) ? null : SqliteExtensions.ParseUtc(r.GetString(10)),
    };
}

public sealed class SqliteSettingsStore(SqlCipherDatabase db) : ISettingsStore
{
    public string? Get(string key) => db.With(c =>
    {
        using var cmd = c.Cmd("SELECT Value FROM Settings WHERE Key = $k;", ("$k", key));
        return cmd.ExecuteScalar() as string;
    });

    public void Set(string key, string value) => db.With(c =>
    {
        using var cmd = c.Cmd(
            "INSERT INTO Settings (Key, Value) VALUES ($k, $v) ON CONFLICT(Key) DO UPDATE SET Value = excluded.Value;",
            ("$k", key), ("$v", value));
        cmd.ExecuteNonQuery();
    });
}

/// <summary>Append-only, hash-chained audit log: each row's hash covers the previous row's hash.</summary>
public sealed class SqliteAuditLog(SqlCipherDatabase db, IClock clock) : IAuditLog
{
    private static readonly string Genesis = new('0', 64);

    public void Append(long? userId, string action, string? details = null) => db.With(c =>
    {
        using var tx = c.BeginTransaction();
        string prev;
        using (var q = c.Cmd("SELECT Hash FROM AuditLog ORDER BY Id DESC LIMIT 1;")) { q.Transaction = tx; prev = q.ExecuteScalar() as string ?? Genesis; }

        var ts = clock.UtcNow.Iso();
        var hash = ComputeHash(prev, ts, userId, action, details);
        using (var ins = c.Cmd(
            "INSERT INTO AuditLog (TimestampUtc, UserId, Action, Details, PrevHash, Hash) VALUES ($t, $u, $a, $d, $p, $h);",
            ("$t", ts), ("$u", userId), ("$a", action), ("$d", details), ("$p", prev), ("$h", hash)))
        {
            ins.Transaction = tx;
            ins.ExecuteNonQuery();
        }
        tx.Commit();
    });

    public IReadOnlyList<AuditEntry> Query(int limit) => db.With(c =>
    {
        var list = new List<AuditEntry>();
        using var cmd = c.Cmd("SELECT Id, TimestampUtc, UserId, Action, Details, PrevHash, Hash FROM AuditLog ORDER BY Id DESC LIMIT $n;", ("$n", limit));
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Map(r));
        return (IReadOnlyList<AuditEntry>)list;
    });

    public AuditVerifyResult Verify() => db.With(c =>
    {
        using var cmd = c.Cmd("SELECT Id, TimestampUtc, UserId, Action, Details, PrevHash, Hash FROM AuditLog ORDER BY Id ASC;");
        using var r = cmd.ExecuteReader();
        var prev = Genesis;
        long expectedId = 1;
        while (r.Read())
        {
            var e = Map(r);
            if (e.Id != expectedId) return new AuditVerifyResult(false, e.Id, "Missing record(s) before this entry.");
            if (e.PrevHash != prev) return new AuditVerifyResult(false, e.Id, "Chain link does not match previous record.");
            var recomputed = ComputeHash(e.PrevHash, e.TimestampUtc.Iso(), e.UserId, e.Action, e.Details);
            if (!string.Equals(recomputed, e.Hash, StringComparison.Ordinal))
                return new AuditVerifyResult(false, e.Id, "Record content does not match its hash.");
            prev = e.Hash;
            expectedId++;
        }
        return AuditVerifyResult.Ok;
    });

    private static AuditEntry Map(SqliteDataReader r) => new(
        r.GetInt64(0), SqliteExtensions.ParseUtc(r.GetString(1)),
        r.IsDBNull(2) ? null : r.GetInt64(2), r.GetString(3),
        r.IsDBNull(4) ? null : r.GetString(4), r.GetString(5), r.GetString(6));

    private static string ComputeHash(string prev, string ts, long? userId, string action, string? details)
    {
        // Length-prefixed fields so field boundaries can't be shifted.
        var sb = new StringBuilder();
        foreach (var f in new[] { prev, ts, userId?.ToString() ?? "", action, details ?? "" })
            sb.Append(f.Length).Append(':').Append(f).Append('|');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }
}
