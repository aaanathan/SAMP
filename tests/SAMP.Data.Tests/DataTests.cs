using Microsoft.Data.Sqlite;
using SAMP.Core;
using SAMP.Data;

namespace SAMP.Tests;

public class DatabaseTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();

    [Fact]
    public void Database_file_is_encrypted_and_not_plain_sqlite()
    {
        _e.Admin();
        _e.Db.Dispose();
        var bytes = File.ReadAllBytes(_e.DbPath);
        Assert.False(bytes.AsSpan(0, 15).SequenceEqual("SQLite format 3"u8));
        Assert.DoesNotContain("admin", System.Text.Encoding.Latin1.GetString(bytes));
    }

    [Fact]
    public void Wrong_key_cannot_open_database()
    {
        _e.Admin();
        _e.Db.Dispose();
        var wrong = new byte[32];
        Assert.Throws<InvalidOperationException>(() => new SqlCipherDatabase(_e.DbPath, wrong));
    }

    [Fact]
    public void Plain_sqlite_client_without_key_cannot_read_it()
    {
        _e.Admin();
        _e.Db.Dispose();
        SQLitePCL.Batteries_V2.Init();
        using var c = new SqliteConnection($"Data Source={_e.DbPath};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT count(*) FROM sqlite_master;";
        Assert.ThrowsAny<SqliteException>(() => cmd.ExecuteScalar());
    }

    [Fact]
    public void Reopening_with_same_key_keeps_data_and_migration_is_idempotent()
    {
        _e.Admin();
        _e.Db.Dispose();
        using var db2 = new SqlCipherDatabase(_e.DbPath, _e.Key);
        Assert.NotNull(new SqliteUserStore(db2).GetByUsername("admin"));
    }

    [Fact]
    public void Key_store_persists_the_same_key_across_loads()
    {
        var path = Path.Combine(_e.Dir, "k2.bin");
        var a = DatabaseKeyStore.LoadOrCreate(path, new PassthroughKeyProtector());
        var b = DatabaseKeyStore.LoadOrCreate(path, new PassthroughKeyProtector());
        Assert.Equal(32, a.Length);
        Assert.Equal(a, b);
    }

    [Fact]
    public void Duplicate_usernames_are_rejected_case_insensitively()
    {
        _e.Admin();
        Assert.Throws<InvalidOperationException>(() =>
            _e.UserService.CreateUser(1, "ADMIN", "dup", TestEnv.StrongPassword, Role.Operator));
    }
}

public class AuditLogTests : IDisposable
{
    private readonly TestEnv _e = new();
    public void Dispose() => _e.Dispose();

    [Fact]
    public void Chain_is_valid_after_normal_use()
    {
        _e.Admin();
        _e.UserService.Authenticate("admin", "bad");
        _e.UserService.Authenticate("admin", TestEnv.StrongPassword);
        Assert.True(_e.Audit.Verify().IsValid);
        Assert.True(_e.Audit.Query(100).Count >= 3);
    }

    [Fact]
    public void Update_and_delete_are_blocked_by_triggers()
    {
        _e.Admin();
        Assert.Throws<SqliteException>(() => _e.Db.With(c =>
        {
            using var cmd = c.CreateCommand(); cmd.CommandText = "UPDATE AuditLog SET Action='x' WHERE Id=1;"; cmd.ExecuteNonQuery();
        }));
        Assert.Throws<SqliteException>(() => _e.Db.With(c =>
        {
            using var cmd = c.CreateCommand(); cmd.CommandText = "DELETE FROM AuditLog WHERE Id=1;"; cmd.ExecuteNonQuery();
        }));
    }

    private void Raw(string sql) => _e.Db.With(c =>
    {
        using var cmd = c.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery();
    });

    [Fact]
    public void Editing_a_row_after_dropping_triggers_is_detected()
    {
        _e.Admin(); _e.UserService.Authenticate("admin", "bad");
        Raw("DROP TRIGGER AuditLog_no_update;");
        Raw("UPDATE AuditLog SET Details='forged' WHERE Id=2;");
        var r = _e.Audit.Verify();
        Assert.False(r.IsValid);
        Assert.Equal(2, r.FirstBrokenId);
    }

    [Fact]
    public void Deleting_a_row_is_detected()
    {
        _e.Admin(); _e.UserService.Authenticate("admin", "bad"); _e.UserService.Authenticate("admin", "bad");
        Raw("DROP TRIGGER AuditLog_no_delete;");
        Raw("DELETE FROM AuditLog WHERE Id=2;");
        var r = _e.Audit.Verify();
        Assert.False(r.IsValid);
        Assert.Equal(3, r.FirstBrokenId);
    }
}

public class CorruptionTests
{
    [Fact]
    public void Truncated_or_garbage_database_files_fail_closed_with_a_clear_error()
    {
        using var e = new TestEnv();
        e.Admin();
        e.Db.Dispose();
        var copy = Path.Combine(e.Dir, "copy.db");
        File.Copy(e.DbPath, copy);
        File.WriteAllBytes(copy, File.ReadAllBytes(copy).Take(512).ToArray());
        Assert.Throws<InvalidOperationException>(() => new SqlCipherDatabase(copy, e.Key));

        var garbage = Path.Combine(e.Dir, "garbage.db");
        File.WriteAllBytes(garbage, new byte[4096].Select((_, i) => (byte)(i * 31)).ToArray());
        Assert.Throws<InvalidOperationException>(() => new SqlCipherDatabase(garbage, e.Key));
    }
}
