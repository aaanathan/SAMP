using Microsoft.Data.Sqlite;

namespace SAMP.Data;

public static class Migrator
{
    public static readonly string[] Main =
    {
        // v1
        """
        CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            DisplayName TEXT NOT NULL,
            Role INTEGER NOT NULL,
            PasswordHash TEXT NOT NULL,
            IsActive INTEGER NOT NULL DEFAULT 1,
            MustChangePassword INTEGER NOT NULL DEFAULT 0,
            FailedAttempts INTEGER NOT NULL DEFAULT 0,
            LockedUntilUtc TEXT NULL,
            CreatedAtUtc TEXT NOT NULL,
            LastLoginUtc TEXT NULL
        );
        CREATE TABLE PasswordHistory (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            UserId INTEGER NOT NULL REFERENCES Users(Id) ON DELETE CASCADE,
            Hash TEXT NOT NULL,
            ChangedAtUtc TEXT NOT NULL
        );
        CREATE TABLE Settings (
            Key TEXT PRIMARY KEY,
            Value TEXT NOT NULL
        );
        CREATE TABLE AuditLog (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            TimestampUtc TEXT NOT NULL,
            UserId INTEGER NULL,
            Action TEXT NOT NULL,
            Details TEXT NULL,
            PrevHash TEXT NOT NULL,
            Hash TEXT NOT NULL
        );
        CREATE TRIGGER AuditLog_no_update BEFORE UPDATE ON AuditLog
            BEGIN SELECT RAISE(ABORT, 'AuditLog is append-only'); END;
        CREATE TRIGGER AuditLog_no_delete BEFORE DELETE ON AuditLog
            BEGIN SELECT RAISE(ABORT, 'AuditLog is append-only'); END;
        """,
        // v2
        """
        CREATE TABLE UnblockSessions (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            UserId INTEGER NOT NULL,
            UnblockedAtUtc TEXT NOT NULL,
            ExpiresAtUtc TEXT NOT NULL,
            LastSeenUtc TEXT NOT NULL,
            EndedAtUtc TEXT NULL,
            EndReason TEXT NULL
        );
        CREATE TABLE BlockRules (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT NOT NULL,
            Enabled INTEGER NOT NULL,
            Action INTEGER NOT NULL,
            MatchType INTEGER NOT NULL,
            Value TEXT NOT NULL,
            Scope INTEGER NOT NULL,
            Note TEXT NULL,
            CreatedBy INTEGER NULL,
            CreatedAtUtc TEXT NOT NULL
        );
        """,
    };

    public static void Apply(SqlCipherDatabase db, IReadOnlyList<string> migrations) => db.With(c =>
    {
        using (var create = c.Cmd("CREATE TABLE IF NOT EXISTS SchemaVersion (Version INTEGER NOT NULL);"))
            create.ExecuteNonQuery();

        int current;
        using (var q = c.Cmd("SELECT COALESCE(MAX(Version), 0) FROM SchemaVersion;"))
            current = Convert.ToInt32(q.ExecuteScalar());

        for (var v = current; v < migrations.Count; v++)
        {
            using var tx = c.BeginTransaction();
            using (var m = c.Cmd(migrations[v])) { m.Transaction = tx; m.ExecuteNonQuery(); }
            using (var s = c.Cmd("INSERT INTO SchemaVersion (Version) VALUES ($v);", ("$v", v + 1))) { s.Transaction = tx; s.ExecuteNonQuery(); }
            tx.Commit();
        }
    });
}
