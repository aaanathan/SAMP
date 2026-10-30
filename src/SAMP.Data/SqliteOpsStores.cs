using Microsoft.Data.Sqlite;
using SAMP.Core;

namespace SAMP.Data;

public sealed class SqliteUnblockSessionStore(SqlCipherDatabase db) : IUnblockSessionStore
{
    public long Add(UnblockSession s) => db.With(c =>
    {
        using var cmd = c.Cmd(
            """
            INSERT INTO UnblockSessions (UserId, UnblockedAtUtc, ExpiresAtUtc, LastSeenUtc) VALUES ($u, $a, $e, $l);
            SELECT last_insert_rowid();
            """,
            ("$u", s.UserId), ("$a", s.UnblockedAtUtc.Iso()), ("$e", s.ExpiresAtUtc.Iso()), ("$l", s.LastSeenUtc.Iso()));
        return Convert.ToInt64(cmd.ExecuteScalar());
    });

    public UnblockSession? GetActive() => db.With(c =>
    {
        using var cmd = c.Cmd("SELECT Id, UserId, UnblockedAtUtc, ExpiresAtUtc, LastSeenUtc FROM UnblockSessions WHERE EndedAtUtc IS NULL ORDER BY Id DESC LIMIT 1;");
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new UnblockSession
        {
            Id = r.GetInt64(0),
            UserId = r.GetInt64(1),
            UnblockedAtUtc = SqliteExtensions.ParseUtc(r.GetString(2)),
            ExpiresAtUtc = SqliteExtensions.ParseUtc(r.GetString(3)),
            LastSeenUtc = SqliteExtensions.ParseUtc(r.GetString(4)),
        };
    });

    public void End(long id, DateTime atUtc, string reason) => db.With(c =>
    {
        using var cmd = c.Cmd("UPDATE UnblockSessions SET EndedAtUtc=$t, EndReason=$r WHERE Id=$id;",
            ("$t", atUtc.Iso()), ("$r", reason), ("$id", id));
        cmd.ExecuteNonQuery();
    });

    public void Touch(long id, DateTime lastSeenUtc) => db.With(c =>
    {
        using var cmd = c.Cmd("UPDATE UnblockSessions SET LastSeenUtc=$t WHERE Id=$id;", ("$t", lastSeenUtc.Iso()), ("$id", id));
        cmd.ExecuteNonQuery();
    });

    public void SetExpiry(long id, DateTime expiresAtUtc) => db.With(c =>
    {
        using var cmd = c.Cmd("UPDATE UnblockSessions SET ExpiresAtUtc=$t WHERE Id=$id;", ("$t", expiresAtUtc.Iso()), ("$id", id));
        cmd.ExecuteNonQuery();
    });
}

public sealed class SqliteBlockRuleStore(SqlCipherDatabase db) : IBlockRuleStore
{
    private const string Cols = "Id, Name, Enabled, Action, MatchType, Value, Scope, Note, CreatedBy, CreatedAtUtc";

    public IReadOnlyList<BlockRule> List() => db.With(c =>
    {
        var list = new List<BlockRule>();
        using var cmd = c.Cmd($"SELECT {Cols} FROM BlockRules ORDER BY Id;");
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Map(r));
        return (IReadOnlyList<BlockRule>)list;
    });

    public long Add(BlockRule x) => db.With(c =>
    {
        using var cmd = c.Cmd(
            """
            INSERT INTO BlockRules (Name, Enabled, Action, MatchType, Value, Scope, Note, CreatedBy, CreatedAtUtc)
            VALUES ($n, $e, $a, $m, $v, $s, $note, $cb, $ca);
            SELECT last_insert_rowid();
            """,
            ("$n", x.Name), ("$e", x.Enabled ? 1 : 0), ("$a", (int)x.Action), ("$m", (int)x.MatchType),
            ("$v", x.Value), ("$s", (int)x.Scope), ("$note", x.Note), ("$cb", x.CreatedBy), ("$ca", x.CreatedAtUtc.Iso()));
        return Convert.ToInt64(cmd.ExecuteScalar());
    });

    public void Update(BlockRule x) => db.With(c =>
    {
        using var cmd = c.Cmd(
            "UPDATE BlockRules SET Name=$n, Enabled=$e, Action=$a, MatchType=$m, Value=$v, Scope=$s, Note=$note WHERE Id=$id;",
            ("$id", x.Id), ("$n", x.Name), ("$e", x.Enabled ? 1 : 0), ("$a", (int)x.Action), ("$m", (int)x.MatchType),
            ("$v", x.Value), ("$s", (int)x.Scope), ("$note", x.Note));
        cmd.ExecuteNonQuery();
    });

    public void Delete(long id) => db.With(c =>
    {
        using var cmd = c.Cmd("DELETE FROM BlockRules WHERE Id=$id;", ("$id", id));
        cmd.ExecuteNonQuery();
    });

    private static BlockRule Map(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0),
        Name = r.GetString(1),
        Enabled = r.GetInt32(2) == 1,
        Action = (RuleAction)r.GetInt32(3),
        MatchType = (BlockMatchType)r.GetInt32(4),
        Value = r.GetString(5),
        Scope = (RuleScope)r.GetInt32(6),
        Note = r.IsDBNull(7) ? null : r.GetString(7),
        CreatedBy = r.IsDBNull(8) ? null : r.GetInt64(8),
        CreatedAtUtc = SqliteExtensions.ParseUtc(r.GetString(9)),
    };
}
