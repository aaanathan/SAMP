using Microsoft.Data.Sqlite;

namespace SAMP.Data;

/// <summary>
/// Single long-lived SQLCipher connection (the service is the only process that opens the file).
/// All access is serialised through <see cref="With{T}"/>.
/// </summary>
public sealed class SqlCipherDatabase : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly object _lock = new();

    static SqlCipherDatabase() => SQLitePCL.Batteries_V2.Init();

    public SqlCipherDatabase(string path, byte[] key, IReadOnlyList<string>? migrations = null)
    {
        if (key.Length != DatabaseKeyStore.KeySize) throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        _conn = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Pooling = false,
            DefaultTimeout = 5,
        }.ToString());
        _conn.Open();
        try
        {
            Exec($"PRAGMA key = \"x'{Convert.ToHexString(key)}'\";");
            Exec("SELECT count(*) FROM sqlite_master;"); // fails here if the key is wrong
            Exec("PRAGMA foreign_keys = ON;");
            Exec("PRAGMA journal_mode = WAL;");
        }
        catch (SqliteException e)
        {
            _conn.Dispose();
            throw new InvalidOperationException("Unable to open database: wrong key or corrupt file.", e);
        }
        Migrator.Apply(this, migrations ?? Migrator.Main);
    }

    public T With<T>(Func<SqliteConnection, T> action)
    {
        lock (_lock) return action(_conn);
    }

    public void With(Action<SqliteConnection> action) => With<object?>(c => { action(c); return null; });

    private void Exec(string sql)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public void Dispose()
    {
        lock (_lock) _conn.Dispose();
    }
}

public static class SqliteExtensions
{
    public static SqliteCommand Cmd(this SqliteConnection c, string sql, params (string Name, object? Value)[] ps)
    {
        var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in ps) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd;
    }

    public static string Iso(this DateTime d) => d.ToUniversalTime().ToString("o", System.Globalization.CultureInfo.InvariantCulture);

    public static DateTime ParseUtc(string s) =>
        DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime();
}
