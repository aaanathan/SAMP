using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SAMP.Core;
using SAMP.Data;

namespace SAMP.Logging;

public sealed record DeviceLogRecord(long Seq, DateTime TimestampUtc, string EventType, string Payload, string PrevHash, string Hash);

public sealed record DeviceLogVerifyResult(bool IsValid, long? FirstBrokenSeq, string? Reason, IReadOnlyList<string> Warnings, long RecordCount);

public interface IAnchorSink
{
    void Write(string line);
    IReadOnlyList<string> ReadAll();
}

/// <summary>Append-only text file kept apart from the log files (different folder/ACL, or copied externally).</summary>
public sealed class FileAnchorSink : IAnchorSink
{
    private readonly string _path;
    private readonly object _lock = new();

    public FileAnchorSink(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    }

    public void Write(string line)
    {
        lock (_lock) File.AppendAllText(_path, line + "\n");
    }

    public IReadOnlyList<string> ReadAll()
    {
        lock (_lock) return File.Exists(_path) ? File.ReadAllLines(_path) : Array.Empty<string>();
    }
}

/// <summary>
/// One encrypted SQLCipher file per UTC day (devicelog-YYYYMMDD.db). Records form a single HMAC-SHA256 chain across
/// days; chain heads are periodically written to independent anchor sinks. The writer keeps today's file open with
/// exclusive locking so no other process can open it.
/// </summary>
public sealed class DeviceLog : IDisposable
{
    public const string FilePrefix = "devicelog-";
    public const int AnchorEveryRecords = 50;
    private static readonly TimeSpan GapThreshold = TimeSpan.FromMinutes(5);
    private static readonly string Genesis = new('0', 64);

    private static readonly string[] Migrations =
    {
        """
        CREATE TABLE DeviceLog (
            Seq INTEGER PRIMARY KEY,
            TimestampUtc TEXT NOT NULL,
            EventType TEXT NOT NULL,
            Payload TEXT NOT NULL,
            PrevHash TEXT NOT NULL,
            Hash TEXT NOT NULL
        );
        CREATE TRIGGER DeviceLog_no_update BEFORE UPDATE ON DeviceLog BEGIN SELECT RAISE(ABORT, 'DeviceLog is append-only'); END;
        CREATE TRIGGER DeviceLog_no_delete BEFORE DELETE ON DeviceLog BEGIN SELECT RAISE(ABORT, 'DeviceLog is append-only'); END;
        """,
    };

    private readonly string _dir;
    private readonly byte[] _master;
    private readonly byte[] _hmacKey;
    private readonly IClock _clock;
    private readonly IReadOnlyList<IAnchorSink> _anchors;
    private readonly object _lock = new();
    private SqlCipherDatabase? _db;
    private DateOnly _dbDay;
    private long _lastSeq;
    private string _lastHash = Genesis;

    public int RetentionDays { get; }

    public DeviceLog(string directory, byte[] masterKey, IClock clock, IReadOnlyList<IAnchorSink> anchors, int retentionDays = 30)
    {
        _dir = directory;
        _master = masterKey;
        _clock = clock;
        _anchors = anchors;
        RetentionDays = retentionDays;
        _hmacKey = Derive("samp-devicelog-hmac");
        Directory.CreateDirectory(_dir);
        LoadTail();
    }

    // ---- writing ---------------------------------------------------------------------------------

    public DeviceLogRecord Append(string eventType, object? payload = null)
    {
        lock (_lock)
        {
            var now = _clock.UtcNow;
            EnsureDb(DateOnly.FromDateTime(now));

            var seq = _lastSeq + 1;
            var ts = now.ToString("o", CultureInfo.InvariantCulture);
            var json = JsonSerializer.Serialize(payload ?? new { });
            var hash = ComputeHash(seq, ts, eventType, json, _lastHash);
            var prev = _lastHash;

            _db!.With(c =>
            {
                using var cmd = c.Cmd(
                    "INSERT INTO DeviceLog (Seq, TimestampUtc, EventType, Payload, PrevHash, Hash) VALUES ($s,$t,$e,$p,$ph,$h);",
                    ("$s", seq), ("$t", ts), ("$e", eventType), ("$p", json), ("$ph", prev), ("$h", hash));
                cmd.ExecuteNonQuery();
            });

            _lastSeq = seq;
            _lastHash = hash;
            if (seq % AnchorEveryRecords == 0) WriteAnchorLocked();
            return new DeviceLogRecord(seq, now, eventType, json, prev, hash);
        }
    }

    public void Heartbeat() => Append("heartbeat");

    /// <summary>The newest record in the chain, or null for an empty log.</summary>
    public DeviceLogRecord? LastRecord()
    {
        lock (_lock)
        {
            foreach (var f in ListFiles().OrderByDescending(f => f.Day))
            {
                var recs = ReadFile(f);
                if (recs.Count > 0) return recs.OrderBy(r => r.Seq).Last();
            }
            return null;
        }
    }

    public void WriteAnchor()
    {
        lock (_lock) WriteAnchorLocked();
    }

    private void WriteAnchorLocked()
    {
        if (_lastSeq == 0) return;
        var body = $"{_clock.UtcNow.ToString("o", CultureInfo.InvariantCulture)}|{_lastSeq}|{_lastHash}";
        var line = $"{body}|{Mac(body)}";
        foreach (var a in _anchors) a.Write(line);
    }

    // ---- reading ---------------------------------------------------------------------------------

    /// <summary>Newest first.</summary>
    public IReadOnlyList<DeviceLogRecord> Query(DateTime? fromUtc, DateTime? toUtc, int limit)
    {
        lock (_lock)
        {
            var result = new List<DeviceLogRecord>();
            foreach (var file in ListFiles().OrderByDescending(f => f.Day))
            {
                if (fromUtc is { } f && file.Day < DateOnly.FromDateTime(f)) continue;
                if (toUtc is { } t && file.Day > DateOnly.FromDateTime(t)) continue;
                foreach (var r in ReadFile(file).OrderByDescending(r => r.Seq))
                {
                    if (fromUtc is { } ff && r.TimestampUtc < ff) continue;
                    if (toUtc is { } tt && r.TimestampUtc > tt) continue;
                    result.Add(r);
                    if (result.Count >= limit) return result;
                }
            }
            return result;
        }
    }

    public DeviceLogVerifyResult Verify()
    {
        lock (_lock)
        {
            var warnings = new List<string>();
            var anchorSeqs = new Dictionary<long, string>();
            foreach (var sink in _anchors)
            foreach (var line in sink.ReadAll())
            {
                var parts = line.Split('|');
                if (parts.Length != 4 || !long.TryParse(parts[1], out var aseq)) { warnings.Add("Unparseable anchor line ignored."); continue; }
                if (!Eq(Mac($"{parts[0]}|{parts[1]}|{parts[2]}"), parts[3])) { warnings.Add($"Anchor for seq {aseq} has an invalid signature (ignored)."); continue; }
                if (anchorSeqs.TryGetValue(aseq, out var existing) && existing != parts[2])
                    return new DeviceLogVerifyResult(false, aseq, "Conflicting anchors for the same record.", warnings, 0);
                anchorSeqs[aseq] = parts[2];
            }

            long count = 0;
            long? prevSeq = null;
            string? prevHash = null;
            DateTime? prevTs = null;
            long prunedUpTo = 0;
            long firstSeq = 0;
            var seenAnchorHashes = new Dictionary<long, string>();

            foreach (var file in ListFiles().OrderBy(f => f.Day))
            foreach (var r in ReadFile(file).OrderBy(r => r.Seq))
            {
                if (count == 0) firstSeq = r.Seq;
                if (prevSeq != null && r.Seq != prevSeq + 1)
                    return Fail(r.Seq, "Missing record(s) before this entry.");
                if (prevHash != null && r.PrevHash != prevHash)
                    return Fail(r.Seq, "Chain link does not match previous record.");
                if (prevHash == null && r.Seq == 1 && r.PrevHash != Genesis)
                    return Fail(r.Seq, "First record has an invalid genesis link.");
                if (!Eq(ComputeHash(r.Seq, r.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), r.EventType, r.Payload, r.PrevHash), r.Hash))
                    return Fail(r.Seq, "Record content does not match its signature.");

                if (r.EventType == "log.pruned")
                {
                    using var doc = JsonDocument.Parse(r.Payload);
                    if (doc.RootElement.TryGetProperty("upToSeq", out var u) && u.TryGetInt64(out var up)) prunedUpTo = Math.Max(prunedUpTo, up);
                }
                if (prevTs != null && r.TimestampUtc - prevTs > GapThreshold)
                    warnings.Add($"Logging gap of {(r.TimestampUtc - prevTs.Value).TotalMinutes:F0} min before seq {r.Seq} ({prevTs:O} to {r.TimestampUtc:O}).");
                if (anchorSeqs.ContainsKey(r.Seq)) seenAnchorHashes[r.Seq] = r.Hash;

                prevSeq = r.Seq; prevHash = r.Hash; prevTs = r.TimestampUtc; count++;
            }

            if (count > 0 && firstSeq > 1 && prunedUpTo < firstSeq - 1)
                return new DeviceLogVerifyResult(false, firstSeq, "Earlier log files are missing without a prune record.", warnings, count);

            foreach (var (aseq, ahash) in anchorSeqs.OrderBy(k => k.Key))
            {
                if (seenAnchorHashes.TryGetValue(aseq, out var h))
                {
                    if (!Eq(h, ahash)) return new DeviceLogVerifyResult(false, aseq, "Log differs from its external anchor (log was altered or rolled back).", warnings, count);
                }
                else if (aseq > (prevSeq ?? 0))
                {
                    return new DeviceLogVerifyResult(false, aseq, "Log is shorter than its external anchor (truncated).", warnings, count);
                }
                else if (aseq > prunedUpTo)
                {
                    return new DeviceLogVerifyResult(false, aseq, "Anchored record is missing from the log.", warnings, count);
                }
            }
            return new DeviceLogVerifyResult(true, null, null, warnings, count);

            DeviceLogVerifyResult Fail(long seq, string why) => new(false, seq, why, warnings, count);
        }
    }

    // ---- retention & replication -----------------------------------------------------------------

    /// <summary>
    /// Copies closed (past) day files and the anchors to <paramref name="destDir"/>, still encrypted.
    /// Uses temp-file + rename so partial copies never look complete.
    /// </summary>
    public int Replicate(string destDir)
    {
        lock (_lock)
        {
            Directory.CreateDirectory(destDir);
            var today = DateOnly.FromDateTime(_clock.UtcNow);
            var copied = 0;
            foreach (var f in ListFiles().Where(f => f.Day < today))
            {
                var target = Path.Combine(destDir, Path.GetFileName(f.Path));
                if (SameFile(f.Path, target)) continue;
                var tmp = target + ".part";
                File.Copy(f.Path, tmp, overwrite: true);
                File.Move(tmp, target, overwrite: true);
                copied++;
            }
            return copied;
        }
    }

    public bool IsReplicated(string destDir, DateOnly day)
    {
        var name = FileName(day);
        return SameFile(Path.Combine(_dir, name), Path.Combine(destDir, name));
    }

    /// <summary>
    /// Deletes whole day files older than the retention window. A signed prune record is appended first so the
    /// removal is distinguishable from tampering. When <paramref name="canDelete"/> returns false the file is kept.
    /// </summary>
    public int Prune(Func<DateOnly, bool>? canDelete = null)
    {
        lock (_lock)
        {
            var cutoff = DateOnly.FromDateTime(_clock.UtcNow).AddDays(-RetentionDays);
            var removed = 0;
            foreach (var f in ListFiles().Where(f => f.Day < cutoff).OrderBy(f => f.Day).ToList())
            {
                if (canDelete != null && !canDelete(f.Day)) break; // keep order: never leave a hole
                var recs = ReadFile(f);
                if (recs.Count > 0)
                    Append("log.pruned", new { file = Path.GetFileName(f.Path), upToSeq = recs.Max(r => r.Seq), finalHash = recs.OrderBy(r => r.Seq).Last().Hash });
                DeleteDbFiles(f.Path);
                removed++;
            }
            return removed;
        }
    }

    public IReadOnlyList<DateOnly> Days() => ListFiles().Select(f => f.Day).OrderBy(d => d).ToList();

    public static string FileName(DateOnly day) => $"{FilePrefix}{day:yyyyMMdd}.db";

    // ---- internals -------------------------------------------------------------------------------

    private readonly record struct LogFile(DateOnly Day, string Path);

    private List<LogFile> ListFiles()
    {
        var list = new List<LogFile>();
        foreach (var p in Directory.GetFiles(_dir, FilePrefix + "????????.db"))
        {
            var stem = Path.GetFileNameWithoutExtension(p)[FilePrefix.Length..];
            if (DateOnly.TryParseExact(stem, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
                list.Add(new LogFile(d, p));
        }
        return list;
    }

    private List<DeviceLogRecord> ReadFile(LogFile file)
    {
        if (_db != null && file.Day == _dbDay) return ReadFrom(_db);
        using var db = Open(file.Day);
        return ReadFrom(db);
    }

    private static List<DeviceLogRecord> ReadFrom(SqlCipherDatabase db) => db.With(c =>
    {
        var list = new List<DeviceLogRecord>();
        using var cmd = c.Cmd("SELECT Seq, TimestampUtc, EventType, Payload, PrevHash, Hash FROM DeviceLog ORDER BY Seq;");
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new DeviceLogRecord(r.GetInt64(0), SqliteExtensions.ParseUtc(r.GetString(1)), r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5)));
        return list;
    });

    private SqlCipherDatabase Open(DateOnly day) =>
        new(Path.Combine(_dir, FileName(day)), Derive("samp-devicelog-db-" + day.ToString("yyyyMMdd", CultureInfo.InvariantCulture)), Migrations);

    private void EnsureDb(DateOnly day)
    {
        if (_db != null && _dbDay == day) return;
        _db?.Dispose();
        _db = Open(day);
        _dbDay = day;
        _db.With(c => { using var cmd = c.Cmd("PRAGMA locking_mode = EXCLUSIVE;"); cmd.ExecuteNonQuery(); });
    }

    private void LoadTail()
    {
        foreach (var f in ListFiles().OrderByDescending(f => f.Day))
        {
            var recs = ReadFile(f);
            if (recs.Count == 0) continue;
            var last = recs.OrderBy(r => r.Seq).Last();
            _lastSeq = last.Seq;
            _lastHash = last.Hash;
            return;
        }
    }

    private static void DeleteDbFiles(string path)
    {
        foreach (var p in new[] { path, path + "-wal", path + "-shm" })
            if (File.Exists(p)) File.Delete(p);
    }

    private static bool SameFile(string a, string b)
    {
        if (!File.Exists(a) || !File.Exists(b)) return false;
        if (new FileInfo(a).Length != new FileInfo(b).Length) return false;
        using var sa = File.OpenRead(a); using var sb = File.OpenRead(b);
        return SHA256.HashData(sa).AsSpan().SequenceEqual(SHA256.HashData(sb));
    }

    private byte[] Derive(string info) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, _master, 32, salt: null, info: Encoding.UTF8.GetBytes(info));

    private string Mac(string s) => Convert.ToHexString(HMACSHA256.HashData(_hmacKey, Encoding.UTF8.GetBytes(s)));

    private string ComputeHash(long seq, string ts, string type, string payload, string prev)
    {
        var sb = new StringBuilder();
        foreach (var f in new[] { seq.ToString(CultureInfo.InvariantCulture), ts, type, payload, prev })
            sb.Append(f.Length).Append(':').Append(f).Append('|');
        return Mac(sb.ToString());
    }

    private static bool Eq(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));

    public void Dispose()
    {
        lock (_lock) _db?.Dispose();
    }
}
