using Microsoft.Data.Sqlite;
using SAMP.Core;
using SAMP.Data;
using SAMP.Logging;

namespace SAMP.Tests;

public class DeviceLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "samp-log-" + Guid.NewGuid().ToString("N"));
    private readonly FakeClock _clock = new();
    private readonly byte[] _key = new byte[32].Select((_, i) => (byte)(i + 1)).ToArray();
    private readonly FileAnchorSink _anchor;
    private DeviceLog _log;

    public DeviceLogTests()
    {
        Directory.CreateDirectory(_dir);
        _anchor = new FileAnchorSink(Path.Combine(_dir, "anchors", "anchors.log"));
        _log = Open();
    }

    private DeviceLog Open() => new(Path.Combine(_dir, "logs"), _key, _clock, [_anchor]);

    public void Dispose()
    {
        _log.Dispose();
        try { Directory.Delete(_dir, true); } catch (IOException) { }
    }

    private string FileFor(DateTime d) => Path.Combine(_dir, "logs", DeviceLog.FileName(DateOnly.FromDateTime(d)));

    [Fact]
    public void Records_chain_and_verify()
    {
        for (var i = 0; i < 5; i++) { _log.Append("device.connected", new { vid = "0951", n = i }); _clock.Advance(TimeSpan.FromMinutes(1)); }
        var v = _log.Verify();
        Assert.True(v.IsValid, v.Reason);
        Assert.Equal(5, v.RecordCount);
        Assert.Equal(5, _log.Query(null, null, 100).Count);
    }

    [Fact]
    public void One_file_per_day_and_chain_continues_across_midnight()
    {
        _clock.UtcNow = new DateTime(2026, 3, 1, 23, 59, 0, DateTimeKind.Utc);
        _log.Append("a");
        _clock.Advance(TimeSpan.FromMinutes(2));
        var second = _log.Append("b");
        Assert.Equal(2, _log.Days().Count);
        Assert.Equal(2, second.Seq);
        Assert.True(_log.Verify().IsValid);

        _log.Dispose();
        _log = Open(); // restart: tail is recovered from the latest file
        Assert.Equal(3, _log.Append("c").Seq);
        Assert.True(_log.Verify().IsValid);
    }

    [Fact]
    public void Files_are_encrypted_and_unreadable_without_the_key()
    {
        _log.Append("device.connected", new { serial = "SECRET-SERIAL-123" });
        _log.Dispose();
        var path = FileFor(_clock.UtcNow);
        var bytes = File.ReadAllBytes(path);
        Assert.DoesNotContain("SECRET-SERIAL-123", System.Text.Encoding.Latin1.GetString(bytes));
        Assert.False(bytes.AsSpan(0, 15).SequenceEqual("SQLite format 3"u8));
        Assert.Throws<InvalidOperationException>(() => new SqlCipherDatabase(path, new byte[32]));
        _log = Open();
    }

    [Fact]
    public void Todays_file_cannot_be_opened_by_another_connection_while_the_writer_holds_it()
    {
        _log.Append("x");
        var day = DateOnly.FromDateTime(_clock.UtcNow);
        var dayKey = System.Security.Cryptography.HKDF.DeriveKey(System.Security.Cryptography.HashAlgorithmName.SHA256, _key, 32, null,
            System.Text.Encoding.UTF8.GetBytes("samp-devicelog-db-" + day.ToString("yyyyMMdd")));
        Assert.Throws<InvalidOperationException>(() => new SqlCipherDatabase(FileFor(_clock.UtcNow), dayKey));
    }

    private void Raw(string file, string sql)
    {
        var day = DateOnly.ParseExact(Path.GetFileNameWithoutExtension(file)[DeviceLog.FilePrefix.Length..], "yyyyMMdd");
        var key = System.Security.Cryptography.HKDF.DeriveKey(System.Security.Cryptography.HashAlgorithmName.SHA256, _key, 32, null,
            System.Text.Encoding.UTF8.GetBytes("samp-devicelog-db-" + day.ToString("yyyyMMdd")));
        using var db = new SqlCipherDatabase(file, key, ["SELECT 1;"]);
        db.With(c => { using var cmd = c.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery(); });
    }

    [Fact]
    public void Update_and_delete_are_blocked_by_triggers()
    {
        _log.Append("x");
        _clock.Advance(TimeSpan.FromDays(1)); // roll so yesterday's file is closed and openable
        _log.Append("y");
        var f = FileFor(_clock.UtcNow.AddDays(-1));
        Assert.Throws<SqliteException>(() => Raw(f, "UPDATE DeviceLog SET EventType='z' WHERE Seq=1;"));
        Assert.Throws<SqliteException>(() => Raw(f, "DELETE FROM DeviceLog WHERE Seq=1;"));
    }

    [Fact]
    public void Edited_record_is_detected_even_when_triggers_are_dropped()
    {
        _log.Append("device.connected", new { s = "A" });
        _log.Append("device.removed", new { s = "A" });
        _clock.Advance(TimeSpan.FromDays(1));
        _log.Append("later");
        var f = FileFor(_clock.UtcNow.AddDays(-1));
        Raw(f, "DROP TRIGGER DeviceLog_no_update;");
        Raw(f, "UPDATE DeviceLog SET Payload='{\"s\":\"forged\"}' WHERE Seq=1;");
        var v = _log.Verify();
        Assert.False(v.IsValid);
        Assert.Equal(1, v.FirstBrokenSeq);
    }

    [Fact]
    public void Deleted_record_is_detected()
    {
        for (var i = 0; i < 3; i++) _log.Append("e");
        _clock.Advance(TimeSpan.FromDays(1));
        _log.Append("later");
        var f = FileFor(_clock.UtcNow.AddDays(-1));
        Raw(f, "DROP TRIGGER DeviceLog_no_delete;");
        Raw(f, "DELETE FROM DeviceLog WHERE Seq=2;");
        var v = _log.Verify();
        Assert.False(v.IsValid);
        Assert.Equal(3, v.FirstBrokenSeq);
    }

    [Fact]
    public void Deleting_a_whole_middle_file_is_detected()
    {
        _log.Append("d1");
        _clock.Advance(TimeSpan.FromDays(1)); _log.Append("d2");
        _clock.Advance(TimeSpan.FromDays(1)); _log.Append("d3");
        File.Delete(FileFor(_clock.UtcNow.AddDays(-1)));
        Assert.False(_log.Verify().IsValid);
    }

    [Fact]
    public void Truncating_the_tail_is_caught_by_the_external_anchor()
    {
        for (var i = 0; i < 4; i++) _log.Append("e");
        _clock.Advance(TimeSpan.FromDays(1));
        _log.Append("e5");
        _log.WriteAnchor(); // anchor at seq 5
        _log.Dispose();
        File.Delete(FileFor(_clock.UtcNow)); // attacker removes the newest file (seq 5)
        _log = Open();
        var v = _log.Verify();
        Assert.False(v.IsValid);
        Assert.Contains("shorter", v.Reason);
    }

    [Fact]
    public void Rolling_back_to_an_old_copy_of_the_log_is_caught()
    {
        _log.Append("a"); _log.Append("b");
        _log.WriteAnchor();
        _log.Dispose();
        var path = FileFor(_clock.UtcNow);
        var copyDir = Path.Combine(_dir, "old"); Directory.CreateDirectory(copyDir);
        File.Copy(path, Path.Combine(copyDir, Path.GetFileName(path)));

        _log = Open();
        _log.Append("c"); _log.WriteAnchor(); // anchor at seq 3
        _log.Dispose();
        foreach (var p in Directory.GetFiles(Path.Combine(_dir, "logs"))) File.Delete(p);
        File.Copy(Path.Combine(copyDir, Path.GetFileName(path)), path);
        _log = Open();
        Assert.False(_log.Verify().IsValid);
    }

    [Fact]
    public void Forged_anchor_lines_are_ignored_with_a_warning()
    {
        _log.Append("a");
        _anchor.Write("2026-01-01T00:00:00.0000000Z|999|DEADBEEF|BADMAC");
        var v = _log.Verify();
        Assert.True(v.IsValid);
        Assert.NotEmpty(v.Warnings);
    }

    [Fact]
    public void Heartbeat_gaps_are_reported_as_warnings()
    {
        _log.Heartbeat();
        _clock.Advance(TimeSpan.FromMinutes(30));
        _log.Heartbeat();
        var v = _log.Verify();
        Assert.True(v.IsValid);
        Assert.Contains(v.Warnings, w => w.Contains("gap"));
    }

    [Fact]
    public void Prune_removes_only_files_past_retention_and_leaves_a_signed_record()
    {
        _clock.UtcNow = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        _log.Append("old1");
        _clock.Advance(TimeSpan.FromDays(1)); _log.Append("old2");
        _clock.Advance(TimeSpan.FromDays(40)); _log.Append("recent");

        Assert.Equal(3, _log.Days().Count);
        Assert.Equal(2, _log.Prune());
        Assert.Single(_log.Days());
        var v = _log.Verify();
        Assert.True(v.IsValid, v.Reason);
        Assert.Contains(_log.Query(null, null, 50), r => r.EventType == "log.pruned");
    }

    [Fact]
    public void Prune_waits_for_external_copy_when_required()
    {
        var ext = Path.Combine(_dir, "external");
        _clock.UtcNow = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        _log.Append("old");
        _clock.Advance(TimeSpan.FromDays(40)); _log.Append("recent");

        Assert.Equal(0, _log.Prune(day => _log.IsReplicated(ext, day)));
        Assert.Equal(1, _log.Replicate(ext));
        Assert.Equal(0, _log.Replicate(ext)); // idempotent
        Assert.Equal(1, _log.Prune(day => _log.IsReplicated(ext, day)));
        Assert.True(_log.Verify().IsValid);
        // the replicated file is still encrypted
        var copy = Directory.GetFiles(ext, "*.db").Single();
        Assert.False(File.ReadAllBytes(copy).AsSpan(0, 15).SequenceEqual("SQLite format 3"u8));
    }

    [Fact]
    public void Missing_early_files_without_prune_record_are_flagged()
    {
        _log.Append("d1");
        _clock.Advance(TimeSpan.FromDays(1)); _log.Append("d2");
        File.Delete(FileFor(_clock.UtcNow.AddDays(-1)));
        Assert.False(_log.Verify().IsValid);
    }

    [Fact]
    public void Query_filters_by_time_range_newest_first()
    {
        _log.Append("a"); _clock.Advance(TimeSpan.FromHours(1));
        _log.Append("b"); _clock.Advance(TimeSpan.FromHours(1));
        _log.Append("c");
        var recs = _log.Query(_clock.UtcNow.AddMinutes(-90), null, 10);
        Assert.Equal(["c", "b"], recs.Select(r => r.EventType).ToArray());
        Assert.Single(_log.Query(null, null, 1));
    }
}
