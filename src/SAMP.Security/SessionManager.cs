using System.Security.Cryptography;
using SAMP.Core;

namespace SAMP.Security;

public sealed record Session(string Token, long UserId, string Username, Role Role, DateTime CreatedUtc)
{
    public DateTime LastActivityUtc { get; internal set; } = CreatedUtc;
}

/// <summary>In-memory, server-side sessions with sliding idle timeout. Lives in the service process.</summary>
public sealed class SessionManager
{
    private readonly IClock _clock;
    private readonly TimeSpan _idleTimeout;
    private readonly Dictionary<string, Session> _sessions = new();
    private readonly object _lock = new();

    public SessionManager(IClock clock, TimeSpan? idleTimeout = null)
    {
        _clock = clock;
        _idleTimeout = idleTimeout ?? TimeSpan.FromMinutes(15);
    }

    public Session Create(User user)
    {
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var session = new Session(token, user.Id, user.Username, user.Role, _clock.UtcNow);
        lock (_lock) _sessions[token] = session;
        return session;
    }

    /// <summary>Returns the session and slides its idle window, or null if unknown/expired.</summary>
    public Session? Validate(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        lock (_lock)
        {
            if (!_sessions.TryGetValue(token, out var s)) return null;
            var now = _clock.UtcNow;
            if (now - s.LastActivityUtc > _idleTimeout)
            {
                _sessions.Remove(token);
                return null;
            }
            s.LastActivityUtc = now;
            return s;
        }
    }

    public Session RequireRole(string? token, Role minimum)
    {
        var s = Validate(token) ?? throw new UnauthorizedAccessException("Not logged in or session expired.");
        if (s.Role < minimum) throw new UnauthorizedAccessException("Insufficient role.");
        return s;
    }

    public void Revoke(string token)
    {
        lock (_lock) _sessions.Remove(token);
    }

    public void RevokeAllForUser(long userId)
    {
        lock (_lock)
        {
            foreach (var t in _sessions.Where(kv => kv.Value.UserId == userId).Select(kv => kv.Key).ToList())
                _sessions.Remove(t);
        }
    }
}
