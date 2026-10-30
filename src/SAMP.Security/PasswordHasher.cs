using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace SAMP.Security;

public sealed record Argon2Options(int MemoryKb = 65536, int Iterations = 3, int Parallelism = 2);

/// <summary>Argon2id hashing. Encoded form: $argon2id$v=19$m=..,t=..,p=..$salt$hash</summary>
public sealed class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private readonly Argon2Options _options;

    public PasswordHasher(Argon2Options? options = null) => _options = options ?? new Argon2Options();

    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Derive(password, salt, _options);
        return $"$argon2id$v=19$m={_options.MemoryKb},t={_options.Iterations},p={_options.Parallelism}" +
               $"${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string encoded)
    {
        if (!TryParse(encoded, out var opts, out var salt, out var expected)) return false;
        var actual = Derive(password, salt, opts);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt, Argon2Options o)
    {
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = o.MemoryKb,
            Iterations = o.Iterations,
            DegreeOfParallelism = o.Parallelism,
        };
        return argon.GetBytes(HashSize);
    }

    private static bool TryParse(string encoded, out Argon2Options options, out byte[] salt, out byte[] hash)
    {
        options = new Argon2Options();
        salt = hash = Array.Empty<byte>();
        try
        {
            var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 5 || parts[0] != "argon2id" || parts[1] != "v=19") return false;
            int m = 0, t = 0, p = 0;
            foreach (var kv in parts[2].Split(','))
            {
                var pair = kv.Split('=');
                var v = int.Parse(pair[1]);
                if (pair[0] == "m") m = v; else if (pair[0] == "t") t = v; else if (pair[0] == "p") p = v;
            }
            if (m <= 0 || t <= 0 || p <= 0) return false;
            options = new Argon2Options(m, t, p);
            salt = Convert.FromBase64String(parts[3]);
            hash = Convert.FromBase64String(parts[4]);
            return true;
        }
        catch (Exception e) when (e is FormatException or IndexOutOfRangeException)
        {
            return false;
        }
    }
}
