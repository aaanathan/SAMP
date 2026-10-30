using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace SAMP.Data;

public interface IKeyProtector
{
    byte[] Protect(byte[] plain);
    byte[] Unprotect(byte[] protectedData);
}

/// <summary>DPAPI, LocalMachine scope, so the service (SYSTEM) and installer see the same key on this machine only.</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyProtector : IKeyProtector
{
    private static readonly byte[] Entropy = "SAMP.DbKey.v1"u8.ToArray();

    public byte[] Protect(byte[] plain) =>
        ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);

    public byte[] Unprotect(byte[] protectedData) =>
        ProtectedData.Unprotect(protectedData, Entropy, DataProtectionScope.LocalMachine);
}

public static class DatabaseKeyStore
{
    public const int KeySize = 32;

    /// <summary>Loads the protected 256-bit key, creating and persisting a new random one on first run.</summary>
    public static byte[] LoadOrCreate(string keyFilePath, IKeyProtector protector)
    {
        if (File.Exists(keyFilePath))
            return protector.Unprotect(File.ReadAllBytes(keyFilePath));

        var dir = Path.GetDirectoryName(Path.GetFullPath(keyFilePath))!;
        Directory.CreateDirectory(dir);
        var key = RandomNumberGenerator.GetBytes(KeySize);
        var tmp = keyFilePath + ".tmp";
        File.WriteAllBytes(tmp, protector.Protect(key));
        File.Move(tmp, keyFilePath, overwrite: false);
        return key;
    }
}
