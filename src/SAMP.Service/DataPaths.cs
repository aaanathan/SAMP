using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SAMP.Service;

public sealed class DataPaths
{
    public string Root { get; }
    public string Database => Path.Combine(Root, "samp.db");
    public string DatabaseKey => Path.Combine(Root, "samp.key");
    public string LogKey => Path.Combine(Root, "log.key");
    public string LogDir => Path.Combine(Root, "logs");
    /// <summary>Anchors live outside the log folder so removing the log folder does not remove them.</summary>
    public string AnchorFile => Path.Combine(Root, "anchors", "anchors.log");
    public string AnchorMirrorFile => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SAMP.Anchor", "anchors.log");

    public DataPaths(string? root = null)
    {
        Root = root ?? Environment.GetEnvironmentVariable("SAMP_DATA_DIR")
               ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SAMP");
    }

    /// <summary>Creates the folders; on Windows, removes inheritance and grants SYSTEM only.</summary>
    public void Prepare()
    {
        foreach (var d in new[] { Root, LogDir, Path.GetDirectoryName(AnchorFile)!, Path.GetDirectoryName(AnchorMirrorFile)! })
        {
            Directory.CreateDirectory(d);
            if (OperatingSystem.IsWindows()) LockDownToSystem(d);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void LockDownToSystem(string dir)
    {
        var info = new DirectoryInfo(dir);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(sec);
    }
}
