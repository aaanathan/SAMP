using System.Runtime.Versioning;
using SAMP.Ipc;

namespace SAMP.UninstallGuard;

[SupportedOSPlatform("windows")]
internal static class WindowsOnly
{
    public static bool StartService() => PartnerSupervisor.EnsureRunning("SAMPService");
}
