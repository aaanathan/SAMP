using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using SAMP.Core;

namespace SAMP.Usb;

/// <summary>
/// WMI enumeration + pnputil enable/disable of USB devices. UNVERIFIED: written from documentation and must be
/// validated on real Windows 10/11 hardware in the Phase 0 spike (see IMPLEMENTATION_PLAN.md section 13.6).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsDeviceController : IDeviceController
{
    private const int ConfigDisabledCode = 22;

    public IReadOnlyList<DeviceInfo> Enumerate()
    {
        var list = new List<DeviceInfo>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT PNPDeviceID, Name, ClassGuid, CompatibleID, Service, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB\\\\VID_%'");
        foreach (ManagementBaseObject o in searcher.Get())
        {
            var id = o["PNPDeviceID"] as string;
            if (string.IsNullOrEmpty(id)) continue;
            var d = Parse(id, o["Name"] as string, o["ClassGuid"] as string, o["CompatibleID"] as string[], o["Service"] as string,
                o["ConfigManagerErrorCode"] is uint c && c == ConfigDisabledCode);
            if (d != null) list.Add(d);
        }
        return list;
    }

    public void SetEnabled(string instanceId, bool enabled)
    {
        if (!SafeInstanceId().IsMatch(instanceId)) throw new ArgumentException("Unexpected characters in device instance id.", nameof(instanceId));
        var psi = new ProcessStartInfo("pnputil.exe")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        psi.ArgumentList.Add(enabled ? "/enable-device" : "/disable-device");
        psi.ArgumentList.Add(instanceId);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start pnputil.");
        p.WaitForExit(15_000);
        if (!p.HasExited) { p.Kill(); throw new TimeoutException("pnputil timed out."); }
        // 0 = ok, 3010 = ok but reboot required
        if (p.ExitCode is not (0 or 3010))
            throw new InvalidOperationException($"pnputil exited with {p.ExitCode}: {p.StandardError.ReadToEnd()}{p.StandardOutput.ReadToEnd()}");
    }

    /// <summary>Parses USB\VID_xxxx&amp;PID_yyyy\SERIAL style instance ids.</summary>
    public static DeviceInfo? Parse(string pnpId, string? name, string? classGuid, string[]? compatibleIds, string? service, bool disabled)
    {
        var m = InstanceRegex().Match(pnpId);
        if (!m.Success) return null;
        var serial = m.Groups["ser"].Value;
        // "&" in the serial position means Windows generated the id: the device has no real serial number.
        if (serial.Contains('&')) serial = "";
        var mass = (compatibleIds ?? []).Any(c => c.Equals(DeviceInstallPolicy.MassStorageCompatibleId, StringComparison.OrdinalIgnoreCase))
                   || string.Equals(service, "USBSTOR", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(service, "UASPStor", StringComparison.OrdinalIgnoreCase);
        return new DeviceInfo(pnpId, m.Groups["vid"].Value.ToUpperInvariant(), m.Groups["pid"].Value.ToUpperInvariant(),
            serial.Length == 0 ? null : serial, mass ? "08" : null, classGuid, name, mass, !disabled);
    }

    [GeneratedRegex(@"^USB\\VID_(?<vid>[0-9A-Fa-f]{4})&PID_(?<pid>[0-9A-Fa-f]{4})(?:&MI_[0-9A-Fa-f]{2})?\\(?<ser>.+)$")]
    private static partial Regex InstanceRegex();

    [GeneratedRegex(@"^[A-Za-z0-9_&\\\-\.\{\}#@ ]+$")]
    private static partial Regex SafeInstanceId();
}
