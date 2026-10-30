using System.Runtime.Versioning;
using Microsoft.Win32;
using SAMP.Core;

namespace SAMP.Usb;

public interface IRegistryAccess
{
    void SetDword(string key, string name, int value);
    void SetString(string key, string name, string value);
    int? GetDword(string key, string name);
    IReadOnlyList<string> GetStringValues(string key);
    void DeleteSubKeyTree(string key);
}

/// <summary>HKEY_LOCAL_MACHINE access. Requires the process to run as SYSTEM/administrator.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryAccess : IRegistryAccess
{
    public void SetDword(string key, string name, int value)
    {
        using var k = Registry.LocalMachine.CreateSubKey(key, writable: true);
        k.SetValue(name, value, RegistryValueKind.DWord);
    }

    public void SetString(string key, string name, string value)
    {
        using var k = Registry.LocalMachine.CreateSubKey(key, writable: true);
        k.SetValue(name, value, RegistryValueKind.String);
    }

    public int? GetDword(string key, string name)
    {
        using var k = Registry.LocalMachine.OpenSubKey(key);
        return k?.GetValue(name) is int i ? i : null;
    }

    public IReadOnlyList<string> GetStringValues(string key)
    {
        using var k = Registry.LocalMachine.OpenSubKey(key);
        if (k == null) return Array.Empty<string>();
        return k.GetValueNames().Select(n => k.GetValue(n) as string).Where(s => s != null).Select(s => s!).ToList();
    }

    public void DeleteSubKeyTree(string key) => Registry.LocalMachine.DeleteSubKeyTree(key, throwOnMissingSubKey: false);
}

/// <summary>
/// Default blocker: writes Device Installation Restrictions, the Removable Storage deny policy and USBSTOR\Start.
/// The whole policy subtree is rewritten on every Apply, so it is idempotent and self-healing.
/// </summary>
public sealed class RegistryUsbBlocker(IRegistryAccess reg) : IUsbBlocker
{
    public const string RestrictionsKey = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
    public const string RemovableStorageKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    public const string UsbStorKey = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    public const string DenyDeviceIdsList = "DenyDeviceIDs";

    public void Apply(bool globalBlocked, IReadOnlyList<BlockRule> rules)
    {
        var p = DeviceInstallPolicy.Compile(rules, globalBlocked);

        reg.DeleteSubKeyTree(RestrictionsKey);
        WriteList("DenyDeviceClasses", p.DenyClasses, retroactive: true);
        WriteList(DenyDeviceIdsList, p.DenyDeviceIds, retroactive: true);
        WriteList("DenyInstanceIDs", p.DenyInstanceIds, retroactive: true);
        WriteList("AllowDeviceClasses", p.AllowClasses, retroactive: false);
        WriteList("AllowDeviceIDs", p.AllowDeviceIds, retroactive: false);
        WriteList("AllowInstanceIDs", p.AllowInstanceIds, retroactive: false);
        if (p.HasAllowRules) reg.SetDword(RestrictionsKey, "AllowDenyLayered", 1);

        // Class-wide switches only when no explicit Allow exceptions exist, otherwise they would defeat them.
        var classWide = globalBlocked && !p.HasAllowRules;
        reg.DeleteSubKeyTree(RemovableStorageKey);
        if (classWide)
        {
            reg.SetDword(RemovableStorageKey, "Deny_Read", 1);
            reg.SetDword(RemovableStorageKey, "Deny_Write", 1);
        }
        reg.SetDword(UsbStorKey, "Start", classWide ? 4 : 3);
    }

    public bool IsGloballyBlocked() =>
        reg.GetStringValues($@"{RestrictionsKey}\{DenyDeviceIdsList}")
            .Contains(DeviceInstallPolicy.MassStorageCompatibleId, StringComparer.OrdinalIgnoreCase);

    private void WriteList(string name, IReadOnlyList<string> values, bool retroactive)
    {
        if (values.Count == 0) return;
        reg.SetDword(RestrictionsKey, name, 1);
        if (retroactive) reg.SetDword(RestrictionsKey, name + "Retroactive", 1);
        for (var i = 0; i < values.Count; i++)
            reg.SetString($@"{RestrictionsKey}\{name}", (i + 1).ToString(), values[i]);
    }
}

/// <summary>No-op controller for hosts where PnP control is not available; the Windows implementation is added after the Phase 0 spike.</summary>
public sealed class NullDeviceController : IDeviceController
{
    public IReadOnlyList<DeviceInfo> Enumerate() => Array.Empty<DeviceInfo>();
    public void SetEnabled(string instanceId, bool enabled) { }
}
