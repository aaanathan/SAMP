using SAMP.Core;
using SAMP.Usb;

namespace SAMP.Tests;

public sealed class FakeRegistry : IRegistryAccess
{
    public Dictionary<string, Dictionary<string, object>> Keys { get; } = new(StringComparer.OrdinalIgnoreCase);

    public void SetDword(string key, string name, int value) => Put(key, name, value);
    public void SetString(string key, string name, string value) => Put(key, name, value);
    public int? GetDword(string key, string name) =>
        Keys.TryGetValue(key, out var k) && k.TryGetValue(name, out var v) && v is int i ? i : null;
    public IReadOnlyList<string> GetStringValues(string key) =>
        Keys.TryGetValue(key, out var k) ? k.Values.OfType<string>().ToList() : new List<string>();
    public void DeleteSubKeyTree(string key)
    {
        foreach (var k in Keys.Keys.Where(k => k.Equals(key, StringComparison.OrdinalIgnoreCase) || k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase)).ToList())
            Keys.Remove(k);
    }
    private void Put(string key, string name, object v)
    {
        if (!Keys.TryGetValue(key, out var k)) Keys[key] = k = new(StringComparer.OrdinalIgnoreCase);
        k[name] = v;
    }
}

public sealed class FakeBlocker : IUsbBlocker
{
    public bool Blocked { get; set; } = true;
    public int ApplyCount { get; private set; }
    public bool FailNext { get; set; }
    public bool FailAlways { get; set; }
    public bool FailRead { get; set; }
    public void Apply(bool globalBlocked, IReadOnlyList<BlockRule> rules)
    {
        if (FailAlways) throw new InvalidOperationException("registry unavailable");
        if (FailNext) { FailNext = false; throw new InvalidOperationException("boom"); }
        Blocked = globalBlocked; ApplyCount++;
    }
    public bool IsGloballyBlocked() => FailRead ? throw new UnauthorizedAccessException("denied") : Blocked;
}

public sealed class FakeDevices : IDeviceController
{
    public List<DeviceInfo> Devices { get; } = new();
    public List<(string Id, bool Enabled)> Calls { get; } = new();
    public IReadOnlyList<DeviceInfo> Enumerate() => Devices.ToList();
    public void SetEnabled(string instanceId, bool enabled)
    {
        Calls.Add((instanceId, enabled));
        var i = Devices.FindIndex(d => d.InstanceId == instanceId);
        if (i >= 0) Devices[i] = Devices[i] with { Enabled = enabled };
    }
}

