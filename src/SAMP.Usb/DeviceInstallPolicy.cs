using SAMP.Core;

namespace SAMP.Usb;

/// <summary>
/// Windows "Device Installation Restrictions" policy compiled from rules plus the global state.
/// Registry layout: Restrictions\&lt;List&gt; = 1 (DWORD) and a subkey Restrictions\&lt;List&gt; with string values "1","2",...
/// </summary>
public sealed record DeviceInstallPolicy(
    IReadOnlyList<string> DenyClasses,
    IReadOnlyList<string> DenyDeviceIds,
    IReadOnlyList<string> DenyInstanceIds,
    IReadOnlyList<string> AllowClasses,
    IReadOnlyList<string> AllowDeviceIds,
    IReadOnlyList<string> AllowInstanceIds,
    bool GlobalBlocked)
{
    public const string MassStorageCompatibleId = @"USB\Class_08";

    public bool HasAllowRules => AllowClasses.Count + AllowDeviceIds.Count + AllowInstanceIds.Count > 0;

    public static DeviceInstallPolicy Compile(IEnumerable<BlockRule> rules, bool globalBlocked)
    {
        var denyClasses = new List<string>();
        var denyIds = new List<string>();
        var denyInst = new List<string>();
        var allowClasses = new List<string>();
        var allowIds = new List<string>();
        var allowInst = new List<string>();

        if (globalBlocked) denyIds.Add(MassStorageCompatibleId);

        foreach (var r in rules.Where(r => r.Enabled && (r.Scope == RuleScope.Always || globalBlocked)))
        {
            var block = r.Action == RuleAction.Block;
            var v = r.Value.Trim();
            switch (r.MatchType)
            {
                case BlockMatchType.DeviceClass when Guid.TryParse(v, out var g):
                    AddUnique(block ? denyClasses : allowClasses, g.ToString("B").ToUpperInvariant());
                    break;
                case BlockMatchType.DeviceClass:
                    AddUnique(block ? denyIds : allowIds, $@"USB\Class_{RuleHex.Norm(v, 2)}");
                    break;
                case BlockMatchType.VendorId:
                    AddUnique(block ? denyIds : allowIds, $@"USB\VID_{RuleHex.Norm(v, 4)}");
                    break;
                case BlockMatchType.VendorProduct:
                {
                    var p = v.Split(':');
                    AddUnique(block ? denyIds : allowIds, $@"USB\VID_{RuleHex.Norm(p[0], 4)}&PID_{RuleHex.Norm(p[1], 4)}");
                    break;
                }
                case BlockMatchType.Serial:
                {
                    var p = v.Split(':', 3);
                    AddUnique(block ? denyInst : allowInst, $@"USB\VID_{RuleHex.Norm(p[0], 4)}&PID_{RuleHex.Norm(p[1], 4)}\{p[2].Trim()}");
                    break;
                }
            }
        }

        return new DeviceInstallPolicy(denyClasses, denyIds, denyInst, allowClasses, allowIds, allowInst, globalBlocked);
    }

    private static void AddUnique(List<string> list, string value)
    {
        if (!list.Contains(value, StringComparer.OrdinalIgnoreCase)) list.Add(value);
    }
}
