using System.Globalization;

namespace SAMP.Core;

public enum RuleAction { Block = 0, Allow = 1 }
public enum BlockMatchType { DeviceClass = 0, VendorId = 1, VendorProduct = 2, Serial = 3 }
public enum RuleScope { Always = 0, OnlyWhenLocked = 1 }

public sealed class BlockRule
{
    public long Id { get; set; }
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public RuleAction Action { get; set; }
    public BlockMatchType MatchType { get; set; }
    /// <summary>DeviceClass: 2-hex USB class code ("08") or class GUID. VendorId: "0951". VendorProduct: "0951:1666". Serial: "0951:1666:SERIAL".</summary>
    public string Value { get; set; } = "";
    public RuleScope Scope { get; set; }
    public string? Note { get; set; }
    public long? CreatedBy { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}

public sealed record DeviceInfo(
    string? InstanceId,
    string? VendorId,
    string? ProductId,
    string? Serial,
    string? ClassCode,
    string? ClassGuid,
    string? Name,
    bool IsMassStorage,
    bool Enabled = true);

public enum DeviceDecision { Allow, Block }

public sealed record DeviceEvaluation(DeviceDecision Decision, long? RuleId, string Reason);

public static class RuleHex
{
    public static string? Norm(string? s, int width)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return s.ToUpperInvariant().PadLeft(width, '0');
    }

    public static bool IsHex(string s, int width) =>
        s.Length == width && s.All(Uri.IsHexDigit);
}

public static class RuleValidator
{
    /// <summary>Returns an error message, or null when the rule is well formed.</summary>
    public static string? Validate(BlockRule r)
    {
        if (string.IsNullOrWhiteSpace(r.Name)) return "Rule name is required.";
        var v = (r.Value ?? "").Trim();
        switch (r.MatchType)
        {
            case BlockMatchType.DeviceClass:
                if (Guid.TryParse(v, out _)) return null;
                return RuleHex.IsHex(RuleHex.Norm(v, 2) ?? "", 2) ? null : "Class must be a 2-digit hex USB class code (e.g. 08) or a GUID.";
            case BlockMatchType.VendorId:
                return RuleHex.IsHex(RuleHex.Norm(v, 4) ?? "", 4) ? null : "Vendor ID must be 4 hex digits.";
            case BlockMatchType.VendorProduct:
            {
                var p = v.Split(':');
                return p.Length == 2 && RuleHex.IsHex(RuleHex.Norm(p[0], 4) ?? "", 4) && RuleHex.IsHex(RuleHex.Norm(p[1], 4) ?? "", 4)
                    ? null : "Use the form VVVV:PPPP (4 hex digits each).";
            }
            case BlockMatchType.Serial:
            {
                var p = v.Split(':', 3);
                return p.Length == 3 && RuleHex.IsHex(RuleHex.Norm(p[0], 4) ?? "", 4) && RuleHex.IsHex(RuleHex.Norm(p[1], 4) ?? "", 4) && p[2].Trim().Length > 0
                    ? null : "Use the form VVVV:PPPP:SERIAL.";
            }
            default:
                return "Unknown match type.";
        }
    }
}

public static class RuleEvaluator
{
    public static int Specificity(BlockMatchType t) => t switch
    {
        BlockMatchType.Serial => 4,
        BlockMatchType.VendorProduct => 3,
        BlockMatchType.VendorId => 2,
        _ => 1,
    };

    public static bool Matches(BlockRule r, DeviceInfo d)
    {
        var v = r.Value.Trim();
        switch (r.MatchType)
        {
            case BlockMatchType.DeviceClass:
                if (Guid.TryParse(v, out var g))
                    return Guid.TryParse(d.ClassGuid, out var dg) && g == dg;
                var c = RuleHex.Norm(d.ClassCode, 2);
                return c != null && c == RuleHex.Norm(v, 2);
            case BlockMatchType.VendorId:
            {
                var dv = RuleHex.Norm(d.VendorId, 4);
                return dv != null && dv == RuleHex.Norm(v, 4);
            }
            case BlockMatchType.VendorProduct:
            {
                var p = v.Split(':');
                if (p.Length != 2) return false;
                return Eq(d.VendorId, p[0]) && Eq(d.ProductId, p[1]);
            }
            case BlockMatchType.Serial:
            {
                var p = v.Split(':', 3);
                if (p.Length != 3 || string.IsNullOrWhiteSpace(d.Serial)) return false;
                return Eq(d.VendorId, p[0]) && Eq(d.ProductId, p[1]) &&
                       string.Equals(d.Serial.Trim(), p[2].Trim(), StringComparison.OrdinalIgnoreCase);
            }
            default:
                return false;
        }

        static bool Eq(string? a, string b)
        {
            var na = RuleHex.Norm(a, 4);
            return na != null && na == RuleHex.Norm(b, 4);
        }
    }

    /// <summary>Most specific matching rule wins; at equal specificity Block beats Allow.
    /// With no match, mass storage follows the global state and everything else is untouched.</summary>
    public static DeviceEvaluation Evaluate(DeviceInfo device, IEnumerable<BlockRule> rules, bool globalBlocked)
    {
        var best = rules
            .Where(r => r.Enabled && (r.Scope == RuleScope.Always || globalBlocked) && Matches(r, device))
            .OrderByDescending(r => Specificity(r.MatchType))
            .ThenBy(r => r.Action == RuleAction.Block ? 0 : 1)
            .FirstOrDefault();

        if (best != null)
            return new DeviceEvaluation(
                best.Action == RuleAction.Block ? DeviceDecision.Block : DeviceDecision.Allow,
                best.Id, $"rule '{best.Name}'");

        if (!device.IsMassStorage)
            return new DeviceEvaluation(DeviceDecision.Allow, null, "not mass storage");

        return globalBlocked
            ? new DeviceEvaluation(DeviceDecision.Block, null, "mass storage blocked globally")
            : new DeviceEvaluation(DeviceDecision.Allow, null, "mass storage unblocked");
    }
}
