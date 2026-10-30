using SAMP.Core;

namespace SAMP.Usb;

/// <summary>Admin-only rule management; every change is validated, audited and re-applied to the OS.</summary>
public sealed class BlockRuleService(IBlockRuleStore store, UnblockManager manager, IAuditLog audit, IClock clock)
{
    public IReadOnlyList<BlockRule> List(Role role)
    {
        RequireAdmin(role);
        return store.List();
    }

    public long Add(long userId, Role role, BlockRule rule)
    {
        RequireAdmin(role);
        Validate(rule);
        rule.CreatedBy = userId;
        rule.CreatedAtUtc = clock.UtcNow;
        rule.Value = rule.Value.Trim();
        if (IsDuplicate(rule)) throw new InvalidOperationException("An identical rule already exists.");
        rule.Id = store.Add(rule);
        audit.Append(userId, "rule.add", Describe(rule));
        manager.ReapplyRules();
        return rule.Id;
    }

    public void Update(long userId, Role role, BlockRule rule)
    {
        RequireAdmin(role);
        Validate(rule);
        rule.Value = rule.Value.Trim();
        store.Update(rule);
        audit.Append(userId, "rule.update", Describe(rule));
        manager.ReapplyRules();
    }

    public void Delete(long userId, Role role, long id)
    {
        RequireAdmin(role);
        store.Delete(id);
        audit.Append(userId, "rule.delete", $"id={id}");
        manager.ReapplyRules();
    }

    private bool IsDuplicate(BlockRule r) => store.List().Any(x =>
        x.Action == r.Action && x.MatchType == r.MatchType && x.Scope == r.Scope &&
        string.Equals(x.Value, r.Value, StringComparison.OrdinalIgnoreCase));

    private static void Validate(BlockRule r)
    {
        var err = RuleValidator.Validate(r);
        if (err != null) throw new ArgumentException(err);
    }

    private static string Describe(BlockRule r) => $"{r.Action} {r.MatchType} {r.Value} ({r.Name}) scope={r.Scope} enabled={r.Enabled}";

    private static void RequireAdmin(Role role)
    {
        if (role != Role.Admin) throw new UnauthorizedAccessException("Admin role required.");
    }
}
