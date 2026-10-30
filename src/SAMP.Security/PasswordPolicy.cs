namespace SAMP.Security;

public sealed record PasswordPolicyOptions(int MinLength = 12, int MinCharacterClasses = 3, int HistoryCount = 5);

public sealed class PasswordPolicy
{
    public PasswordPolicyOptions Options { get; }

    public PasswordPolicy(PasswordPolicyOptions? options = null) => Options = options ?? new PasswordPolicyOptions();

    /// <summary>Returns a list of violations; empty means the password is acceptable.</summary>
    public IReadOnlyList<string> Validate(string password, string? username = null)
    {
        var errors = new List<string>();
        if (password.Length < Options.MinLength)
            errors.Add($"Password must be at least {Options.MinLength} characters.");

        var classes = 0;
        if (password.Any(char.IsLower)) classes++;
        if (password.Any(char.IsUpper)) classes++;
        if (password.Any(char.IsDigit)) classes++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) classes++;
        if (classes < Options.MinCharacterClasses)
            errors.Add($"Password must contain at least {Options.MinCharacterClasses} of: lowercase, uppercase, digit, symbol.");

        if (!string.IsNullOrWhiteSpace(username) &&
            password.Contains(username, StringComparison.OrdinalIgnoreCase))
            errors.Add("Password must not contain the username.");

        return errors;
    }
}

public sealed class PasswordPolicyException(IReadOnlyList<string> violations)
    : Exception(string.Join(" ", violations))
{
    public IReadOnlyList<string> Violations { get; } = violations;
}
