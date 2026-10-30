using SAMP.Ipc;

namespace SAMP.UninstallGuard;

public static class ExitCodes
{
    public const int Ok = 0;
    public const int WrongPassword = 1;
    public const int Locked = 2;
    public const int ServiceUnreachable = 3;
    public const int BadArguments = 4;
}

/// <summary>
/// Called by the Inno Setup installer/uninstaller before it upgrades or removes SAMP. It asks the SAMP service (which
/// owns the Argon2id hash, the attempt counter and the lockout) to open a maintenance window; the service does so only
/// for the correct uninstall password. Fails closed: an unreachable service blocks the change.
/// </summary>
public static class GuardRunner
{
    /// <summary>
    /// Reads the password from a temporary file written by the installer (keeps it off the command line), then
    /// overwrites and deletes the file. Returns null when the file is missing or empty.
    /// </summary>
    public static string? ReadAndDestroyPasswordFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var text = File.ReadAllText(path).TrimEnd('\r', '\n');
            File.WriteAllBytes(path, new byte[Math.Max(64, new FileInfo(path).Length)]);
            File.Delete(path);
            return text.Length == 0 ? null : text;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static async Task<(int Code, string Message)> VerifyAsync(
        string? password, PipeClient pipe, Func<bool>? tryStartService = null, int retries = 10, TimeSpan? retryDelay = null)
    {
        if (string.IsNullOrEmpty(password))
            return (ExitCodes.WrongPassword, "The uninstall password is required. Run the uninstall again and enter it (msiexec /x ... UNINSTALL_PASSWORD=...).");

        var delay = retryDelay ?? TimeSpan.FromSeconds(2);
        var started = false;
        for (var attempt = 0; attempt <= retries; attempt++)
        {
            try
            {
                var r = await pipe.SendAsync("maintenance.begin", null, new { password });
                if (!r.Ok) return (ExitCodes.ServiceUnreachable, $"The SAMP service refused the request: {r.Error}");

                var status = r.Data!.Value.GetProperty("status").GetString();
                return status switch
                {
                    "Ok" => (ExitCodes.Ok, "Uninstall password accepted."),
                    // Setup never finished, so there is no password to ask for.
                    "NotSet" => (ExitCodes.Ok, "No uninstall password has been set."),
                    "Locked" => (ExitCodes.Locked, "Too many wrong attempts. Uninstall is locked for 15 minutes."),
                    _ => (ExitCodes.WrongPassword, "The uninstall password is incorrect."),
                };
            }
            catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException)
            {
                if (!started && tryStartService != null)
                {
                    started = true;
                    try { tryStartService(); } catch (Exception s) when (s is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                }
                if (attempt < retries) await Task.Delay(delay);
            }
        }
        return (ExitCodes.ServiceUnreachable,
            "The SAMP service is not running, so the uninstall password cannot be checked. Repair the installation (msiexec /fvomus) and try again.");
    }
}
