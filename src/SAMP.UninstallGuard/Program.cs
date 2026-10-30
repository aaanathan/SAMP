using System.Runtime.InteropServices;
using SAMP.Core;
using SAMP.Ipc;
using SAMP.UninstallGuard;
using SAMP.Usb;

// Usage (called by the Inno Setup script):
//   SAMP.UninstallGuard.exe --begin-maintenance --password-file <file> [--ui <n>]
//   SAMP.UninstallGuard.exe --begin-maintenance --password <pw> [--ui <n>]     (manual use; visible in the process list)
//   SAMP.UninstallGuard.exe --restore-policy
// Exit codes: 0 ok, 1 wrong/missing password, 2 locked, 3 service unreachable, 4 bad arguments.
return await Main2(args);

static async Task<int> Main2(string[] args)
{
    var mode = args.FirstOrDefault();
    if (mode is "--begin-maintenance" or "--verify")
    {
        var passwordFile = ArgValue(args, "--password-file");
        var password = passwordFile != null ? GuardRunner.ReadAndDestroyPasswordFile(passwordFile) : ArgValue(args, "--password");
        var ui = int.TryParse(ArgValue(args, "--ui"), out var u) ? u : 2;
        var (code, message) = await GuardRunner.VerifyAsync(
            password,
            new PipeClient("samp-ui", TimeSpan.FromSeconds(5)),
            StartService());
        if (code != ExitCodes.Ok)
        {
            Console.Error.WriteLine(message);
            if (ui >= 3) ShowMessage(message); // 2 = silent (/qn); 3+ = some UI
        }
        return code;
    }

    if (mode == "--restore-policy")
        return RestorePolicy();

    Console.Error.WriteLine("Usage: SAMP.UninstallGuard --begin-maintenance (--password-file <file> | --password <pw>) [--ui <n>] | --restore-policy");
    return ExitCodes.BadArguments;
}

static Func<bool>? StartService()
{
    if (!OperatingSystem.IsWindows()) return null;
    return WindowsOnly.StartService;
}

static string? ArgValue(string[] args, string name)
{
    var i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

// After an authorised uninstall the machine must not stay locked down: remove our policy and re-enable devices.
static int RestorePolicy()
{
    if (!OperatingSystem.IsWindows()) return 0;
    try { new RegistryUsbBlocker(new WindowsRegistryAccess()).Apply(globalBlocked: false, Array.Empty<BlockRule>()); }
    catch (Exception e) when (e is UnauthorizedAccessException or IOException or InvalidOperationException) { Console.Error.WriteLine("Policy cleanup: " + e.Message); }
    try
    {
        var devices = new WindowsDeviceController();
        foreach (var d in devices.Enumerate().Where(d => !d.Enabled && d.InstanceId != null))
            devices.SetEnabled(d.InstanceId!, true);
    }
    catch (Exception e) when (e is InvalidOperationException or System.Management.ManagementException or ArgumentException or TimeoutException)
    {
        Console.Error.WriteLine("Device re-enable: " + e.Message);
    }
    return 0;
}

static void ShowMessage(string text)
{
    if (!OperatingSystem.IsWindows()) return;
    NativeMethods.MessageBoxW(IntPtr.Zero, text, "SAMP – Uninstall", 0x10 /* MB_ICONERROR */);
}

internal static partial class NativeMethods
{
    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
}
