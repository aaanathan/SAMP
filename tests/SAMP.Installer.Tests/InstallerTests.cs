using System.Text.RegularExpressions;

namespace SAMP.Tests;

/// <summary>
/// Static checks of installer/SAMP.iss. Inno Setup is Windows-only, so the script itself is never compiled or run in
/// this test suite; these tests only keep it consistent with the rest of the code base.
/// </summary>
public class InnoScriptTests
{
    private static string Read(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, name));
    private readonly string _iss = Read("SAMP.iss");

    [Fact]
    public void App_id_matches_the_uninstall_registry_key_used_to_find_an_existing_install()
    {
        var id = Regex.Match(_iss, @"AppId=\{\{([0-9A-F-]{36})\}").Groups[1].Value;
        Assert.NotEmpty(id);
        Assert.Contains($@"Uninstall\{{{id}}}_is1", _iss);
    }

    [Fact]
    public void Installer_runs_elevated_for_64_bit_windows_10_or_newer()
    {
        Assert.Contains("PrivilegesRequired=admin", _iss);
        Assert.Contains("ArchitecturesInstallIn64BitMode=x64compatible", _iss);
        Assert.Contains("MinVersion=10.0", _iss);
    }

    [Fact]
    public void Service_names_match_the_hosts_and_the_partner_supervisors()
    {
        Assert.Contains("MainService = 'SAMPService'", _iss);
        Assert.Contains("MonitorService = 'SAMPMonitor'", _iss);
        Assert.Contains("\"SAMPService\"", Read("ServiceProgram.cs.txt"));
        Assert.Contains("\"SAMPMonitor\"", Read("MonitorProgram.cs.txt"));
        Assert.Contains("SAMP.Service.exe", _iss);
        Assert.Contains("SAMP.Monitor.exe", _iss);
    }

    [Fact]
    public void Services_are_localsystem_auto_start_and_restart_on_every_failure()
    {
        Assert.Contains("obj= LocalSystem", _iss);
        Assert.Contains("start= auto", _iss);
        Assert.Matches(@"failure ' \+ Name \+ ' reset= 86400 actions= restart/5000/restart/5000/restart/5000", _iss);
    }

    [Fact]
    public void The_password_never_travels_on_a_command_line_only_in_a_temporary_file()
    {
        Assert.DoesNotContain("--password ", _iss);
        Assert.Contains("--password-file", _iss);
        Assert.Contains("SaveStringsToUTF8File", _iss);
        Assert.Matches(@"DeleteFile\(PwFile\)", _iss);
    }

    [Fact]
    public void Every_guard_option_the_script_uses_is_implemented_by_the_guard()
    {
        var guard = Read("GuardProgram.cs.txt");
        foreach (var flag in Regex.Matches(_iss, @"'(--[a-z-]+)").Select(m => m.Groups[1].Value).Concat(
                     Regex.Matches(_iss, @"""(--[a-z-]+)").Select(m => m.Groups[1].Value)).Distinct())
            Assert.Contains($"\"{flag}\"", guard);
        foreach (var flag in new[] { "--begin-maintenance", "--password-file", "--restore-policy" })
            Assert.Contains(flag, _iss);
    }

    [Fact]
    public void Exit_code_constants_match_the_guard()
    {
        Assert.Contains("GuardOk = 0;", _iss);
        Assert.Contains("GuardWrong = 1;", _iss);
        Assert.Contains("GuardLocked = 2;", _iss);
        Assert.Contains("GuardUnreachable = 3;", _iss);
    }

    [Fact]
    public void Uninstall_is_aborted_unless_the_service_accepted_the_password_and_policy_is_restored_after_services_stop()
    {
        var init = Section("function InitializeUninstall");
        Assert.Contains("BeginMaintenance(", init);
        Assert.Contains("Result := MaintenanceOpen;", init);
        Assert.Contains("Exit;", init);   // cancelled prompt aborts

        var step = Section("procedure CurUninstallStepChanged");
        Assert.True(step.IndexOf("StopAndRemoveServices", StringComparison.Ordinal) < step.IndexOf("--restore-policy", StringComparison.Ordinal));
        Assert.Contains("usUninstall", step);
    }

    [Fact]
    public void Upgrades_and_reinstalls_of_an_existing_protected_install_require_the_password_too()
    {
        Assert.Contains("PasswordPage", _iss);
        Assert.Matches(@"ShouldSkipPage[\s\S]*ExistingAppDir = ''", _iss);
        var prepare = Section("function PrepareToInstall");
        Assert.Contains("if not MaintenanceOpen", prepare);
        Assert.True(prepare.IndexOf("MaintenanceOpen", StringComparison.Ordinal) < prepare.IndexOf("StopAndRemoveServices", StringComparison.Ordinal));
    }

    [Fact]
    public void Silent_runs_can_supply_the_password_by_file_or_parameter()
    {
        Assert.Contains("UNINSTPASSWORDFILE", _iss);
        Assert.Contains("UNINSTPASSWORD", _iss);
        Assert.Contains("WizardSilent", _iss);
        Assert.Contains("UninstallSilent", _iss);
    }

    [Fact]
    public void Services_are_disabled_before_they_are_stopped_so_they_cannot_revive_each_other()
    {
        var body = Section("procedure StopAndRemoveServices");
        var disable = body.IndexOf("start= disabled", StringComparison.Ordinal);
        var stop = body.IndexOf("'stop '", StringComparison.Ordinal);
        var delete = body.IndexOf("'delete '", StringComparison.Ordinal);
        Assert.InRange(disable, 0, stop - 1);
        Assert.InRange(stop, disable + 1, delete - 1);
    }

    /// <summary>Text from the given routine header to the next top-level routine.</summary>
    private string Section(string header)
    {
        var start = _iss.IndexOf(header, StringComparison.Ordinal);
        Assert.True(start >= 0, header);
        var next = Regex.Match(_iss[(start + header.Length)..], @"\n(function|procedure) ");
        return next.Success ? _iss.Substring(start, header.Length + next.Index) : _iss[start..];
    }
}
