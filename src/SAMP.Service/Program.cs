using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SAMP.Core;
using SAMP.Data;
using SAMP.Logging;
using SAMP.Security;
using SAMP.Service;
using SAMP.Usb;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "SAMPService");

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("SAMP.Service protects its keys with DPAPI and must run on Windows.");

var paths = new DataPaths();
paths.Prepare();
IKeyProtector protector = new DpapiKeyProtector();
var dbKey = DatabaseKeyStore.LoadOrCreate(paths.DatabaseKey, protector);
var logKey = DatabaseKeyStore.LoadOrCreate(paths.LogKey, protector);

var clock = new SystemClock();
var db = new SqlCipherDatabase(paths.Database, dbKey);
var deviceLog = new DeviceLog(paths.LogDir, logKey, clock,
    [new FileAnchorSink(paths.AnchorFile), new FileAnchorSink(paths.AnchorMirrorFile), new EventLogAnchorSink()]);
var settings = new SqliteSettingsStore(db);
IAuditLog audit = new MirroringAuditLog(new SqliteAuditLog(db, clock), deviceLog);
var hasher = new PasswordHasher();
var policy = new PasswordPolicy();
var userStore = new SqliteUserStore(db);
IDeviceController devices = new WindowsDeviceController();

var sessions = new SessionManager(clock);
var users = new UserService(userStore, audit, hasher, policy, clock);
var uninstall = new UninstallPasswordService(settings, audit, hasher, policy, clock);
var unblock = new UnblockManager(new SqliteUnblockSessionStore(db), new SqliteBlockRuleStore(db),
    new RegistryUsbBlocker(new WindowsRegistryAccess()), devices, settings, audit, clock);
var ruleService = new BlockRuleService(new SqliteBlockRuleStore(db), unblock, audit, clock);
var maintenance = new LogMaintenance(deviceLog, settings);
var recovery = new RecoveryKeyService(settings, users, audit, hasher, clock);
var throttle = new LoginThrottle(clock);
var integrity = new IntegrityMonitor(deviceLog, audit, settings);

// Restrict who can stop/reconfigure the services (SYSTEM full control, Administrators read-only). The restriction is
// lifted only inside a password-gated maintenance window (see MaintenanceWindow) and re-applied at every start.
void ApplyServiceSecurity(bool restricted)
{
    foreach (var svcName in new[] { "SAMPService", "SAMPMonitor" })
    {
        try { ServiceSecurity.Apply(svcName, restricted); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            deviceLog.Append("service.hardening_failed", new { service = svcName, restricted, error = e.Message });
        }
    }
}
ApplyServiceSecurity(true);
var maintenanceWindow = new MaintenanceWindow(clock, ApplyServiceSecurity);
builder.Services.AddSingleton(maintenanceWindow);

builder.Services.AddSingleton(deviceLog);
builder.Services.AddSingleton(unblock);
builder.Services.AddSingleton(maintenance);
builder.Services.AddSingleton(new ServiceApi(users, userStore, sessions, unblock, ruleService, uninstall, audit, deviceLog, settings, maintenance, recovery, throttle, integrity, maintenanceWindow));
builder.Services.AddSingleton(integrity);
builder.Services.AddSingleton(new MonitorApi(unblock, devices, deviceLog));
builder.Services.AddHostedService<WatchdogWorker>();
builder.Services.AddHostedService<PipeWorker>();

await builder.Build().RunAsync();
