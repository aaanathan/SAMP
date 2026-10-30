using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SAMP.Core;
using SAMP.Ipc;
using SAMP.Logging;
using SAMP.Usb;

namespace SAMP.Service;

/// <summary>Reconciles on start, then ticks the unblock timer every 30 s; also heartbeat and log maintenance.</summary>
public sealed class WatchdogWorker(UnblockManager manager, DeviceLog log, LogMaintenance maintenance, IntegrityMonitor integrity, MaintenanceWindow window, ILogger<WatchdogWorker> logger)
    : BackgroundService
{
    public static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MaintenanceInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan PartnerCheckInterval = TimeSpan.FromSeconds(30);
    private const string PartnerService = "SAMPMonitor";

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        Guard("reconcile", manager.Reconcile);
        Guard("service.start", () => StartupChecks.RecordStart(log));
        Guard("maintenance", maintenance.Run);
        Guard("integrity", integrity.Check);

        var lastHeartbeat = DateTime.UtcNow;
        var lastMaintenance = DateTime.UtcNow;
        var lastPartner = DateTime.MinValue;

        using var timer = new PeriodicTimer(TickInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(ct))
            {
                Guard("tick", manager.Tick);
                Guard("maintenance-window", window.Tick);
                var now = DateTime.UtcNow;
                if (now - lastHeartbeat >= HeartbeatInterval) { Guard("heartbeat", log.Heartbeat); lastHeartbeat = now; }
                if (now - lastMaintenance >= MaintenanceInterval) { Guard("maintenance", maintenance.Run); Guard("integrity", integrity.Check); lastMaintenance = now; }
                if (OperatingSystem.IsWindows() && now - lastPartner >= PartnerCheckInterval) { Guard("supervise", SuperviseMonitor); lastPartner = now; }
            }
        }
        catch (OperationCanceledException) { /* shutting down */ }

        Guard("service.stop", () => log.Append("service.stop"));
    }

    [SupportedOSPlatform("windows")]
    private void SuperviseMonitor()
    {
        if (PartnerSupervisor.EnsureRunning(PartnerService))
            log.Append("supervisor.restarted_partner", new { service = PartnerService });
    }

    private void Guard(string what, Action a)
    {
        try { a(); }
        catch (Exception e)
        {
            // Never let one failure stop the watchdog. If the OS policy could not be applied the state stays
            // "blocked" (fail-secure) and the next tick retries.
            logger.LogError(e, "Watchdog step '{Step}' failed", what);
            try { log.Append("service.error", new { step = what, error = e.GetType().Name, message = e.Message }); } catch { /* ignore */ }
        }
    }
}

public sealed class PipeWorker(ServiceApi ui, MonitorApi monitor) : BackgroundService
{
    public const string UiPipe = "samp-ui";
    public const string MonitorPipe = "samp-monitor";

    protected override Task ExecuteAsync(CancellationToken ct) => Task.WhenAll(
        new PipeServer(UiPipe, ui, PipeAccessMode.AuthenticatedUsers).RunAsync(ct),
        new PipeServer(MonitorPipe, monitor, PipeAccessMode.SystemAndAdmins).RunAsync(ct));
}
