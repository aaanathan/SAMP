using System.Management;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SAMP.Core;
using SAMP.Ipc;
using SAMP.Usb;

namespace SAMP.Monitor;

/// <summary>
/// Senses USB device arrival/removal (WMI event + 10 s poll as a safety net) and reports it to SAMP.Service, which is
/// the only writer of the tamper-evident log. Reports that cannot be delivered are queued and retried.
/// UNVERIFIED on real hardware: validate in the Phase 0 spike.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class MonitorWorker(ILogger<MonitorWorker> logger) : BackgroundService
{
    private const string ServiceName = "SAMPService";
    private const string Pipe = "samp-monitor";
    private const int MaxQueue = 1000;

    private readonly WindowsDeviceController _devices = new();
    private readonly PipeClient _client = new(Pipe, TimeSpan.FromSeconds(5));
    private readonly Queue<(string Command, object Args)> _outbox = new();
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private Dictionary<string, DeviceInfo> _known = new(StringComparer.OrdinalIgnoreCase);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2 OR EventType = 3"));
        watcher.EventArrived += (_, _) => _wake.Release();
        try { watcher.Start(); }
        catch (ManagementException e) { logger.LogWarning(e, "WMI watcher unavailable; polling only"); }

        Enqueue("monitor.started", new { });
        foreach (var d in SafeEnumerate())
        {
            _known[d.InstanceId!] = d;
            Enqueue("device.present", new { device = ToDto(d), windowsUser = ActiveUser() });
        }
        await FlushAsync(ct);

        var lastSupervise = DateTime.MinValue;
        while (!ct.IsCancellationRequested)
        {
            try { await _wake.WaitAsync(TimeSpan.FromSeconds(10), ct); }
            catch (OperationCanceledException) { break; }
            await Task.Delay(500, CancellationToken.None); // debounce bursts of events
            while (_wake.CurrentCount > 0) _wake.Wait(0);

            Diff();
            await FlushAsync(ct);

            if (DateTime.UtcNow - lastSupervise > TimeSpan.FromSeconds(30))
            {
                lastSupervise = DateTime.UtcNow;
                try { PartnerSupervisor.EnsureRunning(ServiceName); }
                catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
                { logger.LogWarning(e, "Could not supervise {Service}", ServiceName); }
            }
        }

        Enqueue("monitor.stopped", new { });
        await FlushAsync(CancellationToken.None);
    }

    private void Diff()
    {
        var current = SafeEnumerate().ToDictionary(d => d.InstanceId!, StringComparer.OrdinalIgnoreCase);
        var user = ActiveUser();
        foreach (var (id, d) in current.Where(kv => !_known.ContainsKey(kv.Key)))
            Enqueue("device.arrived", new { device = ToDto(d), windowsUser = user });
        foreach (var (id, d) in _known.Where(kv => !current.ContainsKey(kv.Key)))
            Enqueue("device.removed", new { device = ToDto(d), windowsUser = user });
        _known = current;
    }

    private IReadOnlyList<DeviceInfo> SafeEnumerate()
    {
        try { return _devices.Enumerate().Where(d => d.InstanceId != null).ToList(); }
        catch (ManagementException e) { logger.LogError(e, "Device enumeration failed"); return Array.Empty<DeviceInfo>(); }
    }

    private void Enqueue(string command, object args)
    {
        if (_outbox.Count >= MaxQueue) _outbox.Dequeue(); // oldest dropped; the service logs the gap via heartbeats
        _outbox.Enqueue((command, args));
    }

    private async Task FlushAsync(CancellationToken ct)
    {
        while (_outbox.Count > 0)
        {
            var (cmd, args) = _outbox.Peek();
            try
            {
                var r = await _client.SendAsync(cmd, null, args, ct);
                if (!r.Ok) logger.LogWarning("Service rejected {Command}: {Error}", cmd, r.Error);
                _outbox.Dequeue();
            }
            catch (Exception e) when (e is IOException or TimeoutException or OperationCanceledException)
            {
                return; // service not reachable; keep the queue and retry on the next cycle
            }
        }
    }

    private static MonitorDevice ToDto(DeviceInfo d) =>
        new(d.InstanceId, d.VendorId, d.ProductId, d.Serial, d.ClassCode, d.ClassGuid, d.Name, d.IsMassStorage, d.Enabled);

    private static string? ActiveUser()
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT UserName FROM Win32_ComputerSystem");
            foreach (ManagementBaseObject o in s.Get()) return o["UserName"] as string;
        }
        catch (ManagementException) { }
        return null;
    }
}
