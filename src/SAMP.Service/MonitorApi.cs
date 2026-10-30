using SAMP.Core;
using SAMP.Ipc;
using SAMP.Logging;
using SAMP.Usb;

namespace SAMP.Service;

/// <summary>
/// Receives device events from SAMP.Monitor over the SYSTEM/Admin-only pipe. The service is the single writer of the
/// device log, so the monitor only senses devices; this class logs them and enforces the rules on hot-plug.
/// </summary>
public sealed class MonitorApi(UnblockManager manager, IDeviceController devices, DeviceLog log) : IIpcHandler
{
    public Task<IpcResponse> HandleAsync(IpcRequest req, CancellationToken ct)
    {
        try
        {
            var a = new Args(req.Args);
            switch (req.Command)
            {
                case "device.arrived":
                    return Task.FromResult(IpcResponse.Success(Arrived(a.Device(), a.OptStr("windowsUser"))));
                case "device.removed":
                {
                    var d = a.Device();
                    log.Append("device.removed", new { instanceId = d.InstanceId, vendorId = d.VendorId, productId = d.ProductId, serial = d.Serial, name = d.Name, windowsUser = a.OptStr("windowsUser") });
                    return Task.FromResult(IpcResponse.Success());
                }
                case "device.present":
                {
                    // Snapshot at monitor start-up: devices already attached are logged, and enforced.
                    var d = a.Device();
                    return Task.FromResult(IpcResponse.Success(Arrived(d, a.OptStr("windowsUser"), "device.present")));
                }
                case "monitor.started":
                case "monitor.stopped":
                    log.Append(req.Command);
                    return Task.FromResult(IpcResponse.Success());
                default:
                    return Task.FromResult(IpcResponse.Fail("invalid", $"Unknown command '{req.Command}'."));
            }
        }
        catch (Exception e) when (e is ArgumentException or System.Text.Json.JsonException)
        {
            return Task.FromResult(IpcResponse.Fail("invalid", e.Message));
        }
    }

    private object Arrived(MonitorDevice d, string? windowsUser, string eventType = "device.connected")
    {
        var info = d.ToInfo();
        var eval = manager.EvaluateDevice(info);
        var st = manager.GetStatus();
        string? actionError = null;

        if (d.InstanceId != null)
        {
            var wantEnabled = eval.Decision == DeviceDecision.Allow;
            if (wantEnabled != d.Enabled)
            {
                try { devices.SetEnabled(d.InstanceId, wantEnabled); }
                catch (Exception e) when (e is InvalidOperationException or ArgumentException or TimeoutException)
                {
                    actionError = e.Message;
                }
            }
        }

        log.Append(eventType, new
        {
            instanceId = d.InstanceId, vendorId = d.VendorId, productId = d.ProductId, serial = d.Serial,
            classCode = d.ClassCode, name = d.Name, massStorage = d.MassStorage,
            decision = eval.Decision.ToString(), ruleId = eval.RuleId, reason = eval.Reason,
            globalBlocked = st.IsBlocked, insideUnblockSession = !st.IsBlocked, sampUserId = st.UserId,
            windowsUser, enforcementError = actionError,
        });
        return new { decision = eval.Decision.ToString(), reason = eval.Reason };
    }
}

public static class MonitorArgs
{
    public static DeviceInfo ToInfo(this MonitorDevice d) =>
        new(d.InstanceId, d.VendorId, d.ProductId, d.Serial, d.ClassCode, d.ClassGuid, d.Name, d.MassStorage, d.Enabled);

    public static MonitorDevice Device(this Args a) => a.Obj<MonitorDevice>("device");
}
