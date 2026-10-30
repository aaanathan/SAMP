namespace SAMP.Ipc;

/// <summary>Device description sent by SAMP.Monitor to the service.</summary>
public sealed record MonitorDevice(string? InstanceId, string? VendorId, string? ProductId, string? Serial, string? ClassCode,
    string? ClassGuid, string? Name, bool MassStorage, bool Enabled = true);
