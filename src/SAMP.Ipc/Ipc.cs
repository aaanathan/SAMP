using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;

namespace SAMP.Ipc;

public sealed record IpcRequest(string Command, string? Token = null, JsonElement? Args = null);

public sealed record IpcResponse(bool Ok, string? Error = null, string? Code = null, JsonElement? Data = null)
{
    public static IpcResponse Success(object? data = null) =>
        new(true, Data: data == null ? null : JsonSerializer.SerializeToElement(data, IpcJson.Options));

    public static IpcResponse Fail(string code, string message) => new(false, message, code);
}

public static class IpcJson
{
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        o.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        return o;
    }
}

public interface IIpcHandler
{
    Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken ct);
}

public enum PipeAccessMode
{
    /// <summary>Any authenticated local user (the UI). Every command except a few public ones still needs a session token.</summary>
    AuthenticatedUsers,
    /// <summary>LocalSystem and Administrators only (monitor service / installer guard).</summary>
    SystemAndAdmins,
}

/// <summary>Newline-delimited JSON over a named pipe: one request line, one response line.</summary>
public sealed class PipeServer(string pipeName, IIpcHandler handler, PipeAccessMode access, TimeSpan? readTimeout = null)
{
    private readonly TimeSpan _readTimeout = readTimeout ?? TimeSpan.FromSeconds(30);
    public const int MaxLineBytes = 256 * 1024;

    public async Task RunAsync(CancellationToken ct)
    {
        var tasks = new List<Task>();
        while (!ct.IsCancellationRequested)
        {
            var server = Create();
            try
            {
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync();
                break;
            }
            tasks.RemoveAll(t => t.IsCompleted);
            tasks.Add(Task.Run(() => ServeAsync(server, ct), CancellationToken.None));
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private NamedPipeServerStream Create()
    {
        if (OperatingSystem.IsWindows()) return CreateWindows();
        return new NamedPipeServerStream(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
    }

    [SupportedOSPlatform("windows")]
    private NamedPipeServerStream CreateWindows()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        if (access == PipeAccessMode.AuthenticatedUsers)
            sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, sec);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var _ = pipe;
        try
        {
            using var reader = new StreamReader(pipe, new System.Text.UTF8Encoding(false), false, 4096, leaveOpen: true);
            await using var writer = new StreamWriter(pipe, new System.Text.UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
            while (!ct.IsCancellationRequested && pipe.IsConnected)
            {
                // A client that connects and goes silent must not hold a server instance forever.
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCts.CancelAfter(_readTimeout);
                var line = await reader.ReadLineAsync(readCts.Token).ConfigureAwait(false);
                if (line == null) break;

                IpcResponse response;
                if (line.Length > MaxLineBytes)
                {
                    response = IpcResponse.Fail("too_large", "Request too large.");
                }
                else
                {
                    try
                    {
                        var req = JsonSerializer.Deserialize<IpcRequest>(line, IpcJson.Options);
                        response = req == null || string.IsNullOrWhiteSpace(req.Command)
                            ? IpcResponse.Fail("bad_request", "Malformed request.")
                            : await handler.HandleAsync(req, ct).ConfigureAwait(false);
                    }
                    catch (JsonException)
                    {
                        response = IpcResponse.Fail("bad_request", "Malformed request.");
                    }
                }
                await writer.WriteLineAsync(JsonSerializer.Serialize(response, IpcJson.Options).AsMemory(), ct).ConfigureAwait(false);
            }
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // client went away
        }
    }
}

public sealed class PipeClient(string pipeName, TimeSpan? timeout = null)
{
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(10);

    public async Task<IpcResponse> SendAsync(string command, string? token = null, object? args = null, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(_timeout);
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);

        var req = new IpcRequest(command, token, args == null ? null : JsonSerializer.SerializeToElement(args, IpcJson.Options));
        using var reader = new StreamReader(pipe, new System.Text.UTF8Encoding(false), false, 4096, leaveOpen: true);
        await using var writer = new StreamWriter(pipe, new System.Text.UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync(JsonSerializer.Serialize(req, IpcJson.Options).AsMemory(), cts.Token).ConfigureAwait(false);
        var line = await reader.ReadLineAsync(cts.Token).ConfigureAwait(false)
                   ?? throw new IOException("Service closed the connection.");
        return JsonSerializer.Deserialize<IpcResponse>(line, IpcJson.Options) ?? throw new IOException("Invalid response.");
    }
}

/// <summary>Mutual supervision: restarts the partner Windows service if it is stopped. Windows only.</summary>
[SupportedOSPlatform("windows")]
public static class PartnerSupervisor
{
    /// <returns>true if the partner had to be started.</returns>
    public static bool EnsureRunning(string serviceName)
    {
        using var sc = new ServiceController(serviceName);
        sc.Refresh();
        if (sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending) return false;
        if (sc.Status != ServiceControllerStatus.Stopped) return false;
        sc.Start();
        return true;
    }
}
