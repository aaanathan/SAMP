using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SAMP.Monitor;

if (!OperatingSystem.IsWindows())
    throw new PlatformNotSupportedException("SAMP.Monitor requires Windows (WMI).");

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "SAMPMonitor");
builder.Services.AddHostedService<MonitorWorker>();
await builder.Build().RunAsync();
