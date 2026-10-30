using System.Windows;
using Microsoft.Win32;
using SAMP.App.Core;
using SAMP.Client;
using SAMP.Core;

namespace SAMP.App;

public partial class App : Application
{
    private Mutex? _single;
    private TrayController? _tray;
    private MainWindow? _window;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // One UI per Windows session; a second launch just brings the first to the front.
        _single = new Mutex(true, @"Local\SAMP.App", out var created);
        if (!created)
        {
            Shutdown();
            return;
        }

        var shell = new ShellViewModel(new PipeSampService(), new SystemClock())
        {
            UiInvoke = a => Dispatcher.BeginInvoke(a),
        };
        _window = new MainWindow(shell);
        _tray = new TrayController(shell, ShowWindow, ExitApp);

        // Any user input counts as activity for the idle sign-out.
        System.Windows.Input.InputManager.Current.PreProcessInput += (_, args) =>
        {
            if (args.StagingItem.Input is System.Windows.Input.InputEventArgs) shell.NotifyActivity();
        };

        // Lock, logoff or fast-user-switch ends the SAMP session immediately.
        SystemEvents.SessionSwitch += (_, args) =>
        {
            if (args.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.SessionLogoff
                or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteDisconnect)
                Dispatcher.BeginInvoke(async () => await shell.OnSessionLockedAsync());
        };
        SessionEnding += async (_, _) => await shell.OnSessionLockedAsync();

        var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += async (_, _) => await shell.TickAsync();
        timer.Start();

        _ = shell.InitializeAsync();
        ShowWindow();
    }

    private void ShowWindow()
    {
        if (_window == null) return;
        _window.Show();
        if (_window.WindowState == WindowState.Minimized) _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    private async void ExitApp()
    {
        // Leaving the app always signs out; enforcement continues in the service.
        if (_window?.DataContext is ShellViewModel s) await s.SignOutAsync("Signed out.");
        _tray?.Dispose();
        _window?.ForceClose();
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _single?.Dispose();
        base.OnExit(e);
    }
}
