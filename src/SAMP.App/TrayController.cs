using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using SAMP.App.Core;

namespace SAMP.App;

/// <summary>Tray icon. When signed out it shows only Open / Exit and no details.</summary>
public sealed class TrayController : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly ShellViewModel _shell;
    private readonly ToolStripMenuItem _signOut;

    public TrayController(ShellViewModel shell, Action open, Action exit)
    {
        _shell = shell;
        _signOut = new ToolStripMenuItem("Sign out", null, async (_, _) => await shell.LogoutAsync()) { Visible = false };
        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem("Open SAMP", null, (_, _) => open()));
        menu.Items.Add(_signOut);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Exit", null, (_, _) => exit()));

        _icon = new NotifyIcon { Icon = SystemIcons.Shield, Visible = true, ContextMenuStrip = menu, Text = "SAMP – signed out" };
        _icon.DoubleClick += (_, _) => open();

        shell.PropertyChanged += OnShellChanged;
        shell.Notification += msg => _icon.ShowBalloonTip(5000, "SAMP", msg, ToolTipIcon.Warning);
        // Keep the tooltip fresh while signed in.
        var t = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        t.Tick += (_, _) => Refresh();
        t.Start();
    }

    private void OnShellChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ShellViewModel.State)) Refresh();
    }

    private void Refresh()
    {
        var signedIn = _shell.State == ShellState.Main;
        _signOut.Visible = signedIn;
        if (!signedIn) { _icon.Text = "SAMP – signed out"; return; }
        var d = _shell.Dashboard;
        var text = d == null ? "SAMP" : d.IsBlocked ? "SAMP – USB blocked" : "SAMP – USB unblocked " + d.CountdownText.Replace("Blocks automatically in ", "");
        _icon.Text = text.Length > 63 ? text[..63] : text; // NotifyIcon limit
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
