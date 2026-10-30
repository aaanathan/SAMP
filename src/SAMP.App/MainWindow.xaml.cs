using System.ComponentModel;
using System.Windows;
using SAMP.App.Core;

namespace SAMP.App;

public partial class MainWindow : Window
{
    private bool _forceClose;

    public MainWindow(ShellViewModel shell)
    {
        InitializeComponent();
        DataContext = shell;
    }

    public void ForceClose()
    {
        _forceClose = true;
        Close();
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (_forceClose) { base.OnClosing(e); return; }
        // The X button hides to the tray and signs out, so an unattended window never stays logged in.
        e.Cancel = true;
        Hide();
        if (DataContext is ShellViewModel s) await s.SignOutAsync("Signed out.");
    }
}
