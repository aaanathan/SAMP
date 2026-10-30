using CommunityToolkit.Mvvm.Input;

namespace SAMP.App.Core;

public sealed partial class ServiceUnavailableViewModel(ShellViewModel shell) : ViewModelBase
{
    public string Message => shell.Notice ?? "The SAMP service is not reachable.";

    [RelayCommand]
    private Task RetryAsync() => shell.InitializeAsync();
}
