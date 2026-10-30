using CommunityToolkit.Mvvm.ComponentModel;
using SAMP.Client;

namespace SAMP.App.Core;

public abstract partial class ViewModelBase : ObservableObject
{
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string? _infoMessage;
    [ObservableProperty] private bool _isBusy;

    /// <summary>Called when the screen is shown (and again on refresh).</summary>
    public virtual Task LoadAsync() => Task.CompletedTask;

    /// <summary>Reloads data after a successful action without losing the confirmation message it just set.</summary>
    protected async Task ReloadAsync()
    {
        var info = InfoMessage;
        await LoadAsync();
        if (ErrorMessage == null) InfoMessage = info;
    }

    protected void Clear()
    {
        ErrorMessage = null;
        InfoMessage = null;
    }

    /// <summary>Runs <paramref name="action"/> with busy/error handling; returns true when it succeeded.</summary>
    protected async Task<bool> RunAsync<T>(Func<Task<Result<T>>> action, Action<T>? onSuccess = null, string? successMessage = null)
    {
        if (IsBusy) return false;
        IsBusy = true;
        Clear();
        try
        {
            var r = await action();
            if (!r.Ok)
            {
                ErrorMessage = r.Error;
                return false;
            }
            onSuccess?.Invoke(r.Value!);
            if (successMessage != null) InfoMessage = successMessage;
            return true;
        }
        finally
        {
            IsBusy = false;
        }
    }
}
