using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace SAMP.App;

public sealed class BoolToVisibility(bool invert = false) : IValueConverter
{
    public static readonly BoolToVisibility Instance = new();
    public static readonly BoolToVisibility Inverse = new(true);

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        (value is true) != invert ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
