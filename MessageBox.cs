using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.VisualTree;

namespace Safeguard;

public enum MessageBoxButton
{
    OK,
    OKCancel,
    YesNo,
    YesNoCancel
}

public enum MessageBoxImage
{
    None,
    Information,
    Warning,
    Error,
    Question,
    Exclamation,
    Stop
}

public enum MessageBoxResult
{
    None,
    OK,
    Cancel,
    Yes,
    No
}

public static class MessageBox
{
    public static MessageBoxResult Show(
        string messageBoxText,
        string caption = "",
        MessageBoxButton button = MessageBoxButton.OK,
        MessageBoxImage icon = MessageBoxImage.None)
    {
        return ShowAsync(messageBoxText, caption, button, icon)
            .GetAwaiter()
            .GetResult();
    }

    private static async Task<MessageBoxResult> ShowAsync(
        string messageBoxText,
        string caption,
        MessageBoxButton button,
        MessageBoxImage icon)
    {
        var dialog = CreateDialog(messageBoxText, caption, button, icon, out var resultSource);
        var lifetime = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
        var owner = lifetime?.MainWindow;

        if (owner != null)
        {
            await dialog.ShowDialog(owner);
        }
        else
        {
            dialog.Show();
        }

        return await resultSource.Task;
    }

    private static Window CreateDialog(
        string messageBoxText,
        string caption,
        MessageBoxButton button,
        MessageBoxImage icon,
        out TaskCompletionSource<MessageBoxResult> resultSource)
    {
        resultSource = new TaskCompletionSource<MessageBoxResult>();
        var dialog = new Window
        {
            Title = string.IsNullOrWhiteSpace(caption) ? "Message" : caption,
            SizeToContent = SizeToContent.WidthAndHeight,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Content = BuildContent(messageBoxText, icon, button, resultSource)
        };

        var completionSource = resultSource;

        dialog.Closed += (_, _) =>
        {
            if (!completionSource.Task.IsCompleted)
            {
                completionSource.TrySetResult(MessageBoxResult.None);
            }
        };

        return dialog;
    }

    private static Control BuildContent(
        string messageBoxText,
        MessageBoxImage icon,
        MessageBoxButton button,
        TaskCompletionSource<MessageBoxResult> resultSource)
    {
        var iconBlock = new TextBlock
        {
            Text = GetIconGlyph(icon),
            FontSize = 24,
            VerticalAlignment = VerticalAlignment.Top,
            Foreground = new SolidColorBrush(Color.Parse("#2563EB")),
            Margin = new Thickness(0, 4, 12, 0)
        };

        var messageBlock = new TextBlock
        {
            Text = messageBoxText,
            TextWrapping = TextWrapping.Wrap,
            MaxWidth = 480
        };

        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Margin = new Thickness(0, 16, 0, 0)
        };

        foreach (var actionButton in CreateButtons(button, resultSource))
        {
            buttonPanel.Children.Add(actionButton);
        }

        return new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 12,
            Margin = new Thickness(20),
            Children =
            {
                iconBlock,
                new StackPanel
                {
                    Orientation = Orientation.Vertical,
                    Spacing = 8,
                    Children =
                    {
                        messageBlock,
                        buttonPanel
                    }
                }
            }
        };
    }

    private static IEnumerable<Button> CreateButtons(
        MessageBoxButton button,
        TaskCompletionSource<MessageBoxResult> resultSource)
    {
        return button switch
        {
            MessageBoxButton.OKCancel => new[]
            {
                CreateButton("OK", MessageBoxResult.OK, resultSource),
                CreateButton("Cancel", MessageBoxResult.Cancel, resultSource)
            },
            MessageBoxButton.YesNo => new[]
            {
                CreateButton("Yes", MessageBoxResult.Yes, resultSource),
                CreateButton("No", MessageBoxResult.No, resultSource)
            },
            MessageBoxButton.YesNoCancel => new[]
            {
                CreateButton("Yes", MessageBoxResult.Yes, resultSource),
                CreateButton("No", MessageBoxResult.No, resultSource),
                CreateButton("Cancel", MessageBoxResult.Cancel, resultSource)
            },
            _ => new[]
            {
                CreateButton("OK", MessageBoxResult.OK, resultSource)
            }
        };
    }

    private static Button CreateButton(
        string text,
        MessageBoxResult result,
        TaskCompletionSource<MessageBoxResult> resultSource)
    {
        var button = new Button
        {
            Content = text,
            MinWidth = 80
        };

        button.Click += (_, _) =>
        {
            resultSource.TrySetResult(result);
            var window = button.GetVisualRoot() as Window;
            window?.Close();
        };

        return button;
    }

    private static string GetIconGlyph(MessageBoxImage icon) => icon switch
    {
        MessageBoxImage.Information => "ℹ️",
        MessageBoxImage.Warning => "⚠️",
        MessageBoxImage.Error => "❌",
        MessageBoxImage.Question => "❓",
        MessageBoxImage.Exclamation => "❗",
        MessageBoxImage.Stop => "⛔",
        _ => string.Empty
    };
}
