using System.Diagnostics;
using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Win32;
using NetworkWatch.Core;
using NetworkWatch.Core.Api;

namespace NetworkWatch.Tray;

/// <summary>
/// The tray icon: reflects service state (gray = service unreachable, blue = learning, green = quiet,
/// yellow = medium alerts to review, red = high alert), shows toasts for High alerts with
/// Block / Trust / Details actions, and opens the dashboard.
/// </summary>
internal sealed class TrayApp : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _statusItem;
    private readonly ToolStripMenuItem _pauseItem;
    private readonly System.Windows.Forms.Timer _statusTimer;
    private readonly SynchronizationContext _ui;
    private readonly CancellationTokenSource _cts = new();
    private DashboardForm? _dashboard;
    private DateTimeOffset _pausedUntil = DateTimeOffset.MinValue;

    public TrayApp()
    {
        _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

        _statusItem = new ToolStripMenuItem("Connecting to service…") { Enabled = false };
        _pauseItem = new ToolStripMenuItem("Pause notifications for 1 hour", null, (_, _) => TogglePause());
        var menu = new ContextMenuStrip();
        menu.Items.Add(_statusItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Open Network Watch", null, (_, _) => ShowDashboard());
        menu.Items.Add("Acknowledge all alerts", null, async (_, _) => await RunAsync(c => c.CallRawAsync(new ApiRequest { Cmd = ApiCommands.AckAll })));
        menu.Items.Add(_pauseItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit tray icon (monitoring continues)", null, (_, _) => ExitThread());

        _icon = new NotifyIcon
        {
            Icon = Icons.For(TrayState.Disconnected),
            Text = "Network Watch",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => ShowDashboard();

        ToastNotificationManagerCompat.OnActivated += e => _ui.Post(_ => OnToastActivated(e.Argument), null);

        _statusTimer = new System.Windows.Forms.Timer { Interval = 10_000 };
        _statusTimer.Tick += async (_, _) => await RefreshStatusAsync();
        _statusTimer.Start();
        _ = RefreshStatusAsync();
        _ = Task.Run(() => SubscribeLoopAsync(_cts.Token));
        EnsureAutostart();
    }

    private async Task SubscribeLoopAsync(CancellationToken ct)
    {
        var delay = TimeSpan.FromSeconds(2);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await foreach (var alert in NetworkWatchClient.SubscribeAsync(TimeSpan.FromSeconds(5), ct))
                {
                    delay = TimeSpan.FromSeconds(2);
                    _ui.Post(_ => OnAlert(alert), null);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception)
            {
                // service not running / restarting: retry with backoff
            }
            await Task.Delay(delay, ct).ConfigureAwait(false);
            delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 30));
        }
    }

    private void OnAlert(Alert alert)
    {
        _ = RefreshStatusAsync();
        _dashboard?.OnNewAlert();
        if (alert.Severity != Severity.High || DateTimeOffset.Now < _pausedUntil) return;

        var builder = new ToastContentBuilder()
            .AddArgument("alert", alert.Id)
            .AddText(alert.Title)
            .AddText(alert.WhatHappened.Length > 180 ? alert.WhatHappened[..180] + "…" : alert.WhatHappened)
            .AddAttributionText("Network Watch")
            .AddButton(new ToastButton().SetContent("Details").AddArgument("action", "details").AddArgument("alert", alert.Id));
        if (alert.ProcessPath is not null)
            builder.AddButton(new ToastButton().SetContent("Block").AddArgument("action", "block").AddArgument("alert", alert.Id));
        if (alert.ProcessName is not null && alert.DetectorId != "threat-intel")
            builder.AddButton(new ToastButton().SetContent("Trust").AddArgument("action", "trust").AddArgument("alert", alert.Id));
        builder.Show();
    }

    private async void OnToastActivated(string argument)
    {
        var args = ToastArguments.Parse(argument);
        if (!args.TryGetValue("alert", out string? alertText) || !long.TryParse(alertText, out var alertId)) return;
        args.TryGetValue("action", out string? action);
        switch (action)
        {
            case "block":
                await RunAsync(c => c.CallRawAsync(new ApiRequest { Cmd = ApiCommands.Block, AlertId = alertId }), "Blocked. You can undo this in Network Watch → Alerts.");
                break;
            case "trust":
                await RunAsync(c => c.CallRawAsync(new ApiRequest { Cmd = ApiCommands.Trust, AlertId = alertId }), "Trusted. This program won't raise behavior alerts again.");
                break;
            default:
                ShowDashboard(alertId);
                break;
        }
        _ = RefreshStatusAsync();
    }

    private async Task RefreshStatusAsync()
    {
        try
        {
            await using var client = await NetworkWatchClient.ConnectAsync(TimeSpan.FromSeconds(2));
            var status = await client.CallAsync<StatusDto>(new ApiRequest { Cmd = ApiCommands.Status });
            if (status is null) return;
            var state = status.UnacknowledgedHigh > 0 ? TrayState.Alert
                : status.UnacknowledgedMedium > 0 ? TrayState.Review
                : status.IsLearning ? TrayState.Learning
                : TrayState.Quiet;
            var summary = state switch
            {
                TrayState.Alert => $"{status.UnacknowledgedHigh} alert(s) need attention",
                TrayState.Review => $"{status.UnacknowledgedMedium} item(s) to review",
                TrayState.Learning => $"Learning until {status.LearningEndsAt:ddd HH:mm}",
                _ => "All quiet",
            };
            SetState(state, $"Network Watch: {summary}", $"{summary} · {status.AppsKnown} apps · {status.ThreatIndicators:N0} threat indicators");
            _dashboard?.OnStatus(status);
        }
        catch (Exception)
        {
            SetState(TrayState.Disconnected, "Network Watch: service not running", "Service not running — monitoring is OFF");
        }
    }

    private void SetState(TrayState state, string tooltip, string menuText)
    {
        _icon.Icon = Icons.For(state);
        _icon.Text = tooltip.Length > 127 ? tooltip[..127] : tooltip;
        _statusItem.Text = menuText;
    }

    private void TogglePause()
    {
        if (DateTimeOffset.Now < _pausedUntil)
        {
            _pausedUntil = DateTimeOffset.MinValue;
            _pauseItem.Text = "Pause notifications for 1 hour";
        }
        else
        {
            _pausedUntil = DateTimeOffset.Now.AddHours(1);
            _pauseItem.Text = $"Resume notifications (paused until {_pausedUntil:HH:mm})";
        }
    }

    private void ShowDashboard(long? alertId = null)
    {
        if (_dashboard is null || _dashboard.IsDisposed)
        {
            _dashboard = new DashboardForm(RunAsync);
            _dashboard.FormClosed += (_, _) => _dashboard = null;
        }
        _dashboard.Show();
        if (_dashboard.WindowState == FormWindowState.Minimized) _dashboard.WindowState = FormWindowState.Normal;
        _dashboard.Activate();
        _dashboard.ShowAlert(alertId);
    }

    /// <summary>Runs an API call with a fresh connection and reports errors to the user.</summary>
    private async Task RunAsync(Func<NetworkWatchClient, Task> call, string? successMessage = null)
    {
        try
        {
            await using var client = await NetworkWatchClient.ConnectAsync(TimeSpan.FromSeconds(3));
            await call(client);
            if (successMessage is not null)
                _icon.ShowBalloonTip(3000, "Network Watch", successMessage, ToolTipIcon.Info);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Network Watch", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        _ = RefreshStatusAsync();
    }

    /// <summary>Start with Windows, but only when running from the install folder (not dev builds).</summary>
    private static void EnsureAutostart()
    {
        var exe = Environment.ProcessPath;
        var installDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NetworkWatch");
        if (exe is null || !exe.StartsWith(installDir, StringComparison.OrdinalIgnoreCase)) return;
        try
        {
            using var run = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (run.GetValue("NetworkWatchTray") as string != $"\"{exe}\"")
                run.SetValue("NetworkWatchTray", $"\"{exe}\"");
        }
        catch (Exception ex)
        {
            Debug.WriteLine(ex);
        }
    }

    protected override void ExitThreadCore()
    {
        _cts.Cancel();
        _statusTimer.Dispose();
        _icon.Visible = false;
        _icon.Dispose();
        ToastNotificationManagerCompat.History.Clear();
        base.ExitThreadCore();
    }
}
