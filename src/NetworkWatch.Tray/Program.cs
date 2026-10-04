namespace NetworkWatch.Tray;

internal static class Program
{
    /// <summary>Signaled by a second launch (e.g. the Start-menu shortcut with --show) to open the dashboard.</summary>
    public const string ShowEventName = @"Local\NetworkWatch.Tray.Show";

    [STAThread]
    private static void Main(string[] args)
    {
        // Single instance. Toast button clicks are delivered to the running instance through
        // ToastNotificationManagerCompat.OnActivated; if none is running, Windows starts this exe and
        // the new instance receives the activation once it subscribes.
        using var mutex = new Mutex(true, @"Local\NetworkWatch.Tray", out var createdNew);
        if (!createdNew)
        {
            if (args.Contains("--show") && EventWaitHandle.TryOpenExisting(ShowEventName, out var show))
                using (show) show.Set();
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApp(showDashboard: args.Contains("--show")));
    }
}
