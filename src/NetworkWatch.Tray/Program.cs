namespace NetworkWatch.Tray;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // Single instance. Toast button clicks are delivered to the running instance through
        // ToastNotificationManagerCompat.OnActivated; if none is running, Windows starts this exe and
        // the new instance receives the activation once it subscribes.
        using var mutex = new Mutex(true, @"Local\NetworkWatch.Tray", out var createdNew);
        if (!createdNew) return;

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApp());
    }
}
