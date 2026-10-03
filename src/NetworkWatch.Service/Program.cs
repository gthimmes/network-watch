using NetworkWatch.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "NetworkWatch");

var paths = new ServicePaths(builder.Configuration["data"]);
builder.Logging.AddProvider(new FileLoggerProvider(paths.LogDirectory));
builder.Logging.AddFilter("Microsoft.Hosting", LogLevel.Warning);
builder.Logging.AddFilter("System.Net.Http", LogLevel.Warning);

builder.Services.AddSingleton(paths);
builder.Services.AddHttpClient("feeds", client =>
{
    client.Timeout = TimeSpan.FromSeconds(60);
    client.DefaultRequestHeaders.UserAgent.ParseAdd($"NetworkWatch/{Engine.Version} (+https://github.com/gthimmes/network-watch)");
});
builder.Services.AddSingleton<Engine>();
builder.Services.AddHostedService<PipeServer>();
builder.Services.AddHostedService<FeedWorker>();
builder.Services.AddHostedService<MaintenanceWorker>();
builder.Services.AddHostedService<MonitorWorker>();

builder.Build().Run();
