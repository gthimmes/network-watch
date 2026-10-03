// nwtraffic — benign test traffic for exercising Network Watch detections.
//
//   nwtraffic get <url>                              one HTTPS request
//   nwtraffic beacon <url> <intervalSeconds> <count> a fresh connection every interval (beacon detector)
//   nwtraffic rawip <ip> <port>                      TCP connect with no DNS lookup (direct-ip detector)
//   nwtraffic listen <port> <seconds>                listen on all interfaces (exposure detector)
//
// Copy the published output to %TEMP% to also trigger the "untrusted program" detector (it's unsigned).

using System.Net;
using System.Net.Sockets;

if (args.Length == 0)
{
    Console.WriteLine("usage: nwtraffic get <url> | beacon <url> <intervalSeconds> <count> | rawip <ip> <port> | listen <port> <seconds>");
    return 2;
}

switch (args[0])
{
    case "get":
        await Get(args[1]);
        break;

    case "beacon":
        var interval = TimeSpan.FromSeconds(double.Parse(args[2]));
        var count = int.Parse(args[3]);
        for (var i = 0; i < count; i++)
        {
            await Get(args[1]);
            if (i < count - 1) await Task.Delay(interval);
        }
        break;

    case "rawip":
        using (var tcp = new TcpClient())
        {
            await tcp.ConnectAsync(IPAddress.Parse(args[1]), int.Parse(args[2]));
            Console.WriteLine($"{DateTime.Now:T} connected to {args[1]}:{args[2]}");
        }
        break;

    case "listen":
        var listener = new TcpListener(IPAddress.Any, int.Parse(args[1]));
        listener.Start();
        Console.WriteLine($"{DateTime.Now:T} listening on 0.0.0.0:{args[1]} for {args[2]} s");
        await Task.Delay(TimeSpan.FromSeconds(double.Parse(args[2])));
        listener.Stop();
        break;

    default:
        Console.Error.WriteLine($"unknown command {args[0]}");
        return 2;
}
return 0;

static async Task Get(string url)
{
    // New client per request so each one opens a fresh TCP connection.
    using var http = new HttpClient(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.Zero }) { Timeout = TimeSpan.FromSeconds(15) };
    try
    {
        using var response = await http.GetAsync(url);
        Console.WriteLine($"{DateTime.Now:T} GET {url} -> {(int)response.StatusCode}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"{DateTime.Now:T} GET {url} failed: {ex.GetBaseException().Message}");
    }
}
