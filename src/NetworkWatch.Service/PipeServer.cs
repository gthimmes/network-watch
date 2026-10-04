using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Channels;
using NetworkWatch.Collectors.Windows;
using NetworkWatch.Core;
using NetworkWatch.Core.Api;

namespace NetworkWatch.Service;

/// <summary>
/// Serves the local API on \\.\pipe\NetworkWatch. Any signed-in user may read; mutating commands are
/// only accepted from executables installed under %ProgramFiles%\NetworkWatch (admin-writable only),
/// so malware running as the user can't trust or unblock itself. Also pushes alerts to subscribers.
/// </summary>
public sealed partial class PipeServer : BackgroundService, IAlertSink
{
    private readonly Engine _engine;
    private readonly ILogger<PipeServer> _logger;
    private readonly List<Channel<Alert>> _subscribers = [];
    private readonly Lock _lock = new();

    public PipeServer(Engine engine, ILogger<PipeServer> logger)
    {
        _engine = engine;
        _logger = logger;
        engine.Alerts.AddSink(this);
    }

    public void Publish(Alert alert)
    {
        lock (_lock)
            foreach (var subscriber in _subscribers)
                subscriber.Writer.TryWrite(alert);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(NetworkWatchClient.PipeName, PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
                await pipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                _ = HandleClientAsync(pipe, ct);
                pipe = null; // ownership transferred
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pipe server error");
                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
            finally
            {
                if (pipe is not null) await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var _ = pipe;
        var trusted = IsTrustedClient(pipe, out var clientPath);
        using var reader = new StreamReader(pipe);
        await using var writer = new StreamWriter(pipe) { AutoFlush = true, NewLine = "\n" };
        try
        {
            while (!ct.IsCancellationRequested && pipe.IsConnected)
            {
                var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                if (line is null) break;

                ApiRequest? request = null;
                ApiResponse response;
                try
                {
                    request = JsonSerializer.Deserialize<ApiRequest>(line, ApiJson.Options) ?? throw new ApiException("Empty request.");
                    if (request.Cmd == ApiCommands.Subscribe)
                    {
                        await writer.WriteLineAsync(Serialize(new ApiResponse { Id = request.Id, Ok = true })).ConfigureAwait(false);
                        await StreamAlertsAsync(writer, ct).ConfigureAwait(false);
                        return;
                    }
                    var data = await _engine.Api.HandleAsync(request, trusted, ct).ConfigureAwait(false);
                    if (ApiCommands.Mutating.Contains(request.Cmd))
                    {
                        // Logs are readable by local users: never write secrets (API keys) to them.
                        var logged = request.Cmd == ApiCommands.SetVirusTotalKey && request.Value is not null ? request with { Value = "(redacted)" } : request;
                        _logger.LogInformation("API {Command} by {Client}: {Request}", request.Cmd, clientPath, Serialize(logged));
                    }
                    response = new ApiResponse { Id = request.Id, Ok = true, Data = JsonSerializer.SerializeToElement(data, ApiJson.Options) };
                }
                catch (Exception ex) when (ex is ApiException or JsonException)
                {
                    response = new ApiResponse { Id = request?.Id ?? 0, Ok = false, Error = ex.Message };
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "API command failed: {Request}", line);
                    response = new ApiResponse { Id = request?.Id ?? 0, Ok = false, Error = $"Internal error: {ex.Message}" };
                }
                await writer.WriteLineAsync(Serialize(response)).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
            // client went away or service stopping
        }
    }

    private async Task StreamAlertsAsync(StreamWriter writer, CancellationToken ct)
    {
        var channel = Channel.CreateBounded<Alert>(new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest });
        lock (_lock) _subscribers.Add(channel);
        try
        {
            await foreach (var alert in channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
                await writer.WriteLineAsync(Serialize(new ApiPush("alert", alert))).ConfigureAwait(false);
        }
        finally
        {
            lock (_lock) _subscribers.Remove(channel);
        }
    }

    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, ApiJson.Options);

    private bool IsTrustedClient(NamedPipeServerStream pipe, out string clientPath)
    {
        clientPath = "unknown";
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid)) return false;
        clientPath = ProcessResolver.QueryImagePath((int)pid) ?? $"pid {pid}";
        var installDir = ServicePaths.InstallDirectory + Path.DirectorySeparatorChar;
        return clientPath.StartsWith(installDir, StringComparison.OrdinalIgnoreCase);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(nint pipe, out uint clientProcessId);
}
