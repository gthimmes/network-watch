using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace NetworkWatch.Core.Api;

/// <summary>Client for the service's local API. Safe to share; calls are serialized.</summary>
public sealed class NetworkWatchClient : IAsyncDisposable
{
    public const string PipeName = "NetworkWatch";

    private readonly NamedPipeClientStream _pipe;
    private readonly StreamReader _reader;
    private readonly StreamWriter _writer;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _nextId;

    private NetworkWatchClient(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
        _reader = new StreamReader(pipe);
        _writer = new StreamWriter(pipe) { AutoFlush = true, NewLine = "\n" };
    }

    public bool IsConnected => _pipe.IsConnected;

    public static async Task<NetworkWatchClient> ConnectAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync((int)timeout.TotalMilliseconds, ct).ConfigureAwait(false);
            return new NetworkWatchClient(pipe);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Sends a command and returns the deserialized result. Throws <see cref="ApiException"/> on errors.</summary>
    public async Task<T?> CallAsync<T>(ApiRequest request, CancellationToken ct = default)
    {
        var data = await CallRawAsync(request, ct).ConfigureAwait(false);
        return data is { ValueKind: not JsonValueKind.Null } element ? element.Deserialize<T>(ApiJson.Options) : default;
    }

    public async Task<JsonElement?> CallRawAsync(ApiRequest request, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var id = Interlocked.Increment(ref _nextId);
            await _writer.WriteLineAsync(JsonSerializer.Serialize(request with { Id = id }, ApiJson.Options).AsMemory(), ct).ConfigureAwait(false);
            var line = await _reader.ReadLineAsync(ct).ConfigureAwait(false) ?? throw new IOException("Service closed the connection.");
            var response = JsonSerializer.Deserialize<ApiResponse>(line, ApiJson.Options) ?? throw new IOException("Empty response.");
            if (!response.Ok) throw new ApiException(response.Error ?? "Unknown error");
            return response.Data;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Opens a dedicated connection and yields alerts as the service raises them.</summary>
    public static async IAsyncEnumerable<Alert> SubscribeAsync(TimeSpan connectTimeout, [EnumeratorCancellation] CancellationToken ct = default)
    {
        await using var client = await ConnectAsync(connectTimeout, ct).ConfigureAwait(false);
        await client.CallRawAsync(new ApiRequest { Cmd = ApiCommands.Subscribe }, ct).ConfigureAwait(false);
        while (!ct.IsCancellationRequested)
        {
            var line = await client._reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null) yield break;
            var push = JsonSerializer.Deserialize<ApiPush>(line, ApiJson.Options);
            if (push?.Alert is not null) yield return push.Alert;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _pipe.DisposeAsync().ConfigureAwait(false);
        _gate.Dispose();
    }
}
