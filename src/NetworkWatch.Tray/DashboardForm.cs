using NetworkWatch.Core;
using NetworkWatch.Core.Api;
using NetworkWatch.Core.Storage;

namespace NetworkWatch.Tray;

/// <summary>Main window: Alerts (with explanations and actions), Activity, Apps, Blocked programs.</summary>
internal sealed class DashboardForm : Form
{
    private readonly Func<Func<NetworkWatchClient, Task>, string?, Task> _run;
    private readonly Label _statusLabel = new() { Dock = DockStyle.Top, Height = 44, Padding = new Padding(10, 6, 10, 0) };
    private readonly ListView _alerts = NewList(("When", 110), ("Severity", 70), ("Alert", 520), ("Count", 50), ("Status", 110));
    private readonly TextBox _details = new() { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical, Font = new Font("Segoe UI", 10) };
    private readonly ListView _activity = NewList(("Time", 110), ("Dir", 40), ("Proto", 50), ("Program", 170), ("Remote", 190), ("Domain", 240), ("Location", 220), ("Signer", 170), ("Threat", 200));
    private readonly TextBox _search = new() { PlaceholderText = "Filter by program, domain or IP…", Width = 320 };
    private readonly ListView _apps = NewList(("Program", 190), ("Signed by", 210), ("Sent 24h", 80), ("Received 24h", 90), ("First seen", 110), ("Last seen", 110), ("Trusted", 60), ("Path", 380));
    private readonly ListView _blocks = NewList(("Rule", 320), ("Direction", 80), ("Program", 520));
    private readonly CheckBox _showInfo = new() { Text = "Show info-level", AutoSize = true };
    private readonly CheckBox _showAcknowledged = new() { Text = "Show acknowledged", AutoSize = true };
    private List<Alert> _alertData = [];
    private long? _pendingSelect;

    public DashboardForm(Func<Func<NetworkWatchClient, Task>, string?, Task> run)
    {
        _run = run;
        Text = "Network Watch";
        Width = 1200;
        Height = 760;
        StartPosition = FormStartPosition.CenterScreen;
        Icon = Icons.For(TrayState.Quiet);
        Font = new Font("Segoe UI", 9.5f);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(AlertsPage());
        tabs.TabPages.Add(ActivityPage());
        tabs.TabPages.Add(AppsPage());
        tabs.TabPages.Add(BlocksPage());
        tabs.SelectedIndexChanged += async (_, _) => await RefreshTabAsync(tabs.SelectedIndex);
        Controls.Add(tabs);
        Controls.Add(_statusLabel);

        Shown += async (_, _) =>
        {
            if (await Fetch<StatusDto>(new ApiRequest { Cmd = ApiCommands.Status }) is { } status) OnStatus(status);
            await LoadAlertsAsync();
        };
    }

    public void OnNewAlert()
    {
        if (Visible) _ = LoadAlertsAsync();
    }

    public void OnStatus(StatusDto s)
    {
        _statusLabel.Text =
            (s.IsLearning ? $"Learning what's normal on this PC until {s.LearningEndsAt:dddd HH:mm}. Behavior alerts stay quiet until then; threat-intel and high-risk checks are active now."
                          : "Watching for anything unusual.") + Environment.NewLine +
            $"{s.EventsProcessed:N0} events · {s.FlowsStored:N0} connections recorded · {s.AppsKnown} programs · {s.ThreatIndicators:N0} threat indicators";
    }

    public void ShowAlert(long? alertId)
    {
        _pendingSelect = alertId;
        _ = LoadAlertsAsync();
    }

    // ── Alerts ──────────────────────────────────────────────────────────────

    private TabPage AlertsPage()
    {
        var page = new TabPage("Alerts");
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 300 };
        _alerts.SelectedIndexChanged += (_, _) => ShowSelectedAlert();
        split.Panel1.Controls.Add(_alerts);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, Padding = new Padding(4) };
        buttons.Controls.Add(Button("Acknowledge", async () => await AlertAction(a => new ApiRequest { Cmd = ApiCommands.Ack, AlertId = a.Id }, null)));
        buttons.Controls.Add(Button("Trust this program", async () => await AlertAction(a => new ApiRequest { Cmd = ApiCommands.Trust, AlertId = a.Id }, "Trusted.")));
        buttons.Controls.Add(Button("Trust for this check only", async () => await AlertAction(a => new ApiRequest { Cmd = ApiCommands.Trust, AlertId = a.Id, DetectorId = a.DetectorId }, "Trusted for this check.")));
        buttons.Controls.Add(Button("Block program", async () =>
        {
            if (Selected() is { ProcessPath: not null } a &&
                MessageBox.Show($"Block all network access for\n{a.ProcessPath}?", "Network Watch", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                await AlertAction(x => new ApiRequest { Cmd = ApiCommands.Block, AlertId = x.Id }, "Blocked in Windows Firewall.");
        }));
        buttons.Controls.Add(Button("Acknowledge all", async () => { await _run(c => c.CallRawAsync(new ApiRequest { Cmd = ApiCommands.AckAll }), null); await LoadAlertsAsync(); }));
        _showInfo.CheckedChanged += async (_, _) => await LoadAlertsAsync();
        buttons.Controls.Add(_showInfo);
        _showAcknowledged.CheckedChanged += async (_, _) => await LoadAlertsAsync();
        buttons.Controls.Add(_showAcknowledged);

        split.Panel2.Controls.Add(_details);
        split.Panel2.Controls.Add(buttons);
        page.Controls.Add(split);
        return page;
    }

    private async Task LoadAlertsAsync()
    {
        try
        {
            await using var client = await NetworkWatchClient.ConnectAsync(TimeSpan.FromSeconds(3));
            _alertData = await client.CallAsync<List<Alert>>(new ApiRequest
            {
                Cmd = ApiCommands.Alerts, Limit = 500, MinSeverity = _showInfo.Checked ? Severity.Info : Severity.Medium,
            }) ?? [];
            if (!_showAcknowledged.Checked) _alertData = _alertData.Where(a => a.Status == AlertStatus.New).ToList();
        }
        catch (Exception ex)
        {
            _details.Text = $"Can't reach the Network Watch service: {ex.Message}";
            return;
        }

        var selectId = _pendingSelect ?? Selected()?.Id;
        _pendingSelect = null;
        _alerts.BeginUpdate();
        _alerts.Items.Clear();
        foreach (var a in _alertData)
        {
            var item = new ListViewItem([a.LastSeen.ToString("MM-dd HH:mm"), a.Severity.ToString(), a.Title, a.Count.ToString(),
                a.Status == AlertStatus.New ? "New" : "Acknowledged"]) { Tag = a };
            item.ForeColor = a.Severity switch { Severity.High => Color.Firebrick, Severity.Medium => Color.DarkGoldenrod, _ => Color.DimGray };
            if (a.Status == AlertStatus.New) item.Font = new Font(_alerts.Font, FontStyle.Bold);
            _alerts.Items.Add(item);
            if (a.Id == selectId) item.Selected = true;
        }
        _alerts.EndUpdate();
        if (_alerts.SelectedItems.Count == 0) _details.Text = _alertData.Count == 0 ? (_showAcknowledged.Checked ? "No alerts." : "Nothing new to review. Tick \"Show acknowledged\" to see past alerts.") : "Select an alert to see what happened and what to do.";
        else _alerts.SelectedItems[0].EnsureVisible();
    }

    private Alert? Selected() => _alerts.SelectedItems.Count > 0 ? _alerts.SelectedItems[0].Tag as Alert : null;

    private void ShowSelectedAlert()
    {
        if (Selected() is not { } a) return;
        var nl = Environment.NewLine;
        _details.Text =
            $"{a.Title}  [{a.Severity}]{nl}{nl}" +
            $"WHAT HAPPENED{nl}{a.WhatHappened}{nl}{nl}" +
            $"WHY IT MATTERS{nl}{a.WhyItMatters}{nl}{nl}" +
            $"WHAT TO DO{nl}{a.WhatToDo}{nl}{nl}" +
            $"Seen {a.Count}x between {a.FirstSeen:g} and {a.LastSeen:g} · check: {a.DetectorId}" +
            (a.ProcessPath is null ? "" : $"{nl}Program: {a.ProcessPath}") +
            (a.Remote is null ? "" : $"{nl}Remote: {a.Remote}{(a.Domain is null ? "" : $" ({a.Domain})")}");
    }

    private async Task AlertAction(Func<Alert, ApiRequest> request, string? success)
    {
        if (Selected() is not { } a) return;
        await _run(c => c.CallRawAsync(request(a)), success);
        await LoadAlertsAsync();
    }

    // ── Activity / Apps / Blocks ────────────────────────────────────────────

    private TabPage ActivityPage()
    {
        var page = new TabPage("Activity");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4) };
        bar.Controls.Add(_search);
        bar.Controls.Add(Button("Refresh", LoadActivityAsync));
        _search.KeyDown += async (_, e) => { if (e.KeyCode == Keys.Enter) await LoadActivityAsync(); };
        page.Controls.Add(_activity);
        page.Controls.Add(bar);
        return page;
    }

    private async Task LoadActivityAsync()
    {
        var rows = await Fetch<List<ConnectionRecord>>(new ApiRequest { Cmd = ApiCommands.Connections, Limit = 1000, Search = _search.Text });
        Fill(_activity, rows, c =>
        [
            c.Time.ToString("MM-dd HH:mm:ss"), c.Direction == "Outbound" ? "out" : "in", c.Protocol, $"{c.ProcessName} ({c.Pid})",
            $"{c.RemoteIp}:{c.RemotePort}", c.Domain ?? $"({c.Scope})",
            string.Join(", ", new[] { c.Country, c.Network }.Where(s => !string.IsNullOrEmpty(s))), c.Signer ?? c.Signature, c.Threat ?? "",
        ], c => c.Threat is not null ? Color.Firebrick : null);
    }

    private TabPage AppsPage()
    {
        var page = new TabPage("Programs");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4) };
        bar.Controls.Add(Button("Refresh", LoadAppsAsync));
        bar.Controls.Add(Button("Remove trust", async () =>
        {
            if (_apps.SelectedItems.Count > 0 && _apps.SelectedItems[0].Tag is AppRecord app)
            {
                await _run(c => c.CallRawAsync(new ApiRequest { Cmd = ApiCommands.Untrust, AppKey = app.AppKey }), "Trust removed.");
                await LoadAppsAsync();
            }
        }));
        page.Controls.Add(_apps);
        page.Controls.Add(bar);
        return page;
    }

    private async Task LoadAppsAsync()
    {
        var rows = await Fetch<List<AppRecord>>(new ApiRequest { Cmd = ApiCommands.Apps });
        var usage = (await Fetch<List<AppUsage>>(new ApiRequest { Cmd = ApiCommands.Usage, Hours = 24, Limit = 1000 }) ?? [])
            .ToDictionary(u => u.AppKey);
        Fill(_apps, rows, a =>
        [
            a.ProcessName, a.Signer ?? "(unsigned / unknown)",
            usage.TryGetValue(a.AppKey, out var u) ? UploadVolumeDetector.FormatBytes(u.BytesSent) : "",
            usage.TryGetValue(a.AppKey, out var v) ? UploadVolumeDetector.FormatBytes(v.BytesReceived) : "",
            a.FirstSeen.ToString("MM-dd HH:mm"), a.LastSeen.ToString("MM-dd HH:mm"), a.Trusted ? "yes" : "", a.ProcessPath ?? "",
        ], a => a.Signer is null ? Color.DarkGoldenrod : null);
    }

    private TabPage BlocksPage()
    {
        var page = new TabPage("Blocked");
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4) };
        bar.Controls.Add(Button("Refresh", LoadBlocksAsync));
        bar.Controls.Add(Button("Unblock program", async () =>
        {
            if (_blocks.SelectedItems.Count > 0 && _blocks.SelectedItems[0].Tag is BlockRule rule)
            {
                await _run(c => c.CallRawAsync(new ApiRequest { Cmd = ApiCommands.Unblock, ProcessPath = rule.ProcessPath }), "Unblocked.");
                await LoadBlocksAsync();
            }
        }));
        page.Controls.Add(_blocks);
        page.Controls.Add(bar);
        return page;
    }

    private async Task LoadBlocksAsync()
    {
        var rows = await Fetch<List<BlockRule>>(new ApiRequest { Cmd = ApiCommands.Blocks });
        Fill(_blocks, rows, r => [r.Name, r.Direction, r.ProcessPath], _ => null);
    }

    private Task RefreshTabAsync(int index) => index switch
    {
        0 => LoadAlertsAsync(),
        1 => LoadActivityAsync(),
        2 => LoadAppsAsync(),
        _ => LoadBlocksAsync(),
    };

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static async Task<T?> Fetch<T>(ApiRequest request)
    {
        try
        {
            await using var client = await NetworkWatchClient.ConnectAsync(TimeSpan.FromSeconds(3));
            return await client.CallAsync<T>(request);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Can't reach the Network Watch service: {ex.Message}", "Network Watch");
            return default;
        }
    }

    private static void Fill<T>(ListView list, List<T>? rows, Func<T, string[]> columns, Func<T, Color?> color)
    {
        list.BeginUpdate();
        list.Items.Clear();
        foreach (var row in rows ?? [])
        {
            var item = new ListViewItem(columns(row)) { Tag = row };
            if (color(row) is { } c) item.ForeColor = c;
            list.Items.Add(item);
        }
        list.EndUpdate();
    }

    private static ListView NewList(params (string Name, int Width)[] columns)
    {
        var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false };
        foreach (var (name, width) in columns) list.Columns.Add(name, width);
        return list;
    }

    private static Button Button(string text, Func<Task> onClick)
    {
        var button = new Button { Text = text, AutoSize = true, Height = 30 };
        button.Click += async (_, _) => await onClick();
        return button;
    }
}
