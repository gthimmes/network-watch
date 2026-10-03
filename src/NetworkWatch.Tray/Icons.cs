using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace NetworkWatch.Tray;

public enum TrayState { Disconnected, Learning, Quiet, Review, Alert }

/// <summary>Draws the tray icons at runtime: a shield with a state color, no image assets needed.</summary>
internal static partial class Icons
{
    private static readonly Dictionary<TrayState, Icon> Cache = [];

    public static Icon For(TrayState state)
    {
        if (Cache.TryGetValue(state, out var icon)) return icon;
        var color = state switch
        {
            TrayState.Alert => Color.FromArgb(220, 38, 38),
            TrayState.Review => Color.FromArgb(234, 179, 8),
            TrayState.Quiet => Color.FromArgb(22, 163, 74),
            TrayState.Learning => Color.FromArgb(37, 99, 235),
            _ => Color.FromArgb(120, 120, 120),
        };
        return Cache[state] = Draw(color, state == TrayState.Alert ? "!" : null);
    }

    private static Icon Draw(Color color, string? glyph)
    {
        const int size = 32;
        using var bitmap = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var path = new GraphicsPath();
            // Shield outline
            path.AddLines(new PointF[] { new(16, 2), new(29, 7), new(28, 18), new(16, 30), new(4, 18), new(3, 7) });
            path.CloseFigure();
            using var fill = new SolidBrush(color);
            using var outline = new Pen(Color.FromArgb(230, 255, 255, 255), 2f);
            g.FillPath(fill, path);
            g.DrawPath(outline, path);
            if (glyph is not null)
            {
                using var font = new Font("Segoe UI", 15, FontStyle.Bold, GraphicsUnit.Pixel);
                using var white = new SolidBrush(Color.White);
                var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                g.DrawString(glyph, font, white, new RectangleF(0, 1, size, size - 4), format);
            }
            else
            {
                // A small "signal" dot so states are distinguishable by shape, not only color.
                using var white = new SolidBrush(Color.FromArgb(235, 255, 255, 255));
                g.FillEllipse(white, 12, 11, 8, 8);
            }
        }
        var handle = bitmap.GetHicon();
        var icon = (Icon)Icon.FromHandle(handle).Clone();
        DestroyIcon(handle);
        return icon;
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(nint handle);
}
