using NetworkWatch.Core;

namespace NetworkWatch.Core.Tests;

public class ReorderBufferTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void HoldsItemsUntilTheHoldTimeElapses()
    {
        var buffer = new ReorderBuffer<string>(TimeSpan.FromSeconds(3));
        buffer.Add("a", T0);

        Assert.Empty(buffer.DrainReady(T0.AddSeconds(2)).ToList());
        Assert.Equal(["a"], buffer.DrainReady(T0.AddSeconds(3)).ToList());
        Assert.Equal(0, buffer.Count);
    }

    [Fact]
    public void ReleasesInArrivalOrderAndStopsAtFirstUnreadyItem()
    {
        var buffer = new ReorderBuffer<string>(TimeSpan.FromSeconds(3));
        buffer.Add("a", T0);
        buffer.Add("b", T0.AddSeconds(1));
        buffer.Add("c", T0.AddSeconds(5));

        Assert.Equal(["a", "b"], buffer.DrainReady(T0.AddSeconds(4)).ToList());
        Assert.Equal(1, buffer.Count);
    }

    [Fact]
    public void DrainAllEmptiesTheBuffer()
    {
        var buffer = new ReorderBuffer<string>(TimeSpan.FromSeconds(3));
        buffer.Add("a", T0);
        buffer.Add("b", T0);

        Assert.Equal(["a", "b"], buffer.DrainAll().ToList());
        Assert.Equal(0, buffer.Count);
    }
}
