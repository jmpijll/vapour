package defs

import (
	"testing"
	"time"
)

func TestWindowCounterExcludesWarmupAndBoundaryRequests(t *testing.T) {
	start := time.Now().Add(20 * time.Millisecond)
	c := &windowCounter{start: start, end: start.Add(time.Second)}
	_, _ = c.Write(make([]byte, 100))
	c.finish(100, time.Now())
	time.Sleep(time.Until(start) + time.Millisecond)
	_, _ = c.Write(make([]byte, 7))
	c.finish(11, time.Now())
	c.finish(100, start.Add(-time.Millisecond))
	r := c.snapshot(start)
	if r.Bytes != 18 || r.Requests != 1 {
		t.Fatalf("warmup/crossing request counted: %+v", r)
	}
	c.end = time.Now().Add(-time.Millisecond)
	_, _ = c.Write(make([]byte, 100))
	c.finish(100, time.Now())
	if c.total != 18 {
		t.Fatal("post-window bytes counted")
	}
}

func TestJitterFormulaAndMedian(t *testing.T) {
	samples := []float64{10, 20, 10, 30}
	if Median(samples) != 15 {
		t.Fatal("incorrect median")
	}
	if got := sampleValue("jitter", samples); got != 40.0/3.0 {
		t.Fatalf("jitter=%v", got)
	}
	if sampleValue("jitter", []float64{10, 10, 10}) != 0 {
		t.Fatal("stable RTT must have zero jitter")
	}
}
