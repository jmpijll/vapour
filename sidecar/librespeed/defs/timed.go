package defs

// Vapour's duration-controlled adaptation of server.go Download/Upload:
// same parallel, repeatedly replenished HTTP transfers and preallocated payload,
// with caller cancellation, isolated warmup, strict status checking and bounded
// counters. The original implementation is retained alongside this adapter.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sync"
	"time"
)

type WindowResult struct {
	ElapsedMS float64   `json:"elapsed_ms"`
	Value     float64   `json:"value"`
	Bytes     uint64    `json:"bytes"`
	SamplesMS []float64 `json:"samples_ms,omitempty"`
	Timeouts  int       `json:"timeouts"`
	Requests  uint64    `json:"requests"`
}

func Endpoint(s Server, endpoint string) (string, error) {
	u, err := url.Parse(s.Server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid server URL")
	}
	e, err := url.Parse(endpoint)
	if err != nil || e.IsAbs() || e.Host != "" || e.Fragment != "" || endpoint == "" {
		return "", fmt.Errorf("invalid endpoint")
	}
	u.Path = path.Join(u.Path, e.Path)
	u.RawQuery = e.RawQuery
	return u.String(), nil
}

func NewTimedClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 8
	t.DisableCompression = true
	t.ResponseHeaderTimeout = 3 * time.Second
	return &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func Probe(ctx context.Context, client *http.Client, s Server) (float64, error) {
	target, err := Endpoint(s, s.PingURL)
	if err != nil {
		return 0, err
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probe, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("User-Agent", "Vapour-LibreSpeed/1")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1025))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 || n != 0 {
		return 0, fmt.Errorf("ping endpoint must return an empty HTTP 200 response")
	}
	return float64(time.Since(started)) / float64(time.Millisecond), nil
}

func Median(samples []float64) float64 {
	v := slices.Clone(samples)
	slices.Sort(v)
	if len(v) == 0 {
		return 0
	}
	m := len(v) / 2
	if len(v)%2 == 0 {
		return (v[m-1] + v[m]) / 2
	}
	return v[m]
}
func sampleValue(phase string, samples []float64) float64 {
	if phase == "latency" {
		return Median(samples)
	}
	if len(samples) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(samples); i++ {
		total += math.Abs(samples[i] - samples[i-1])
	}
	return total / float64(len(samples)-1)
}

func SampleWindow(ctx context.Context, client *http.Client, s Server, phase string, duration time.Duration, progress func(WindowResult)) (WindowResult, error) {
	result := WindowResult{}
	start := time.Now()
	end := start.Add(duration)
	for time.Now().Before(end) {
		probeCtx, cancel := context.WithDeadline(ctx, end)
		value, err := Probe(probeCtx, client, s)
		cancel()
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.Timeouts++
		} else if time.Now().Before(end) {
			result.SamplesMS = append(result.SamplesMS, value)
		}
		result.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
		result.Value = sampleValue(phase, result.SamplesMS)
		progress(result)
		remaining := time.Until(end)
		if remaining <= 0 {
			break
		}
		pause := min(200*time.Millisecond, remaining)
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, ctx.Err()
		case <-timer.C:
		}
	}
	result.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
	if len(result.SamplesMS) < 3 {
		return result, fmt.Errorf("insufficient valid HTTP RTT samples")
	}
	return result, nil
}

type windowCounter struct {
	start    time.Time
	mu       sync.Mutex
	end      time.Time
	total    uint64
	requests uint64
	errors   int
}

func (c *windowCounter) Write(p []byte) (int, error) {
	c.mu.Lock()
	if now := time.Now(); !now.Before(c.start) && now.Before(c.end) {
		c.total += uint64(len(p))
	}
	c.mu.Unlock()
	return len(p), nil
}
func (c *windowCounter) finish(n uint64, requestStart time.Time) {
	c.mu.Lock()
	if !requestStart.Before(c.start) && time.Now().Before(c.end) {
		c.total += n
		c.requests++
	}
	c.mu.Unlock()
}
func (c *windowCounter) snapshot(start time.Time) WindowResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	elapsed := min(time.Since(start), c.end.Sub(start))
	return WindowResult{ElapsedMS: float64(elapsed) / float64(time.Millisecond), Bytes: c.total, Requests: c.requests, Value: float64(c.total) * 8 / elapsed.Seconds() / 1e6}
}

func TransferWindow(ctx context.Context, client *http.Client, s Server, phase string, duration time.Duration, parallel int, progress func(WindowResult)) (WindowResult, error) {
	return TransferWindowWithWarmup(ctx, client, s, phase, 0, duration, parallel, progress)
}

func TransferWindowWithWarmup(ctx context.Context, client *http.Client, s Server, phase string, warmup, duration time.Duration, parallel int, progress func(WindowResult)) (WindowResult, error) {
	endpoint := s.DownloadURL
	if phase == "upload" {
		endpoint = s.UploadURL
	}
	target, err := Endpoint(s, endpoint)
	if err != nil {
		return WindowResult{}, err
	}
	// LibreSpeed payload generation; shared immutable allocation outside the clock.
	payload := NewCounter()
	payload.SetUploadSize(256)
	payload.GenerateBlob()
	if phase == "download" {
		u, _ := url.Parse(target)
		q := u.Query()
		q.Set("ckSize", "16")
		u.RawQuery = q.Encode()
		target = u.String()
	}
	start := time.Now().Add(warmup)
	end := start.Add(duration)
	window, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	counter := &windowCounter{start: start, end: end}
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for window.Err() == nil {
				var body io.Reader
				requestBytes := NewCounter()
				method := http.MethodGet
				if phase == "upload" {
					method = http.MethodPost
					body = io.TeeReader(bytes.NewReader(payload.Payload()), requestBytes)
				}
				req, e := http.NewRequestWithContext(window, method, target, body)
				if e != nil {
					return
				}
				if phase == "upload" {
					req.ContentLength = int64(len(payload.Payload()))
				}
				req.Header.Set("User-Agent", "Vapour-LibreSpeed/1")
				req.Header.Set("Accept-Encoding", "identity")
				req.Header.Set("Cache-Control", "no-store")
				requestStart := time.Now()
				resp, e := client.Do(req)
				if e == nil {
					if resp.StatusCode != 200 {
						e = fmt.Errorf("HTTP %d", resp.StatusCode)
					} else if phase == "download" {
						_, e = io.Copy(io.Discard, io.TeeReader(resp.Body, counter))
					} else {
						_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024*1024))
						if e == nil && requestBytes.Total() != uint64(len(payload.Payload())) {
							e = fmt.Errorf("server replied before consuming upload payload")
						}
						if e == nil {
							counter.finish(uint64(len(payload.Payload())), requestStart)
						}
					}
					resp.Body.Close()
				}
				if e != nil && window.Err() == nil {
					counter.mu.Lock()
					counter.errors++
					counter.mu.Unlock()
					return
				}
			}
		}()
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for window.Err() == nil {
		select {
		case <-window.Done():
		case <-ticker.C:
			if !time.Now().Before(start) {
				progress(counter.snapshot(start))
			}
		}
	}
	cancel()
	wg.Wait()
	result := counter.snapshot(start)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if counter.errors > 0 {
		return result, fmt.Errorf("transfer failed in %d worker(s)", counter.errors)
	}
	if result.Bytes == 0 {
		return result, fmt.Errorf("no measured bytes acknowledged in window")
	}
	return result, nil
}
