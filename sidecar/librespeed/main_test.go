package main

import (
	"context"
	"github.com/librespeed/speedtest-cli/defs"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (defs.Server, *atomic.Uint64) {
	t.Helper()
	received := &atomic.Uint64{}
	h := http.NewServeMux()
	h.HandleFunc("/empty.php", func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Millisecond) })
	h.HandleFunc("/garbage.php", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		_, _ = w.Write(make([]byte, 32768))
	})
	h.HandleFunc("/upload.php", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return
		}
		received.Add(uint64(n))
		time.Sleep(5 * time.Millisecond)
	})
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return defs.Server{ID: 1, Name: "Fixture", Server: server.URL, DownloadURL: "garbage.php", UploadURL: "upload.php", PingURL: "empty.php"}, received
}

func TestFourMinimumWindowsAndWarmupIsolation(t *testing.T) {
	s, received := fixture(t)
	start := time.Now()
	phases := map[string]defs.WindowResult{}
	warmups := 0
	err := run(context.Background(), Config{RunID: "fixture", Servers: []defs.Server{s}, DurationMS: 10000, Parallel: 2}, func(e Event) {
		if e.Warmup {
			warmups++
		}
		if e.Event == "phase_complete" {
			phases[e.Phase] = *e.WindowResult
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(phases) != 4 || warmups != 4 {
		t.Fatalf("phases=%d warmups=%d", len(phases), warmups)
	}
	if time.Since(start) < 44*time.Second {
		t.Fatal("warmup or measurement shortened")
	}
	for name, r := range phases {
		if r.ElapsedMS < 10000 {
			t.Fatalf("%s measured only %v ms", name, r.ElapsedMS)
		}
		if r.Value < 0 || ((name == "download" || name == "upload") && r.Value == 0) {
			t.Fatalf("%s lacks a result", name)
		}
	}
	if phases["upload"].Bytes >= received.Load() {
		t.Fatal("warmup upload bytes leaked into measurement")
	}
	if len(phases["latency"].SamplesMS) < 3 || len(phases["jitter"].SamplesMS) < 3 {
		t.Fatal("missing separate raw sample windows")
	}
	t.Logf("elapsed=%s phases=%+v fixture_upload_bytes=%d", time.Since(start), phases, received.Load())
}

func TestCancellationEveryPhase(t *testing.T) {
	for _, phase := range []string{"latency", "jitter", "download", "upload"} {
		t.Run(phase, func(t *testing.T) {
			s, _ := fixture(t)
			client := defs.NewTimedClient()
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			var err error
			if phase == "latency" || phase == "jitter" {
				_, err = defs.SampleWindow(ctx, client, s, phase, 10*time.Second, func(defs.WindowResult) {})
			} else {
				_, err = defs.TransferWindow(ctx, client, s, phase, 10*time.Second, 2, func(defs.WindowResult) {})
			}
			if err == nil || time.Since(start) > time.Second {
				t.Fatalf("cancellation err=%v elapsed=%s", err, time.Since(start))
			}
		})
	}
}
func TestInvalidDurationAndTooManyServers(t *testing.T) {
	for _, c := range []Config{{DurationMS: 9999}, {DurationMS: 10000, Servers: make([]defs.Server, 33)}} {
		if err := run(context.Background(), c, func(Event) {}); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
func TestFailedTransferIsNotResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte("not test data"))
	}))
	defer server.Close()
	client := defs.NewTimedClient()
	defer client.CloseIdleConnections()
	s := defs.Server{Server: server.URL, DownloadURL: "bad", UploadURL: "bad"}
	for _, phase := range []string{"download", "upload"} {
		r, err := defs.TransferWindow(context.Background(), client, s, phase, 30*time.Millisecond, 2, func(defs.WindowResult) {})
		if err == nil || r.Bytes != 0 {
			t.Fatalf("failed %s became result %+v %v", phase, r, err)
		}
	}
}
