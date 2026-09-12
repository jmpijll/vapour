package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/librespeed/speedtest-cli/defs"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"
)

type Config struct {
	RunID      string        `json:"run_id"`
	Servers    []defs.Server `json:"servers"`
	ServerID   *int          `json:"server_id"`
	DurationMS int           `json:"duration_ms"`
	Parallel   int           `json:"parallel"`
}
type Event struct {
	RunID      string       `json:"run_id"`
	Event      string       `json:"event"`
	Phase      string       `json:"phase,omitempty"`
	Warmup     bool         `json:"warmup"`
	DurationMS int          `json:"duration_ms"`
	Server     *defs.Server `json:"server,omitempty"`
	Error      string       `json:"error,omitempty"`
	*defs.WindowResult
}

func run(ctx context.Context, c Config, emit func(Event)) error {
	if c.DurationMS == 0 {
		c.DurationMS = 10000
	}
	if c.DurationMS < 10000 || c.DurationMS > 20000 {
		return fmt.Errorf("duration_ms must be 10000..20000")
	}
	if c.Parallel == 0 {
		c.Parallel = 4
	}
	if c.Parallel < 1 || c.Parallel > 8 {
		return fmt.Errorf("parallel must be 1..8")
	}
	if len(c.Servers) > 32 {
		return fmt.Errorf("provide 1..32 servers")
	}
	client := defs.NewTimedClient()
	defer client.CloseIdleConnections()
	if len(c.Servers) == 0 {
		var err error
		c.Servers, err = fetchCatalog(ctx, client, officialCatalog)
		if err != nil {
			return err
		}
	}
	chosen, err := selectServer(ctx, client, c)
	if err != nil {
		return err
	}
	emit(Event{RunID: c.RunID, Event: "selected", Server: chosen, DurationMS: c.DurationMS})
	for _, phase := range []string{"latency", "jitter", "download", "upload"} {
		emit(Event{RunID: c.RunID, Event: "progress", Phase: phase, Warmup: true, DurationMS: 1000})
		if phase == "latency" || phase == "jitter" {
			warmEnd := time.Now().Add(time.Second)
			for time.Now().Before(warmEnd) {
				probeCtx, cancel := context.WithDeadline(ctx, warmEnd)
				_, _ = defs.Probe(probeCtx, client, *chosen)
				cancel()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				timer := time.NewTimer(min(200*time.Millisecond, max(time.Until(warmEnd), 0)))
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			emit(Event{RunID: c.RunID, Event: "progress", Phase: phase, DurationMS: c.DurationMS, WindowResult: &defs.WindowResult{}})
		}
		progress := func(r defs.WindowResult) {
			r.SamplesMS = nil
			emit(Event{RunID: c.RunID, Event: "progress", Phase: phase, DurationMS: c.DurationMS, WindowResult: &r})
		}
		var result defs.WindowResult
		var err error
		duration := time.Duration(c.DurationMS) * time.Millisecond
		if phase == "latency" || phase == "jitter" {
			result, err = defs.SampleWindow(ctx, client, *chosen, phase, duration, progress)
		} else {
			result, err = defs.TransferWindowWithWarmup(ctx, client, *chosen, phase, time.Second, duration, c.Parallel, progress)
		}
		if err != nil {
			return err
		}
		emit(Event{RunID: c.RunID, Event: "phase_complete", Phase: phase, DurationMS: c.DurationMS, WindowResult: &result})
	}
	emit(Event{RunID: c.RunID, Event: "complete", Server: chosen, DurationMS: c.DurationMS})
	return nil
}
func selectServer(ctx context.Context, client *http.Client, c Config) (*defs.Server, error) {
	selection, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	type candidate struct {
		server *defs.Server
		median float64
	}
	results := make(chan candidate, len(c.Servers))
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i := range c.Servers {
		s := &c.Servers[i]
		if c.ServerID != nil && s.ID != *c.ServerID {
			continue
		}
		for _, e := range []string{s.PingURL, s.DownloadURL, s.UploadURL} {
			if _, err := defs.Endpoint(*s, e); err != nil {
				return nil, err
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-selection.Done():
				return
			}
			defer func() { <-slots }()
			samples := []float64{}
			for j := 0; j < 3; j++ {
				v, err := defs.Probe(selection, client, *s)
				if err != nil {
					return
				}
				samples = append(samples, v)
			}
			results <- candidate{s, defs.Median(samples)}
		}()
	}
	wg.Wait()
	close(results)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var chosen *defs.Server
	best := 1e99
	for c := range results {
		if c.median < best {
			chosen = c.server
			best = c.median
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("no reachable LibreSpeed server")
	}
	return chosen, nil
}

func main() {
	configPath := flag.String("config", "", "configuration JSON file")
	eventsPath := flag.String("events", "", "JSONL output file")
	cancelPath := flag.String("cancel", "", "optional cancellation marker path")
	flag.Parse()
	var config Config
	var raw []byte
	var scanner *bufio.Scanner
	output := os.Stdout
	if *configPath != "" {
		var err error
		raw, err = os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if *eventsPath == "" {
			fmt.Fprintln(os.Stderr, "--events required")
			return
		}
		output, err = os.OpenFile(*eventsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer output.Close()
	} else {
		scanner = bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), 128*1024)
		if !scanner.Scan() {
			return
		}
		raw = scanner.Bytes()
	}
	encoder := json.NewEncoder(output)
	var mutex sync.Mutex
	emit := func(e Event) { mutex.Lock(); defer mutex.Unlock(); _ = encoder.Encode(e) }
	if err := json.Unmarshal(raw, &config); err != nil {
		emit(Event{Event: "error", Error: "invalid configuration"})
		return
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, 120*time.Second)
	defer cancel()
	if scanner != nil {
		go func() {
			for scanner.Scan() {
				var message struct {
					Command string `json:"command"`
				}
				if json.Unmarshal(scanner.Bytes(), &message) == nil && message.Command == "cancel" {
					cancel()
					return
				}
			}
			cancel()
		}()
	}
	if *cancelPath != "" {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(*cancelPath); err == nil {
						cancel()
						return
					}
				}
			}
		}()
	}
	if err := run(ctx, config, emit); err != nil {
		kind := "error"
		if ctx.Err() == context.Canceled {
			kind = "cancelled"
		}
		emit(Event{RunID: config.RunID, Event: kind, Error: err.Error()})
	}
}
