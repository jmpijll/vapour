package main

import (
	"os"
	"testing"
)

// Run explicitly with VAPOUR_ADGUARD_FILTER pointing to the official list.
// The resolver only binds loopback ephemeral ports; it sends no DNS requests.
func BenchmarkOfficialFilterStartup(b *testing.B) {
	path := os.Getenv("VAPOUR_ADGUARD_FILTER")
	if path == "" {
		b.Skip("set VAPOUR_ADGUARD_FILTER to benchmark the official list")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	cfg := config{Upstream: "127.0.0.1:9", ListenAddress: "127.0.0.1", Rules: string(data)}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runtime := &serviceRuntime{}
		if _, err := runtime.start(cfg); err != nil {
			b.Fatal(err)
		}
		if err := runtime.stop(); err != nil {
			b.Fatal(err)
		}
	}
}
