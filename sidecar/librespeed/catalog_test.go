package main

import (
	"context"
	"github.com/librespeed/speedtest-cli/defs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCatalogueBoundsAndValidation(t *testing.T) {
	good := `[{"id":1,"server":"https://example.com/backend/","dlURL":"garbage.php","ulURL":"empty.php","pingURL":"empty.php"}]`
	for name, body := range map[string]string{"good": good, "HTTP": strings.Replace(good, "https:", "http:", 1), "redirect_endpoint": strings.Replace(good, "garbage.php", "https://another.example/file", 1), "large": strings.Repeat(" ", 1024*1024+1), "invalid": "{}"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client := defs.NewTimedClient()
			defer client.CloseIdleConnections()
			_, err := fetchCatalog(context.Background(), client, server.URL)
			if (err == nil) != (name == "good") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSelectionHonorsManualServer(t *testing.T) {
	s, _ := fixture(t)
	s.ID = 42
	id := 42
	client := defs.NewTimedClient()
	defer client.CloseIdleConnections()
	selected, err := selectServer(context.Background(), client, Config{Servers: []defs.Server{s}, ServerID: &id})
	if err != nil || selected.ID != 42 {
		t.Fatalf("selected=%v err=%v", selected, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = selectServer(ctx, client, Config{Servers: []defs.Server{s}}); err == nil {
		t.Fatal("cancelled discovery succeeded")
	}
}
