package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/librespeed/speedtest-cli/defs"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Same fixed catalogue as the pinned upstream speedtest/speedtest.go.
const officialCatalog = "https://librespeed.org/backend-servers/servers.php"

func fetchCatalog(ctx context.Context, client *http.Client, source string) ([]defs.Server, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Vapour-LibreSpeed/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server catalogue unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server catalogue HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, fmt.Errorf("server catalogue exceeds 1 MiB")
	}
	var servers []defs.Server
	if err = json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("invalid server catalogue")
	}
	if len(servers) == 0 || len(servers) > 32 {
		return nil, fmt.Errorf("server catalogue must contain 1..32 candidates")
	}
	for _, s := range servers {
		u, err := url.Parse(s.Server)
		if err != nil || u.Scheme != "https" {
			return nil, fmt.Errorf("public server must use HTTPS")
		}
		for _, e := range []string{s.DownloadURL, s.UploadURL, s.PingURL} {
			if _, err := defs.Endpoint(s, e); err != nil {
				return nil, err
			}
		}
	}
	return servers, nil
}
