package main

import (
	"os"
	"testing"
)

func TestOfficialFilterCompatibility(t *testing.T) {
	path := os.Getenv("VAPOUR_ADGUARD_FILTER")
	if path == "" {
		t.Skip("explicit official filter fixture required")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newDomainEngine(string(content))
	if err != nil {
		t.Fatal(err)
	}
	if engine.rulesCount() == 0 {
		t.Fatal("official list produced no DNS rules")
	}
	t.Logf("Official list parsed: %d rules", engine.rulesCount())
}
