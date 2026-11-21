package main

import (
	"encoding/json"
	"testing"
)

// The helper's config must accept the global mappings map the GUI writes,
// keyed by target and valued by local destination.
func TestTunConfigParsesMappings(t *testing.T) {
	raw := `{
		"points": [
			{"name": "清大科越access", "server": "access.qctc.com.cn", "port": 44892}
		],
		"mappings": {"210.76.17.0:3306": "127.0.0.1:33060"}
	}`
	var cfg tunConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := cfg.Mappings["210.76.17.0:3306"]; got != "127.0.0.1:33060" {
		t.Fatalf("mapping = %q, want 127.0.0.1:33060 (map=%v)", got, cfg.Mappings)
	}
	if len(cfg.Points) != 1 || cfg.Points[0].Name != "清大科越access" {
		t.Fatalf("points = %+v", cfg.Points)
	}

	// A config without mappings stays empty, not nil-deref.
	var none tunConfig
	if err := json.Unmarshal([]byte(`{"points":[]}`), &none); err != nil {
		t.Fatal(err)
	}
	if len(none.Mappings) != 0 {
		t.Fatalf("expected no mappings, got %v", none.Mappings)
	}
}
