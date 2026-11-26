package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestNewConfigEngineOrderMatchesExample(t *testing.T) {
	want := []string{"nfqws2", "sing-box", "xray"}
	store, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil || !slices.Equal(store.Get().EngineOrder, want) {
		t.Fatal("fresh configuration has unexpected preference", err)
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "configs", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var example Config
	if err := json.Unmarshal(data, &example); err != nil || !slices.Equal(example.EngineOrder, want) {
		t.Fatal("example disagrees with the installed default", err)
	}
}

func TestLoadPreservesSavedNonemptyEngineOrder(t *testing.T) {
	for _, order := range [][]string{{"nfqws2", "usque", "warp-wg", "sing-box"}, {"warp-wg", "nfqws2"}, {"xray", "wireguard", "amneziawg"}} {
		t.Run(order[0], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			cfg := Default()
			cfg.EngineOrder = order
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			store, err := Load(path)
			if err != nil || !slices.Equal(store.Get().EngineOrder, order) {
				t.Fatal("saved route preference was replaced", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, data) {
				t.Fatal("loading silently rewrote saved preferences", err)
			}
		})
	}
}
