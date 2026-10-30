//go:build !linux

package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStrictExistingRefusesUnsupportedOwnershipWithoutChangingFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw, err := json.MarshalIndent(Default(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte("config.json"))
	name := hex.EncodeToString(key[:])
	marker := []byte("RAZVILKA state file writer v1 " + name + "\n")
	markerPath := filepath.Join(dir, ".state-"+name+".lock")
	for file, data := range map[string][]byte{path: raw, markerPath: marker} {
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if store, err := LoadExistingStrict(ctx, path); store != nil || err == nil {
		t.Fatal("unsupported strict owner admitted", err)
	}
	for file, want := range map[string][]byte{path: raw, markerPath: marker} {
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("unsupported strict load changed retained file", err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatal("unsupported strict load created another file", err)
	}
}
