package nodestore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Skipping validation for an identical image must never skip it for changed
// bytes, including a file replaced behind an open Store.
func TestValidatedImageCacheStillRejectsChangedBytes(t *testing.T) {
	for _, kind := range []string{"identity", "secret", "duplicate", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, path := setup(t)
			importGood(t, s)
			for range 2 { // validate, then reuse the validated image
				if _, err := s.Snapshot(context.Background(), testTime); err != nil {
					t.Fatal(err)
				}
			}
			var doc document
			if err := json.Unmarshal(readBytes(t, path), &doc); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "identity":
				doc.Nodes[0].ID = "forged"
			case "secret":
				doc.Secrets[0].Outbound = json.RawMessage(strings.Replace(string(doc.Secrets[0].Outbound), "426614174000", "426614174001", 1))
			}
			data, _ := json.Marshal(doc)
			switch kind {
			case "duplicate":
				data = append([]byte(`{"schema":1,`), data[1:]...)
			case "unknown":
				data = append([]byte(`{"unknown":"secret",`), data[1:]...)
			}
			if err := os.WriteFile(filepath.Join(path, fileName), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Snapshot(context.Background(), testTime); !errors.Is(err, ErrStore) {
				t.Fatalf("changed image accepted: %v", err)
			}
		})
	}
}

func TestValidatedImageCacheSeesMutations(t *testing.T) {
	s, _ := setup(t)
	id := importGood(t, s).Nodes[0].ID
	if _, err := s.Snapshot(context.Background(), testTime); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAlias(context.Background(), id, "Home VPS", testTime); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(context.Background(), testTime)
	if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Name != "Home VPS" {
		t.Fatalf("mutation not visible: %+v %v", snap.Nodes, err)
	}
}

func BenchmarkSnapshotUnchangedStore(b *testing.B) {
	path := b.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		b.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	lines := make([]string, 0, 100)
	for i := range 100 {
		lines = append(lines, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-%012d@host-%d.example:443?security=tls&sni=sni-%d.example#node-%d", i, i, i, i))
	}
	if _, err := s.Import(context.Background(), manual, strings.Join(lines, "\n"), testTime, 3600e9, false); err != nil {
		b.Fatal(err)
	}
	for _, cached := range []bool{true, false} {
		name := map[bool]string{true: "validated-image", false: "full-validation"}[cached]
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if !cached {
					s.hasValidated = false
				}
				if _, err := s.Snapshot(context.Background(), testTime); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
