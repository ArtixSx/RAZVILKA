package privatebackup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestEncryptedStrategySnapshotExactRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "strategy-lab.json")
	raw := []byte("{\n  \"schema_version\": 2, \"candidates\": {}, \"evidence\": [], \"selections\": {}\n}\n\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := strategylab.New(path)
	if err != nil {
		t.Fatal(err)
	}
	in, err := m.ExportPrivateIfPresent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload := NewPayload("0.20.0-dev")
	payload.StrategyLabSnapshot = in
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(payload, "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(envelope)
	if bytes.Contains(encoded, []byte("schema_version")) {
		t.Fatal("private state leaked")
	}
	decoded, err := Decrypt(envelope, "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	if decoded.StrategyLabSnapshot == nil || !bytes.Equal(decoded.StrategyLabSnapshot.Content, raw) {
		t.Fatal("exact state bytes lost")
	}
	if _, err := Decrypt(envelope, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	corrupt := envelope
	corrupt.Ciphertext = "invalid"
	if _, err := Decrypt(corrupt, "synthetic-password"); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	decoded.StrategyLabSnapshot = nil
	if Validate(decoded) == nil {
		t.Fatal("old decoder omission accepted")
	}
}
