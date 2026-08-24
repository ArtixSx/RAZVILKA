package privatebackup

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestEncryptedPrivateBackupRoundTripAndTamperDetection(t *testing.T) {
	payload := NewPayload("0.9.0")
	payload.Services["youtube"] = config.ServiceState{Enabled: true, Route: "warp-wg", Sources: []string{"192.168.1.25"}}
	payload.EngineOrder = []string{"nfqws2", "warp-wg"}
	payload.EngineFiles = []EngineFile{{EngineID: "warp-wg", FileID: "main", Content: "[Interface]\nPrivateKey = secret\n", Sensitive: true}}
	payload.EngineFiles[0].SHA256 = Sum([]byte(payload.EngineFiles[0].Content))
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(payload, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decrypt(envelope, "correct horse battery staple")
	if err != nil || decoded.Digest != payload.Digest || decoded.EngineFiles[0].Content != payload.EngineFiles[0].Content {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	if _, err := Decrypt(envelope, "incorrect password here"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	envelope.Ciphertext = strings.Repeat("A", len(envelope.Ciphertext))
	if _, err := Decrypt(envelope, "correct horse battery staple"); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestBackupRejectsWeakPasswordAndDigestMutation(t *testing.T) {
	payload := NewPayload("0.9.0")
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(payload, "short"); err == nil {
		t.Fatal("weak password was accepted")
	}
	payload.Services["changed"] = config.ServiceState{Route: "direct"}
	if err := Validate(payload); err == nil {
		t.Fatal("mutated payload digest was accepted")
	}
}
