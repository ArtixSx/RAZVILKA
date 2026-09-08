package privatebackup

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func TestProviderSnapshotValidationAndLegacyPayloadEncoding(t *testing.T) {
	legacy := NewPayload("0.18.1-dev")
	if err := Seal(&legacy); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(legacy)
	if strings.Contains(string(encoded), "provider_snapshots") {
		t.Fatal("empty extension changed legacy payload representation")
	}
	for _, mutate := range []func(*ProviderSnapshot){
		func(s *ProviderSnapshot) { s.Provider = "unknown" },
		func(s *ProviderSnapshot) { s.SourceKind = "script" },
		func(s *ProviderSnapshot) { s.SHA256 = "incorrect" },
		func(s *ProviderSnapshot) { s.ImportedAt = "invalid" },
		func(s *ProviderSnapshot) {
			s.Content = strings.Repeat("x", (256<<10)+1)
			s.SHA256 = Sum([]byte(s.Content))
		},
	} {
		payload := NewPayload("0.18.1-dev")
		snapshot := ProviderSnapshot{Provider: "cloudflare", ID: "cf-test", SourceKind: "usque-session", Content: "private-fixture", SHA256: Sum([]byte("private-fixture")), ImportedAt: payload.CreatedAt}
		mutate(&snapshot)
		payload.ProviderSnapshots = []ProviderSnapshot{snapshot}
		if Seal(&payload) == nil {
			t.Fatal("invalid provider snapshot accepted")
		}
	}
}

func TestLocallyRegisteredCloudflareSnapshotIsPrivateBackupCompatible(t *testing.T) {
	payload := NewPayload("0.18.1-dev")
	content := `{"schema":1,"private_key":"private-test-marker"}`
	payload.ProviderSnapshots = []ProviderSnapshot{{
		Provider: "cloudflare", ID: "cf-0123456789abcdef0123456789abcdef",
		SourceKind: "local-registration", Content: content, SHA256: Sum([]byte(content)), ImportedAt: payload.CreatedAt,
	}}
	if err := Seal(&payload); err != nil {
		t.Fatal("local registration snapshot rejected before provider validation", err)
	}
}

func TestEnvelopeRejectsOversizedSaltBeforeKDF(t *testing.T) {
	payload := NewPayload("0.18.1-dev")
	if err := Seal(&payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := Encrypt(payload, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	envelope.Salt = strings.Repeat("A", 1000)
	if _, err := Decrypt(envelope, "correct horse battery staple"); err == nil {
		t.Fatal("unbounded salt accepted")
	}
}

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
