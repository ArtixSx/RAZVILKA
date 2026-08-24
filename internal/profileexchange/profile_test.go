package profileexchange

import (
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
)

func TestSealAndValidatePortableProfile(t *testing.T) {
	bundle := New("0.4.0", "Домашний", "NFQWS rules", "Artem")
	bundle.Services["youtube"] = config.ServiceState{Enabled: true, Route: "auto"}
	bundle.CustomServices = []catalog.Service{{ID: "custom-example", Name: "Example", Category: "Custom", Domains: []string{"example.com"}, Strategy: []string{"auto"}}}
	content := "youtube.com\n"
	bundle.EngineFiles = []EngineFile{{EngineID: "nfqws2", FileID: "user-list", Content: content, SHA256: Sum([]byte(content))}}
	if err := Seal(&bundle); err != nil {
		t.Fatal(err)
	}
	if err := Validate(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Name = "tampered"
	if err := Validate(bundle); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered profile error=%v", err)
	}
}

func TestProfileRejectsSecretsAndBadFileChecksum(t *testing.T) {
	bundle := New("0.4.0", "Unsafe", "", "")
	bundle.ContainsSecrets = true
	if err := Seal(&bundle); err != nil {
		t.Fatal(err)
	}
	if err := Validate(bundle); err == nil {
		t.Fatal("expected secret-bearing profile to be rejected")
	}
	bundle.ContainsSecrets = false
	bundle.EngineFiles = []EngineFile{{EngineID: "nfqws2", FileID: "main", Content: "x", SHA256: strings.Repeat("0", 64)}}
	if err := Seal(&bundle); err != nil {
		t.Fatal(err)
	}
	if err := Validate(bundle); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("checksum error=%v", err)
	}
}
