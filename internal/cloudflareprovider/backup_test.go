package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

const backupPassword = "synthetic provider backup password"

func TestEncryptedSnapshotBackupMergeAndIdempotence(t *testing.T) {
	ctx := context.Background()
	source, _ := privateStore(t)
	parsed, _ := ParseImport(SourceUSQUE, usqueV1Fixture(t))
	account, err := source.ImportSnapshot(ctx, parsed)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := source.Backup(ctx, backupPassword, "0.18.1-dev")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(envelope)
	if strings.Contains(string(encoded), "fixture-private") || bytes.Contains(encoded, []byte("private_key")) {
		t.Fatal("backup is plaintext")
	}
	target, path := privateStore(t)
	wg, _ := ParseImport(SourceWGCF, wgcfFixture())
	existing, err := target.ImportSnapshot(ctx, wg)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		views, err := target.RestoreBackup(ctx, envelope, backupPassword)
		if err != nil || len(views) != 1 || views[0].ID != account.ID || views[0].Verification != "imported-unverified" {
			t.Fatalf("restore failed: %v", err)
		}
	}
	views, _ := target.List(ctx)
	if len(views) != 2 || views[0].ID != existing.ID {
		t.Fatal("restore replaced an existing snapshot or duplicated input")
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	views, err = reopened.List(ctx)
	if err != nil || len(views) != 2 {
		t.Fatalf("restart: %v", err)
	}
}

func TestFailedRestoreNeverChangesPrivateStore(t *testing.T) {
	ctx := context.Background()
	s, path := privateStore(t)
	parsed, _ := ParseImport(SourceWGCF, wgcfFixture())
	if _, err := s.ImportSnapshot(ctx, parsed); err != nil {
		t.Fatal(err)
	}
	envelope, err := s.Backup(ctx, backupPassword, "0.18.1-dev")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(path, storeFile))
	checkUnchanged := func() {
		t.Helper()
		after, _ := os.ReadFile(filepath.Join(path, storeFile))
		if !bytes.Equal(before, after) {
			t.Fatal("failed restore changed private state")
		}
	}
	if _, err := s.RestoreBackup(ctx, envelope, "different strong password"); !errors.Is(err, ErrBackup) {
		t.Fatalf("wrong password: %v", err)
	}
	checkUnchanged()
	for _, mode := range []string{"conflict", "invalid-content", "foreign-state", "duplicate-id"} {
		t.Run(mode, func(t *testing.T) {
			payload, err := privatebackup.Decrypt(envelope, backupPassword)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "conflict":
				payload.ProviderSnapshots[0].Content = string(bytes.ReplaceAll(wgcfFixture(), []byte("fixture-private-token"), []byte("different-private-token")))
			case "invalid-content":
				payload.ProviderSnapshots[0].Content = "broken-private-input"
			case "foreign-state":
				payload.Services["youtube"] = config.ServiceState{Route: "auto"}
			case "duplicate-id":
				payload.ProviderSnapshots = append(payload.ProviderSnapshots, payload.ProviderSnapshots[0])
				if privatebackup.Seal(&payload) == nil {
					t.Fatal("duplicate backup accepted")
				}
				return
			}
			payload.ProviderSnapshots[0].SHA256 = privatebackup.Sum([]byte(payload.ProviderSnapshots[0].Content))
			if err := privatebackup.Seal(&payload); err != nil {
				t.Fatal(err)
			}
			modified, err := privatebackup.Encrypt(payload, backupPassword)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.RestoreBackup(ctx, modified, backupPassword); err == nil {
				t.Fatal("unsafe restore accepted")
			}
			checkUnchanged()
		})
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.RestoreBackup(cancelled, envelope, backupPassword); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel ignored: %v", err)
	}
	checkUnchanged()
}

func TestRestoreRespectsAnotherWriterAndCapacity(t *testing.T) {
	ctx := context.Background()
	source, _ := privateStore(t)
	parsed, _ := ParseImport(SourceWireGuard, wgFixture())
	if _, err := source.ImportSnapshot(ctx, parsed); err != nil {
		t.Fatal(err)
	}
	envelope, err := source.Backup(ctx, backupPassword, "0.18.1-dev")
	if err != nil {
		t.Fatal(err)
	}
	target, path := privateStore(t)
	lock := filepath.Join(path, ".import.lock")
	if err := os.WriteFile(lock, []byte("unknown writer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := target.RestoreBackup(ctx, envelope, backupPassword); !errors.Is(err, ErrBusy) {
		t.Fatalf("writer guard: %v", err)
	}
	if content, _ := os.ReadFile(lock); string(content) != "unknown writer" {
		t.Fatal("foreign lock removed")
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < MaxAccounts; n++ {
		input := append(append([]byte(nil), wgFixture()...), []byte("\n# snapshot "+strings.Repeat("x", n))...)
		parsed, _ := ParseImport(SourceWireGuard, input)
		if _, err := target.ImportSnapshot(ctx, parsed); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadFile(filepath.Join(path, storeFile))
	if _, err := target.RestoreBackup(ctx, envelope, backupPassword); err == nil {
		t.Fatal("capacity exceeded")
	}
	after, _ := os.ReadFile(filepath.Join(path, storeFile))
	if !bytes.Equal(before, after) {
		t.Fatal("over-capacity restore was partially committed")
	}
}
