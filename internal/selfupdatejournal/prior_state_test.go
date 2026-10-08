package selfupdatejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func preparedPriorFixture(t *testing.T) *fixture {
	t.Helper()
	f := fixtureAt(t, t.TempDir())
	for _, target := range []string{"etc/init.d/S99razvilka", "etc/razvilka/service-catalog.json", "etc/razvilka/community-catalog.json", "etc/razvilka/sources.json"} {
		path := filepath.Join(f.installation, filepath.FromSlash(target))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("prior owned file"), 0600); err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(f.candidate, filepath.Base(path))
		if err := os.WriteFile(candidate, []byte("candidate owned file"), 0600); err != nil {
			t.Fatal(err)
		}
		// The real Prepare owner seals these independently supplied fixture bytes.
		hash := sha256.Sum256([]byte("candidate owned file"))
		f.files = append(f.files, File{Target: target, Candidate: candidate, SHA256: hex.EncodeToString(hash[:])})
	}
	f.prepare(t)
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		// Only protocol/lease behavior is modeled, never process quiescence.
		if err := f.store.Execute(context.Background(), transaction, command, okay, okay); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestPreparedPriorStateKeepsActualWriterLeaseAndOriginalContext(t *testing.T) {
	f := preparedPriorFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	other, err := Open(f.installation, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	before, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	checks := 0
	check := func(c context.Context) error {
		if c != ctx {
			t.Fatal("original context replaced")
		}
		checks++
		return c.Err()
	}
	called := 0
	err = f.store.WithPreparedPriorState(ctx, transaction, check, check, func(c context.Context, r Receipt) error {
		called++
		if c != ctx || r.ID != transaction || r.Phase != "prepared" || len(r.Files) != 6 {
			t.Fatal("wrong prepared source")
		}
		if err := other.Install(c, transaction, okay, okay); err == nil {
			t.Fatal("another writer entered during source capture")
		}
		return nil
	})
	if err != nil || called != 1 || checks < 4 {
		t.Fatalf("prepared source was not held: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	if string(before) != string(after) {
		t.Fatal("source observation changed its receipt")
	}
	if err := other.Install(ctx, transaction, okay, okay); err != nil {
		t.Fatal("capture did not release its writer lease", err)
	}
}

func TestPreparedPriorStateFencesUnknownAndChangedSource(t *testing.T) {
	for _, change := range []string{"unknown-command", "installed", "missing-marker", "unknown-marker", "source-bytes", "source-mode", "receipt-during-copy", "cancel", "authority", "quiescence"} {
		t.Run(change, func(t *testing.T) {
			f := preparedPriorFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			receiptPath := filepath.Join(f.journal, transaction, "receipt.json")
			r, _, err := f.store.Current()
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "unknown-command":
				r.Phase, r.Command, r.BeforeFiles = "command-started", "quiesce-old-runtime", true
			case "installed":
				r.Phase, r.Index = "installed", len(r.Files)
			case "missing-marker":
				if err := os.Remove(filepath.Join(f.journal, ".writer.lock")); err != nil {
					t.Fatal(err)
				}
			case "unknown-marker":
				if err := os.WriteFile(filepath.Join(f.journal, ".writer.lock"), []byte("foreign writer identity"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source-bytes":
				if err := os.WriteFile(filepath.Join(f.installation, "bin/razvilka"), []byte("third source"), 0755); err != nil {
					t.Fatal(err)
				}
			case "source-mode":
				if err := os.Chmod(filepath.Join(f.installation, "bin/razvilka"), 0400); err != nil {
					t.Fatal(err)
				}
			}
			if change == "unknown-command" || change == "installed" {
				data, _ := json.Marshal(r)
				if err := os.WriteFile(receiptPath, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			refused := errors.New("source owner revoked")
			authority, quiescence := okay, okay
			if change == "authority" {
				authority = func(context.Context) error { return refused }
			}
			if change == "quiescence" {
				quiescence = func(context.Context) error { return refused }
			}
			called := false
			err = f.store.WithPreparedPriorState(ctx, transaction, authority, quiescence, func(context.Context, Receipt) error {
				called = true
				if change == "cancel" {
					cancel()
				}
				if change == "receipt-during-copy" {
					r.Commands = append(r.Commands, "foreign-command")
					data, _ := json.Marshal(r)
					return os.WriteFile(receiptPath, data, 0600)
				}
				return nil
			})
			if err == nil || called && change != "cancel" && change != "receipt-during-copy" {
				t.Fatalf("unsafe source admitted: %v", err)
			}
			if change == "missing-marker" {
				if _, err := os.Lstat(filepath.Join(f.journal, ".writer.lock")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("copy manufactured a missing writer identity", err)
				}
			}
		})
	}
}

func TestPreparedPriorStateRejectsUnownedCaptureRequest(t *testing.T) {
	f := preparedPriorFixture(t)
	called := false
	if err := f.store.WithPreparedPriorState(context.Background(), transaction, okay, okay, func(context.Context, Receipt) error { called = true; return nil }); err == nil || called {
		t.Fatal("unbounded context admitted")
	}
}
