package cloudflareprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func restoreSnapshot(n int) privatebackup.ProviderSnapshot {
	raw := bytes.ReplaceAll(usqueFixture(), []byte("private-device-marker"), []byte(fmt.Sprintf("synthetic-device-%d", n)))
	return privatebackup.ProviderSnapshot{Provider: "cloudflare", ID: fmt.Sprintf("cf-%032x", n), SourceKind: SourceUSQUE, Content: string(raw), SHA256: digest(raw), ImportedAt: "2026-01-01T00:00:00Z"}
}

func TestProviderRestoreSharesOrdinaryWriterLease(t *testing.T) {
	ctx := context.Background()
	s, path := privateStore(t)
	other, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	session, err := s.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
	if _, err := other.ImportSnapshot(ctx, parsed); !errors.Is(err, ErrBusy) {
		t.Fatalf("import crossed lease: %v", err)
	}
	if _, err := OpenRestoreTarget(path); !errors.Is(err, ErrBusy) {
		t.Fatalf("startup target crossed lease: %v", err)
	}
	if _, err := s.BeginRestore(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("same Store reentered: %v", err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := s.ImportSnapshot(short, parsed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ordinary writer did not cancel: %v", err)
	}
	source, _ := privateStore(t)
	if _, err := source.ImportSnapshot(ctx, parsed); err != nil {
		t.Fatal(err)
	}
	envelope, err := source.Backup(ctx, backupPassword, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.RestoreBackup(ctx, envelope, backupPassword); !errors.Is(err, ErrBusy) {
		t.Fatalf("backup crossed lease: %v", err)
	}
	before, err := session.Read(ctx)
	if err != nil || before.Exists {
		t.Fatal("absent store not preserved")
	}
	after, review, err := session.MergeImage(ctx, []privatebackup.ProviderSnapshot{restoreSnapshot(1)})
	if err != nil || review.Added != 1 {
		t.Fatalf("plan: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, storeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plan wrote store")
	}
	if err := session.CompareAndSwap(ctx, before, after); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Read(ctx); !errors.Is(err, restorejournal.ErrUnavailable) {
		t.Fatal("closed target readable")
	}
	if err := session.CompareAndSwap(ctx, after, before); !errors.Is(err, restorejournal.ErrUnavailable) {
		t.Fatal("closed target writable")
	}
	if _, _, err := session.MergeImage(ctx, []privatebackup.ProviderSnapshot{restoreSnapshot(2)}); !errors.Is(err, restorejournal.ErrUnavailable) {
		t.Fatal("closed target builds plan")
	}
	views, err := s.List(ctx)
	if err != nil || len(views) != 1 || views[0].Verification != "imported-unverified" {
		t.Fatal("Store did not reread snapshot")
	}
	if _, err := other.ImportSnapshot(ctx, parsed); err != nil {
		t.Fatal("writer did not resume", err)
	}
	release, err := other.lockWrite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginRestore(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("target crossed ordinary writer")
	}
	release()
	resumed, err := s.BeginRestore(ctx)
	if err != nil {
		t.Fatal("failed preparation retained gate", err)
	}
	resumed.Close()
	for _, text := range []string{fmt.Sprintf("%+v %#v", session, session), fmt.Sprint(after)} {
		if strings.Contains(text, "private-key-marker") || strings.Contains(text, path) {
			t.Fatal("target logging leaks secrets/path")
		}
	}
}

func TestProviderRestoreMergeConflictAndExactUndo(t *testing.T) {
	s, path := privateStore(t)
	ctx := context.Background()
	item := restoreSnapshot(1)
	doc, err := snapshotsDocument([]privatebackup.ProviderSnapshot{item})
	if err != nil {
		t.Fatal(err)
	}
	// Preserve formatting and unknown metadata on exact undo, not reserialization.
	data, _ := json.MarshalIndent(doc, "", "  ")
	data = bytes.Replace(data, []byte("{\n"), []byte("{\n  \"future_metadata\": \"preserve-on-undo\",\n"), 1)
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(path, storeFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	session, err := s.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	before, _ := session.Read(ctx)
	idempotent, review, err := session.MergeImage(ctx, []privatebackup.ProviderSnapshot{item})
	if err != nil || review.Existing != 1 || !sameSnapshotImage(before, idempotent) {
		t.Fatal("no-op changed exact bytes")
	}
	conflict := item
	conflict.Content = strings.ReplaceAll(conflict.Content, "private-token-marker", "another-token-marker")
	conflict.SHA256 = digest([]byte(conflict.Content))
	if _, _, err := session.MergeImage(ctx, []privatebackup.ProviderSnapshot{conflict}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting credentials accepted: %v", err)
	}
	for _, items := range [][]privatebackup.ProviderSnapshot{nil, {item, item}, {{Provider: "unknown"}}, {func() privatebackup.ProviderSnapshot { bad := item; bad.ID = "../accounts"; return bad }()}} {
		if _, _, err := session.MergeImage(ctx, items); !errors.Is(err, ErrBackup) {
			t.Fatalf("bad snapshots accepted: %v", err)
		}
	}
	after, _, err := session.MergeImage(ctx, []privatebackup.ProviderSnapshot{restoreSnapshot(2)})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.CompareAndSwap(ctx, before, after); err != nil {
		t.Fatal(err)
	}
	if err := session.CompareAndSwap(ctx, before, before); !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("stale before accepted")
	}
	if err := session.CompareAndSwap(ctx, after, before); err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(filepath.Join(path, storeFile))
	if !bytes.Equal(data, actual) {
		t.Fatal("undo changed bytes")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := session.CompareAndSwap(canceled, before, after); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled write accepted")
	}
	if _, err := session.Read(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled read accepted")
	}
	for _, bad := range []restorejournal.Image{{Exists: true}, {Exists: false, Data: []byte("x")}, {Exists: true, Data: []byte(`{"schema":1,"owner":"foreign"}`)}, {Exists: true, Data: []byte(`{}`)}, {Exists: true, Data: []byte(`null`)}, {Exists: true, Data: []byte(`{"accounts":[]}`)}} {
		if err := session.CompareAndSwap(ctx, before, bad); err == nil {
			t.Fatal("invalid image accepted")
		}
	}
	// A noncooperative later edit must be observed, never overwritten by undo.
	if err := os.WriteFile(filepath.Join(path, storeFile), append(bytes.Clone(data), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := session.CompareAndSwap(ctx, before, after); !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("external edit overwritten")
	}
}

func TestProviderRestoreFailureAfterReplacement(t *testing.T) {
	for _, commitFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(commitFirst), func(t *testing.T) {
			s, _ := privateStore(t)
			ctx := context.Background()
			session, err := s.BeginRestore(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			before, _ := session.Read(ctx)
			after, _, err := session.MergeImage(ctx, []privatebackup.ProviderSnapshot{restoreSnapshot(1)})
			if err != nil {
				t.Fatal(err)
			}
			realWrite := session.write
			session.write = func(image restorejournal.Image) error {
				if commitFirst {
					if err := realWrite(image); err != nil {
						return err
					}
				}
				return errors.New("private-secret and internal-path")
			}
			if err := session.CompareAndSwap(ctx, before, after); err != restorejournal.ErrRecovery {
				t.Fatalf("raw error leaked: %v", err)
			}
			actual, _ := session.Read(ctx)
			want := before
			if commitFirst {
				want = after
			}
			if !sameSnapshotImage(actual, want) {
				t.Fatal("uncertain write incorrectly classified")
			}
			session.write = realWrite
			if err := session.CompareAndSwap(ctx, actual, before); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func largeSnapshots(t *testing.T, count int) []privatebackup.ProviderSnapshot {
	t.Helper()
	items := make([]privatebackup.ProviderSnapshot, count)
	for n := range items {
		item := restoreSnapshot(n + 1)
		item.Content = strings.TrimSuffix(item.Content, "}") + `,"padding":"` + strings.Repeat("x", 190<<10) + `"}`
		item.SHA256 = digest([]byte(item.Content))
		if _, err := ParseImport(item.SourceKind, []byte(item.Content)); err != nil {
			t.Fatal("bad large fixture", err)
		}
		items[n] = item
	}
	return items
}

func TestProviderRestoreBudgetDoesNotShrinkStandaloneCapacity(t *testing.T) {
	s, path := privateStore(t)
	ctx := context.Background()
	items := largeSnapshots(t, 17)
	session, err := s.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.MergeImage(ctx, items); !errors.Is(err, ErrRestoreCapacity) {
		t.Fatalf("oversized after not rejected: %v", err)
	}
	session.Close()
	if _, err := os.Stat(filepath.Join(path, storeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversized plan wrote file")
	}
	// Ordinary imports remain usable above 4 MiB, below the existing store cap.
	for _, item := range items {
		parsed, _ := ParseImport(item.SourceKind, []byte(item.Content))
		if _, err := s.ImportSnapshot(ctx, parsed); err != nil {
			t.Fatal("standalone capacity reduced", err)
		}
	}
	before, err := os.ReadFile(filepath.Join(path, storeFile))
	if err != nil || len(before) <= restorejournal.MaxImageBytes || len(before) > storeLimit {
		t.Fatal("bad oversized store fixture")
	}
	if _, err := s.BeginRestore(ctx); !errors.Is(err, ErrRestoreCapacity) {
		t.Fatalf("oversized before not rejected: %v", err)
	}
	if _, err := OpenRestoreTarget(path); !errors.Is(err, ErrRestoreCapacity) {
		t.Fatalf("startup budget: %v", err)
	}
	views, err := s.List(ctx)
	if err != nil || len(views) != 17 {
		t.Fatal("oversized store unreadable", err)
	}
	parsed, _ := ParseImport(items[0].SourceKind, []byte(items[0].Content))
	if _, err := s.ImportSnapshot(ctx, parsed); err != nil {
		t.Fatal("oversize failure leaked lease", err)
	}
	after, _ := os.ReadFile(filepath.Join(path, storeFile))
	if !bytes.Equal(before, after) {
		t.Fatal("budget failure or no-op changed file")
	}
}

func TestProviderRestorePreparationFailureReleasesOwnership(t *testing.T) {
	s, path := privateStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.BeginRestore(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	files, _ := os.ReadDir(path)
	if len(files) != 0 {
		t.Fatal("canceled preparation created marker")
	}
	if err := os.WriteFile(filepath.Join(path, storeFile), []byte("{unfinished secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginRestore(context.Background()); !errors.Is(err, ErrStore) {
		t.Fatal("invalid before allowed", err)
	}
	if _, err := OpenRestoreTarget(path); !errors.Is(err, ErrStore) {
		t.Fatal("startup accepted invalid before", err)
	}
	data, _ := json.Marshal(privateDocument{Schema: Schema, Owner: "razvilka"})
	if err := os.WriteFile(filepath.Join(path, storeFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := s.BeginRestore(context.Background())
	if err != nil {
		t.Fatal("failed preparation leaked ownership", err)
	}
	target.Close()
	missing := filepath.Join(path, "missing")
	if _, err := OpenRestoreTarget(missing); err == nil {
		t.Fatal("missing root accepted")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("root created implicitly")
	}
	if providerBinding(path) == providerBinding(missing) {
		t.Fatal("binding ignored root")
	}
}

func TestProviderRestorePreservesUnknownWriterMarker(t *testing.T) {
	for _, marker := range []string{"", "interrupted legacy import", writerLockMarker[:10]} {
		t.Run(fmt.Sprintf("length-%d", len(marker)), func(t *testing.T) {
			s, path := privateStore(t)
			lock := filepath.Join(path, writerLockFile)
			if err := os.WriteFile(lock, []byte(marker), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.BeginRestore(context.Background()); !errors.Is(err, ErrBusy) {
				t.Fatal("unknown marker adopted", err)
			}
			if _, err := OpenRestoreTarget(path); !errors.Is(err, ErrBusy) {
				t.Fatal("startup adopted marker", err)
			}
			data, _ := os.ReadFile(lock)
			if string(data) != marker {
				t.Fatal("unknown marker changed")
			}
			if _, err := os.Stat(filepath.Join(path, storeFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed preparation wrote snapshots")
			}
		})
	}
}

func TestProviderExistingDocumentRequiresOwnershipAndSchema(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"accounts":[]}`, `{"schema":1}`, `{"owner":"razvilka"}`} {
		t.Run(raw, func(t *testing.T) {
			s, path := privateStore(t)
			file := filepath.Join(path, storeFile)
			if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if other, err := OpenStore(path); err == nil {
				other.Close()
				t.Fatal("corrupt document treated as absent")
			}
			if _, err := s.BeginRestore(context.Background()); !errors.Is(err, ErrStore) {
				t.Fatalf("invalid recovery document: %v", err)
			}
			parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
			if _, err := s.ImportSnapshot(context.Background(), parsed); !errors.Is(err, ErrStore) {
				t.Fatalf("import replaced corrupt document: %v", err)
			}
			got, _ := os.ReadFile(file)
			if string(got) != raw {
				t.Fatal("corrupt file modified")
			}
		})
	}
}
