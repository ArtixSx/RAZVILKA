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
)

func legacyFixture(t *testing.T, kind string, raw []byte) (*LegacySources, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.conf")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sources, err := NewLegacySources([]LegacySpec{{ID: "legacy-source", Label: "Synthetic source", Kind: kind, Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	return sources, path
}

func TestLegacyCopyIsExplicitIdempotentAndPreservesOriginal(t *testing.T) {
	for _, kind := range []string{SourceWireGuard, SourceWGCF, SourceUSQUE} {
		t.Run(kind, func(t *testing.T) {
			raw := wgFixture()
			if kind == SourceWGCF {
				raw = wgcfFixture()
			}
			if kind == SourceUSQUE {
				raw = usqueV1Fixture(t)
			}
			sources, path := legacyFixture(t, kind, raw)
			store, destination := privateStore(t)
			before, _ := os.Stat(path)
			review, err := sources.Preview(context.Background(), "legacy-source")
			if err != nil || review.Account.Ownership != "copied-snapshot" || review.Account.Verification != "imported-unverified" {
				t.Fatalf("preview: %+v %v", review, err)
			}
			files, _ := os.ReadDir(destination)
			if len(files) != 0 {
				t.Fatal("preview persisted state")
			}
			encoded, _ := json.Marshal(review)
			if bytes.Contains(encoded, raw) || bytes.Contains(encoded, []byte("fixture-private-token")) || bytes.Contains(encoded, []byte(path)) {
				t.Fatal("private source escaped preview")
			}
			first, err := sources.Copy(context.Background(), store, "legacy-source", review.Digest)
			if err != nil {
				t.Fatal(err)
			}
			again, err := sources.Copy(context.Background(), store, "legacy-source", review.Digest)
			if err != nil || first.ID != again.ID {
				t.Fatal("duplicate copy")
			}
			after, _ := os.Stat(path)
			content, _ := os.ReadFile(path)
			if !bytes.Equal(content, raw) || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("source modified or replaced")
			}
		})
	}
}

func TestLegacyReviewCannotCopyChangedOrDifferentSource(t *testing.T) {
	sources, path := legacyFixture(t, SourceWireGuard, wgFixture())
	store, destination := privateStore(t)
	ctx := context.Background()
	review, err := sources.Preview(ctx, "legacy-source")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(wgFixture(), []byte("\n# changed after review")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Copy(ctx, store, "legacy-source", review.Digest); !errors.Is(err, ErrLegacyChanged) {
		t.Fatalf("changed copy: %v", err)
	}
	if _, err := sources.Copy(ctx, store, "legacy-source", ""); !errors.Is(err, ErrLegacyChanged) {
		t.Fatal("missing review accepted")
	}
	for _, id := range []string{"../source.conf", path, "https://example.com/", "unknown"} {
		if _, err := sources.Preview(ctx, id); !errors.Is(err, ErrLegacySource) {
			t.Fatal("arbitrary source accepted")
		}
	}
	other, _ := NewLegacySources([]LegacySpec{{ID: "other-source", Label: "Same bytes", Kind: SourceWireGuard, Path: path}})
	if _, err := other.Copy(ctx, store, "other-source", review.Digest); !errors.Is(err, ErrLegacyChanged) {
		t.Fatal("review from different source accepted")
	}
	files, _ := os.ReadDir(destination)
	if len(files) != 0 {
		t.Fatal("rejected copy wrote state")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := sources.Preview(cancelled, "legacy-source"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored")
	}
}

func TestLegacyRejectsUnsafeFilesAndPreservesForeignLock(t *testing.T) {
	sources, path := legacyFixture(t, SourceWireGuard, wgFixture())
	store, destination := privateStore(t)
	ctx := context.Background()
	review, err := sources.Preview(ctx, "legacy-source")
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(destination, ".import.lock")
	if err := os.WriteFile(lock, []byte("foreign writer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Copy(ctx, store, "legacy-source", review.Digest); !errors.Is(err, ErrBusy) {
		t.Fatalf("lock ignored: %v", err)
	}
	if raw, _ := os.ReadFile(lock); string(raw) != "foreign writer" {
		t.Fatal("foreign lock changed")
	}
	for _, raw := range [][]byte{nil, []byte("broken-private-token"), []byte(strings.Repeat("x", MaxImportBytes+1))} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := sources.Preview(ctx, "legacy-source"); err == nil || strings.Contains(fmt.Sprint(err), path) || strings.Contains(fmt.Sprint(err), "broken-private-token") {
			t.Fatal("unsafe source or error accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Preview(ctx, "legacy-source"); !errors.Is(err, ErrLegacyMissing) {
		t.Fatalf("missing source: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Preview(ctx, "legacy-source"); !errors.Is(err, ErrLegacySource) {
		t.Fatal("directory accepted")
	}
}

func TestLegacyRejectsSymlinkAndRegistryMutation(t *testing.T) {
	sources, path := legacyFixture(t, SourceWireGuard, wgFixture())
	link := filepath.Join(t.TempDir(), "source.conf")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	specs := []LegacySpec{{ID: "file-link", Label: "Link", Kind: SourceWireGuard, Path: link}}
	sources, err := NewLegacySources(specs)
	if err != nil {
		t.Fatal(err)
	}
	specs[0].Path = path
	if _, err := sources.Preview(context.Background(), "file-link"); !errors.Is(err, ErrLegacySource) {
		t.Fatal("symlink or mutable registry accepted")
	}
	parentLink := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(path), parentLink); err != nil {
		t.Fatal(err)
	}
	sources, err = NewLegacySources([]LegacySpec{{ID: "parent-link", Label: "Parent", Kind: SourceWireGuard, Path: filepath.Join(parentLink, "source.conf")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sources.Preview(context.Background(), "parent-link"); !errors.Is(err, ErrLegacySource) {
		t.Fatal("symlink root accepted")
	}
}

func TestLegacyRegistryDoesNotProbeOrCreateFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing", "source.conf")
	sources, err := NewLegacySources([]LegacySpec{{ID: "future", Label: "Not detected", Kind: SourceUSQUE, Path: path}})
	if err != nil || len(sources.Locations()) != 1 {
		t.Fatal("registry requires existing files")
	}
	files, _ := os.ReadDir(root)
	if len(files) != 0 {
		t.Fatal("registry created paths")
	}
	for _, id := range []string{"../escape", "", "BAD", "id/private"} {
		if _, err := NewLegacySources([]LegacySpec{{ID: id, Label: "Bad", Kind: SourceUSQUE, Path: path}}); err == nil {
			t.Fatal("invalid source ID accepted")
		}
	}
}
