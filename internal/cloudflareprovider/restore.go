package cloudflareprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// RestoreTarget owns copied snapshots only, not runtime profiles, registrations
// or routes. It shares the permanent .import.lock with ALL ordinary writers,
// including existing binaries using that protocol. Paths come from startup.
type RestoreTarget struct {
	mu      sync.Mutex
	root    *ownedfs.Root
	binding string
	release func()
	closed  bool
	write   func(restorejournal.Image) error
}

func (*RestoreTarget) String() string   { return "[Cloudflare snapshot recovery target]" }
func (*RestoreTarget) GoString() string { return "[Cloudflare snapshot recovery target]" }

func providerBinding(path string) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	h := sha256.Sum256([]byte("cloudflare-snapshots-schema-1\x00" + path + "\x00" + storeFile))
	return hex.EncodeToString(h[:])
}

// RestoreBinding is a lexical startup binding, not an archive-controlled path.
func RestoreBinding(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", restorejournal.ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", restorejournal.ErrInvalid
	}
	return providerBinding(abs), nil
}

// OpenRestoreTarget is usable before OpenStore during future startup recovery.
// It never creates a directory or snapshot. Lock markers are permanent and can
// be created by preparation. Absent is a valid empty store; empty/corrupt files
// and images above the journal budget fail closed, without deleting anything.
func OpenRestoreTarget(path string) (*RestoreTarget, error) {
	root, err := openPrivateRoot(path)
	if err != nil {
		return nil, err
	}
	unlock, err := acquireWriterLock(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	return newRestoreTarget(context.Background(), root, providerBinding(path), func() { unlock(); _ = root.Close() })
}

// Takes ownership of release, including on construction failure.
func newRestoreTarget(ctx context.Context, root *ownedfs.Root, binding string, release func()) (*RestoreTarget, error) {
	t := &RestoreTarget{root: root, binding: binding, release: release}
	t.write = func(image restorejournal.Image) error { return writeSnapshotImage(root, image) }
	if _, err := t.Read(ctx); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

func (t *RestoreTarget) Binding() string { return t.binding }
func (t *RestoreTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		t.release()
	}
	return nil
}
func (t *RestoreTarget) read(ctx context.Context) (restorejournal.Image, error) {
	if t.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	image, err := readSnapshotImage(ctx, t.root, restorejournal.MaxImageBytes)
	if err != nil {
		return restorejournal.Image{}, err
	}
	if _, err := snapshotDocument(image, restorejournal.MaxImageBytes); err != nil {
		return restorejournal.Image{}, err
	}
	return image, nil
}
func (t *RestoreTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.read(ctx)
}
func (t *RestoreTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := snapshotDocument(before, restorejournal.MaxImageBytes); err != nil {
		return err
	}
	if _, err := snapshotDocument(after, restorejournal.MaxImageBytes); err != nil {
		return err
	}
	current, err := t.read(ctx)
	if err != nil {
		return err
	}
	if !sameSnapshotImage(current, before) {
		return restorejournal.ErrConflict
	}
	if sameSnapshotImage(before, after) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The write seam wraps the real atomic writer in fault-injection tests.
	if t.write(restorejournal.Image{Exists: after.Exists, Data: bytes.Clone(after.Data)}) != nil {
		return restorejournal.ErrRecovery
	}
	return nil
}
func sameSnapshotImage(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}

// MergeImage prepares a bounded plan only. It reuses the standalone merge rules:
// preserve existing IDs and copies, reject conflicting credentials, no activation.
// The caller validates the full encrypted archive and passes snapshots, not paths.
func (t *RestoreTarget) MergeImage(ctx context.Context, items []privatebackup.ProviderSnapshot) (restorejournal.Image, BackupReview, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	before, err := t.read(ctx)
	if err != nil {
		return restorejournal.Image{}, BackupReview{}, err
	}
	restored, err := snapshotsDocument(items)
	if err != nil {
		return restorejournal.Image{}, BackupReview{}, err
	}
	doc, _ := snapshotDocument(before, restorejournal.MaxImageBytes)
	doc, _, review, err := mergeSnapshots(doc, restored)
	if err != nil {
		return restorejournal.Image{}, BackupReview{}, err
	}
	if review.Added == 0 {
		return before, review, nil
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return restorejournal.Image{}, BackupReview{}, ErrStore
	}
	if len(data) > restorejournal.MaxImageBytes {
		return restorejournal.Image{}, BackupReview{}, ErrRestoreCapacity
	}
	if err := ctx.Err(); err != nil {
		return restorejournal.Image{}, BackupReview{}, err
	}
	return restorejournal.Image{Exists: true, Data: data}, review, nil
}

// BeginRestore holds the Store gate, mutex and the same OS lease as Import and
// RestoreBackup. No cached account state exists to resynchronize on Close.
// It fails promptly instead of queueing while a coordinator holds other stores.
func (s *Store) BeginRestore(ctx context.Context) (*RestoreTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.gate <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	if !s.mu.TryLock() {
		<-s.gate
		return nil, ErrBusy
	}
	release := func() { s.mu.Unlock(); <-s.gate }
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	unlock, err := acquireWriterLock(s.root)
	if err != nil {
		release()
		return nil, err
	}
	return newRestoreTarget(ctx, s.root, s.binding, func() { unlock(); release() })
}
