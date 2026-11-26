//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestPrivateDirectoryAtomicCASRetainsDisplacedTree(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	path := filepath.Join(parent, "nodes")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	retainedFile(t, path, "old/record", []byte("old-private-image"))
	before, err := readDirectoryImage(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(t.TempDir(), "new")
	if err := os.Mkdir(next, 0700); err != nil {
		t.Fatal(err)
	}
	retainedFile(t, next, "new/record", []byte("new-private-image"))
	after, err := readDirectoryImage(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	target := fileDirectoryTarget{path: path, check: func(context.Context) error { return nil }, admission: func(ctx context.Context, begin func() error) error { return begin() }}
	if err := target.CompareAndSwap(ctx, before, after); err != nil {
		t.Fatal(err)
	}
	actual, err := target.Read(ctx)
	if err != nil || actual.Exists != after.Exists || !bytes.Equal(actual.Data, after.Data) {
		t.Fatal("complete directory replacement failed")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	retained := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".self-update-private-") {
			image, err := readDirectoryImage(ctx, filepath.Join(parent, entry.Name()))
			if err != nil || !bytes.Equal(image.Data, before.Data) {
				t.Fatal("displaced private tree was not retained")
			}
			retained++
		}
	}
	if retained != 1 {
		t.Fatal("exact displaced tree missing")
	}
	// A concurrent writer changes the entire CAS image; no known old/new
	// image may be imposed over its third image.
	retainedFile(t, path, "foreign", []byte("foreign"))
	foreign, _ := target.Read(ctx)
	if !errors.Is(target.CompareAndSwap(ctx, after, before), restorejournal.ErrConflict) {
		t.Fatal("third directory image overwritten")
	}
	unchanged, _ := target.Read(ctx)
	if !bytes.Equal(foreign.Data, unchanged.Data) {
		t.Fatal("foreign directory mutation lost")
	}
}

func TestNativeSelfUpdatePrivateCASStopAtActualRename(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			ctx := context.Background()
			parent := t.TempDir()
			control := filepath.Join(parent, "control")
			authority, err := operationgate.InitializeSelfUpdateControl(ctx, control)
			if err != nil {
				t.Fatal(err)
			}
			id := "0123456789abcdef0123456789abcdef"
			calls := 0
			admit := func(c context.Context, begin func() error) error {
				calls++
				if _, err := operationgate.RequestSelfUpdateStop(c, control, id, 7); err != nil {
					return err
				}
				return operationgate.WithSelfUpdateEffectAdmission(c, control, id, authority.InstallationID, authority.Sequence, "rollback-private-nodes", begin)
			}
			path := filepath.Join(parent, "target")
			var before, after restorejournal.Image
			var target restorejournal.Target
			if directory {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				retainedFile(t, path, "record", []byte("old"))
				before, err = readDirectoryImage(ctx, path)
				next := t.TempDir()
				retainedFile(t, next, "record", []byte("new"))
				after, err = readDirectoryImage(ctx, next)
				target = &fileDirectoryTarget{path: path, check: func(context.Context) error { return nil }, admission: admit}
			} else {
				if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
					t.Fatal(err)
				}
				file, openErr := restorejournal.OpenFileTarget(path)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer file.Close()
				root, openErr := os.OpenRoot(parent)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer root.Close()
				before, err = file.Read(ctx)
				after = restorejournal.Image{Exists: true, Data: []byte("new")}
				target = fileGuardedTarget{Target: file, root: root, name: "target", check: func(context.Context) error { return nil }, admission: admit}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := target.CompareAndSwap(ctx, before, after); !errors.Is(err, operationgate.ErrSelfUpdateStopped) || calls != 1 {
				t.Fatal("Stop did not fence actual private rename", err, calls)
			}
			actual, err := target.Read(ctx)
			if err != nil || actual.Exists != before.Exists || !bytes.Equal(actual.Data, before.Data) {
				t.Fatal("old image replaced after Stop", err)
			}
		})
	}
}

func TestNativeSelfUpdateFilesystemProbeLeavesTargetsUntouched(t *testing.T) {
	path := t.TempDir()
	retainedFile(t, path, "user-owned", []byte("preserve"))
	if err := probePrivateFilesystem(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != "user-owned" {
		t.Fatal("probe modified application data", err, entries)
	}
}

func TestPrivateDirectoryAuthorityAndAbsence(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	path := filepath.Join(parent, "state")
	next := t.TempDir()
	retainedFile(t, next, "record", []byte("bounded-image"))
	after, err := readDirectoryImage(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	blocked := errors.New("authority revoked")
	target := fileDirectoryTarget{path: path, check: func(context.Context) error { return blocked }, admission: func(ctx context.Context, begin func() error) error { return begin() }}
	if !errors.Is(target.CompareAndSwap(ctx, restorejournal.Image{}, after), blocked) {
		t.Fatal("revocation bypassed")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("target created before authority")
	}
	target.check = func(context.Context) error { return nil }
	if err := target.CompareAndSwap(ctx, restorejournal.Image{}, after); err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(ctx, after, restorejournal.Image{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("absent image not restored")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if target.CompareAndSwap(cancelled, restorejournal.Image{}, after) == nil {
		t.Fatal("cancelled CAS accepted")
	}
}

func TestFileCommandLeaseRejectsSubstitutionAndUnknownMarker(t *testing.T) {
	root, err := ownedfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	release, err := fileCommandLease(root, "stop-old-panel")
	if err != nil {
		t.Fatal(err)
	}
	if next, err := fileCommandLease(root, "stop-old-panel"); err == nil {
		next()
		t.Fatal("parallel command writer admitted")
	}
	release()
	if err := root.WriteAtomic(".stop-old-panel.lock", []byte("foreign lock"), 0600); err != nil {
		t.Fatal(err)
	}
	if next, err := fileCommandLease(root, "stop-old-panel"); err == nil {
		next()
		t.Fatal("unknown marker accepted")
	}
}
