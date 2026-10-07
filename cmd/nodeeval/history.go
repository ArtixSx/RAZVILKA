package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type workspace struct {
	path, storePath string
	root            *ownedfs.Root
	info, storeInfo os.FileInfo
	fresh           *nodestore.Store
}

func pathsOverlap(a, b string) bool {
	if runtime.GOOS == "windows" {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	inside := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return inside(a, b) || inside(b, a)
}

// Resolve existing parents before creating anything: a symlink alias must not
// put checker/report writes into the supposedly read-only store hierarchy.
func separatedExistingStore(root, store string) bool {
	parent, err := filepath.EvalSymlinks(filepath.Dir(root))
	if err != nil {
		return false
	}
	actualStore, err := filepath.EvalSymlinks(store)
	return err == nil && !pathsOverlap(filepath.Join(parent, filepath.Base(root)), actualStore)
}

func newWorkspace(path string) (*workspace, error) {
	if !absoluteClean(path) || os.Mkdir(path, 0700) != nil {
		return nil, errors.New("workspace")
	}
	info, err := os.Lstat(path)
	if err != nil || !privateDirectory(info) || !os.SameFile(info, info) {
		return nil, errors.New("workspace")
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, errors.New("workspace")
	}
	return &workspace{path: path, root: root, info: info}, nil
}

func privateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (runtime.GOOS == "windows" || info.Mode().Perm()&0077 == 0)
}

func samePrivateDirectory(path string, held os.FileInfo) bool {
	info, err := os.Lstat(path)
	return err == nil && privateDirectory(info) && held != nil && os.SameFile(held, info)
}

func (w *workspace) Close() error { return w.root.Close() }

func (w *workspace) createStore() (*nodestore.Store, error) {
	if w.storeInfo != nil || !samePrivateDirectory(w.path, w.info) || w.root.MkdirAll("store", 0700) != nil {
		return nil, errors.New("isolated store")
	}
	w.storePath = filepath.Join(w.path, "store")
	info, err := os.Lstat(w.storePath)
	if err != nil || !privateDirectory(info) || !os.SameFile(info, info) {
		return nil, errors.New("isolated store")
	}
	w.storeInfo = info
	store, err := nodestore.Open(w.storePath)
	if err != nil {
		return nil, errors.New("isolated store")
	}
	w.fresh = store
	return store, nil
}

// Constructed only for this invocation's newly created store; there is no
// supplied store pointer/path that could redirect this grant into live history.
// No installed-controller, downgrade, restore or RecordCheck authority is given.
func (w *workspace) historyAdmission(ctx context.Context) (func(context.Context, int) error, error) {
	if ctx == nil || ctx.Err() != nil || w == nil || w.fresh == nil || w.storeInfo == nil || !samePrivateDirectory(w.path, w.info) || !samePrivateDirectory(w.storePath, w.storeInfo) {
		return nil, errors.New("isolated admission")
	}
	snapshot, err := w.fresh.Snapshot(ctx, time.Now())
	if err != nil || snapshot.Generation != 0 || len(snapshot.Nodes) != 0 || len(snapshot.Sources) != 0 {
		return nil, errors.New("isolated admission")
	}
	invocation := ctx
	return func(ctx context.Context, wanted int) error {
		if invocation.Err() != nil || ctx == nil || ctx.Err() != nil || wanted < 1 || wanted > nodestore.ExactHistoryReadVersion ||
			!samePrivateDirectory(w.path, w.info) || !samePrivateDirectory(w.storePath, w.storeInfo) {
			return errors.New("isolated admission")
		}
		// Use the actual typed reader, including unchecked XHTTP, before every
		// feed publication; unsupported/future/corrupt state is never reader1.
		required, err := w.fresh.RequiredHistoryReadVersion(ctx)
		if err != nil || required < 1 || required > nodestore.ExactHistoryReadVersion ||
			!samePrivateDirectory(w.path, w.info) || !samePrivateDirectory(w.storePath, w.storeInfo) || ctx.Err() != nil || invocation.Err() != nil {
			return errors.New("isolated admission")
		}
		return nil
	}, nil
}

func (w *workspace) reportFile() (*os.File, error) {
	if !samePrivateDirectory(w.path, w.info) {
		return nil, errors.New("report")
	}
	return w.root.OpenFile("results.jsonl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
