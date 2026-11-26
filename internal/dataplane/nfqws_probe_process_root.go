package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Retained before handing the original per-file writer to the helper. The
// writer-v1 marker FD and actual directory must stay the SAME across Wait,
// terminal ACK and cleanup. A safe replacement with equal bytes is foreign.
type nfqwsProbeProcessRoot struct {
	mu          sync.Mutex
	self        *nfqwsProbeProcessRoot
	path        string
	root        *ownedfs.Root
	anchor      os.FileInfo
	marker      *os.File
	markerInfo  os.FileInfo
	markerName  string
	markerBytes []byte
	closed      bool
	closeErr    error
}

func newNFQWSProbeProcessRoot(ctx context.Context, path string, target *restorejournal.FileTarget) (*nfqwsProbeProcessRoot, error) {
	if target == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrNFQWSManagedProcessUnknown
	}
	r := &nfqwsProbeProcessRoot{path: path}
	r.self = r
	var err error
	r.root, r.anchor, err = openNetworkPolicyObservationRoot(path)
	if err != nil {
		return nil, err
	}
	actual, err := target.ParentIdentity()
	if err != nil || !os.SameFile(r.anchor, actual) {
		_ = r.close()
		return nil, ErrNFQWSManagedProcessUnknown
	}
	// This is the current restorejournal per-filename writer-v1 namespace;
	// a future marker protocol must fail closed until explicitly supported.
	key := sha256.Sum256([]byte(nfqws2LeaseFile))
	hash := hex.EncodeToString(key[:])
	r.markerName = ".state-" + hash + ".lock"
	r.markerBytes = []byte("RAZVILKA state file writer v1 " + hash + "\n")
	r.marker, err = executionHistoryOpen(r.root, r.markerName) // NONBLOCK|NOFOLLOW; fstat rejects FIFO/device swaps.
	if err == nil {
		r.markerInfo, err = r.marker.Stat()
	}
	if err == nil {
		err = r.matchesTarget(ctx, target)
	}
	if err != nil {
		return nil, errors.Join(err, r.close())
	}
	return r, nil
}

func (r *nfqwsProbeProcessRoot) current(ctx context.Context) error {
	if r == nil || r.self != r || ctx == nil || ctx.Err() != nil {
		return ErrNFQWSManagedProcessUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.root == nil || r.marker == nil || r.anchor == nil || r.markerInfo == nil {
		return ErrNFQWSManagedProcessUnknown
	}
	info, err := os.Lstat(r.path)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(r.anchor, info) {
		return ErrNFQWSManagedProcessUnknown
	}
	held, err := r.root.RootInfo()
	if err != nil || !os.SameFile(held, r.anchor) {
		return ErrNFQWSManagedProcessUnknown
	}
	marker, err := r.marker.Stat()
	named, e2 := r.root.Stat(r.markerName)
	if err != nil || e2 != nil || !validNetworkPolicyReceiptFile(marker) || marker.Mode().Perm()&077 != 0 || !os.SameFile(marker, r.markerInfo) || !os.SameFile(marker, named) || marker.Size() != int64(len(r.markerBytes)) {
		return ErrNFQWSManagedProcessUnknown
	}
	data := make([]byte, len(r.markerBytes))
	n, err := r.marker.ReadAt(data, 0)
	if err != nil || n != len(data) || !bytes.Equal(data, r.markerBytes) {
		return ErrNFQWSManagedProcessUnknown
	}
	closing, err := r.root.Stat(r.markerName)
	parent, e2 := os.Lstat(r.path)
	if err != nil || e2 != nil || !os.SameFile(closing, r.markerInfo) || !os.SameFile(parent, r.anchor) || !networkPolicyPrivateDirectory(parent) {
		return ErrNFQWSManagedProcessUnknown
	}
	return ctx.Err()
}

func (r *nfqwsProbeProcessRoot) matchesTarget(ctx context.Context, target *restorejournal.FileTarget) error {
	if err := r.current(ctx); err != nil {
		return err
	}
	actual, err := target.ParentIdentity()
	if err != nil || !os.SameFile(actual, r.anchor) {
		return ErrNFQWSManagedProcessUnknown
	}
	return r.current(ctx)
}

func (r *nfqwsProbeProcessRoot) close() error {
	if r == nil || r.self != r {
		return ErrNFQWSManagedProcessUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	if r.marker != nil {
		r.closeErr = errors.Join(r.closeErr, r.marker.Close())
	}
	if r.root != nil {
		r.closeErr = errors.Join(r.closeErr, r.root.Close())
	}
	return r.closeErr
}
