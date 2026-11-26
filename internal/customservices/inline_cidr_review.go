package customservices

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrInlineCIDRReview = errors.New("original custom inline CIDR definition unavailable or changed")

// InlineCIDRReview retains an actual Manager's complete published registry,
// original directory and file descriptor. Its metadata is a comparison, not
// source-refresh provenance, network authority or a runtime lifetime. App must
// independently retain its original Manager/catalog/control and operation.
type InlineCIDRReview struct {
	self     *InlineCIDRReview
	mu       sync.Mutex
	manager  *Manager
	path     string
	rootPath string
	name     string
	root     *ownedfs.Root
	rootInfo os.FileInfo
	file     *os.File
	fileInfo os.FileInfo
	image    []byte
	services []catalog.Service
	service  catalog.Service
	invalid  bool
	closed   bool
	closeErr error
}

func (*InlineCIDRReview) String() string   { return "[original custom inline CIDR review]" }
func (*InlineCIDRReview) GoString() string { return "[original custom inline CIDR review]" }

func inlineCIDRContext(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	_, finite := ctx.Deadline()
	return finite
}

// ReviewAppliedInlineCIDRs accepts only an exact service actually published by
// this Manager. No caller path, bytes, reader, source receipt or readiness flag
// can issue a review. The complete registry and descriptor closing reads must
// agree with the Manager's acknowledged disk image before publication.
func (m *Manager) ReviewAppliedInlineCIDRs(ctx context.Context, expected catalog.Service) (*InlineCIDRReview, error) {
	if m == nil || !inlineCIDRContext(ctx) || len(expected.Domains) != 0 || len(expected.CIDRs) == 0 || len(expected.SourceRefs) != 0 {
		return nil, ErrInlineCIDRReview
	}
	for _, value := range expected.CIDRs {
		p, err := netip.ParsePrefix(value)
		if err != nil || p != p.Masked() || p.Bits() == 0 || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return nil, ErrInlineCIDRReview
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	index := m.indexLocked(expected.ID)
	if m.writeUncertain || index < 0 || !reflect.DeepEqual(clone([]catalog.Service{expected}), clone([]catalog.Service{m.services[index]})) || !m.diskImage.Exists || len(m.diskImage.Data) == 0 || len(m.diskImage.Data) > restorejournal.MaxImageBytes {
		return nil, ErrInlineCIDRReview
	}
	path, err := filepath.Abs(m.path)
	if err != nil {
		return nil, ErrInlineCIDRReview
	}
	r := &InlineCIDRReview{manager: m, path: m.path, rootPath: filepath.Dir(path), name: filepath.Base(path), image: bytes.Clone(m.diskImage.Data), services: clone(m.services), service: clone([]catalog.Service{m.services[index]})[0]}
	r.self = r
	keep := false
	defer func() {
		if !keep {
			_ = r.Close()
		}
	}()
	r.root, err = ownedfs.Open(r.rootPath)
	if err != nil {
		return nil, ErrInlineCIDRReview
	}
	r.rootInfo, err = r.root.RootInfo()
	if err != nil || !inlineCIDRPrivate(r.rootInfo, true) {
		return nil, ErrInlineCIDRReview
	}
	r.file, err = r.root.OpenFile(r.name, os.O_RDONLY, 0)
	if err != nil {
		return nil, ErrInlineCIDRReview
	}
	r.fileInfo, err = r.file.Stat()
	if err != nil || !inlineCIDRPrivate(r.fileInfo, false) {
		return nil, ErrInlineCIDRReview
	}
	if err := r.currentLocked(ctx, m); err != nil {
		return nil, err
	}
	keep = true
	return r, nil
}

// Service returns detached immutable comparison metadata. Current under the
// same original App operation remains mandatory before every actual use.
func (r *InlineCIDRReview) Service() catalog.Service {
	if r == nil || r.self != r {
		return catalog.Service{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return clone([]catalog.Service{r.service})[0]
}

func (r *InlineCIDRReview) Current(ctx context.Context, original *Manager) error {
	if r == nil || r.self != r || original == nil || !inlineCIDRContext(ctx) {
		return ErrInlineCIDRReview
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.invalid || r.manager != original {
		return ErrInlineCIDRReview
	}
	original.mu.RLock()
	defer original.mu.RUnlock()
	if err := r.currentLocked(ctx, original); err != nil {
		r.invalid = true
		return err
	}
	return nil
}

// Caller holds the original Manager read lock and, after publication, r.mu.
func (r *InlineCIDRReview) currentLocked(ctx context.Context, original *Manager) error {
	if !inlineCIDRContext(ctx) || r.manager != original || original.path != r.path || original.writeUncertain || !original.diskImage.Exists || !bytes.Equal(original.diskImage.Data, r.image) || !reflect.DeepEqual(clone(original.services), r.services) || r.root == nil || r.file == nil {
		return ErrInlineCIDRReview
	}
	bookend := func() bool {
		directory, err := os.Lstat(r.rootPath)
		root, rootErr := r.root.RootInfo()
		held, heldErr := r.file.Stat()
		named, namedErr := r.root.Stat(r.name)
		return err == nil && rootErr == nil && heldErr == nil && namedErr == nil &&
			inlineCIDRSame(r.rootInfo, directory, true) && inlineCIDRSame(r.rootInfo, root, true) &&
			inlineCIDRSame(r.fileInfo, held, false) && inlineCIDRSame(r.fileInfo, named, false)
	}
	if !bookend() || r.fileInfo.Size() <= 0 || r.fileInfo.Size() > restorejournal.MaxImageBytes {
		return ErrInlineCIDRReview
	}
	data := make([]byte, int(r.fileInfo.Size()))
	defer clear(data)
	n, err := r.file.ReadAt(data, 0)
	if err != nil || n != len(data) || !bytes.Equal(data, r.image) || !bookend() || !inlineCIDRContext(ctx) {
		return ErrInlineCIDRReview
	}
	decoded, err := decodeDocument(data)
	if err != nil || !reflect.DeepEqual(decoded, r.services) {
		return ErrInlineCIDRReview
	}
	return nil
}

func inlineCIDRPrivate(info os.FileInfo, directory bool) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && (directory && info.IsDir() || !directory && info.Mode().IsRegular()) &&
		(runtime.GOOS == "windows" || info.Mode().Perm()&0077 == 0)
}

func inlineCIDRSame(original, current os.FileInfo, directory bool) bool {
	return inlineCIDRPrivate(original, directory) && inlineCIDRPrivate(current, directory) && os.SameFile(original, current) && original.Mode() == current.Mode() &&
		(directory || original.Size() == current.Size() && original.ModTime().Equal(current.ModTime()))
}

func (r *InlineCIDRReview) Close() error {
	if r == nil {
		return nil
	}
	if r.self != r {
		return ErrInlineCIDRReview
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	if r.file != nil && r.file.Close() != nil {
		r.closeErr = ErrInlineCIDRReview
	}
	if r.root != nil && r.root.Close() != nil {
		r.closeErr = ErrInlineCIDRReview
	}
	return r.closeErr
}
