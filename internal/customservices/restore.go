package customservices

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// RestoreTarget opens an existing registry before any Manager cache is loaded.
// The path comes from trusted startup configuration, never from an archive.
// Ordinary Manager writers share the same per-file OS lease.
type RestoreTarget struct{ file *restorejournal.FileTarget }

func (*RestoreTarget) String() string   { return "[customservices recovery target]" }
func (*RestoreTarget) GoString() string { return "[customservices recovery target]" }

func OpenRestoreTarget(path string) (*RestoreTarget, error) {
	file, err := restorejournal.OpenFileTarget(path)
	if err != nil {
		return nil, err
	}
	target := &RestoreTarget{file: file}
	if _, err := target.Read(context.Background()); err != nil {
		_ = file.Close()
		return nil, err
	}
	return target, nil
}

func (t *RestoreTarget) Binding() string {
	hash := sha256.Sum256([]byte("customservices-schema-1\x00" + t.file.Binding()))
	return hex.EncodeToString(hash[:])
}
func (t *RestoreTarget) Close() error { return t.file.Close() }

func validRestoreImage(image restorejournal.Image) bool {
	if !image.Exists || len(image.Data) > restorejournal.MaxImageBytes {
		return false
	}
	_, err := decodeDocument(image.Data)
	return err == nil
}

func (t *RestoreTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	image, err := t.file.Read(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	if !validRestoreImage(image) {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return image, nil
}

func (t *RestoreTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if !validRestoreImage(before) || !validRestoreImage(after) {
		return restorejournal.ErrInvalid
	}
	return t.file.CompareAndSwap(ctx, before, after)
}

// MergeImage uses the ordinary import validation/merge without writing the file.
// Full archive validation and cross-registry checks remain the coordinator's job.
func (t *RestoreTarget) MergeImage(ctx context.Context, in []catalog.Service, reserved map[string]bool, allowUpdates bool) (restorejournal.Image, error) {
	image, err := t.Read(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	current, _ := decodeDocument(image.Data)
	result, err := mergeServices(current, in, reserved, allowUpdates)
	if err != nil {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	data, err := json.MarshalIndent(document{Schema: 1, Services: result}, "", "  ")
	if err != nil || len(data) > restorejournal.MaxImageBytes {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return restorejournal.Image{Exists: true, Data: data}, nil
}

// RestoreSession owns the Manager mutex AND its file lease for a bounded
// transaction. Never hold it over user interaction. Close after the coordinator
// has handled the journal outcome, before resuming ordinary operations.
type RestoreSession struct {
	mu      sync.Mutex
	target  *RestoreTarget
	manager *Manager
	closed  bool
}

func (*RestoreSession) String() string   { return "[customservices restore session]" }
func (*RestoreSession) GoString() string { return "[customservices restore session]" }

func (m *Manager) BeginRestore(ctx context.Context) (*RestoreSession, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if !m.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	keep := false
	defer func() {
		if !keep {
			m.mu.Unlock()
		}
	}()
	if m.writeUncertain {
		return nil, restorejournal.ErrRecovery
	}
	target, err := OpenRestoreTarget(m.path)
	if err != nil {
		return nil, err
	}
	image, err := target.Read(ctx)
	if err != nil || image.Exists != m.diskImage.Exists || !bytes.Equal(image.Data, m.diskImage.Data) {
		_ = target.Close()
		if err != nil {
			return nil, err
		}
		return nil, restorejournal.ErrConflict
	}
	keep = true
	return &RestoreSession{target: target, manager: m}, nil
}
func (s *RestoreSession) Read(ctx context.Context) (restorejournal.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	return s.target.Read(ctx)
}
func (s *RestoreSession) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return restorejournal.ErrUnavailable
	}
	return s.target.CompareAndSwap(ctx, before, after)
}
func (s *RestoreSession) MergeImage(ctx context.Context, in []catalog.Service, reserved map[string]bool, allowUpdates bool) (restorejournal.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	return s.target.MergeImage(ctx, in, reserved, allowUpdates)
}
func (s *RestoreSession) Binding() string { return s.target.Binding() }

func (s *RestoreSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	defer s.manager.mu.Unlock()
	defer s.target.Close()
	image, err := s.target.Read(context.Background())
	if err != nil {
		s.manager.writeUncertain = true
		return restorejournal.ErrRecovery
	}
	stored, err := decodeDocument(image.Data)
	if err != nil {
		s.manager.writeUncertain = true
		return restorejournal.ErrRecovery
	}
	s.manager.services = stored
	s.manager.diskImage = image
	return nil
}
