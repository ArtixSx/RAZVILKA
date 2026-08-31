package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// RestoreTarget is the typed adapter for config.json. It may be opened BEFORE
// config.Load during future startup recovery; it does not start/change routes.
// Every new config Store writer shares its per-file OS lease. Old binaries and
// unrelated direct filesystem writers do not participate in this protocol.
type RestoreTarget struct{ file *restorejournal.FileTarget }

func (*RestoreTarget) String() string   { return "[configuration recovery target]" }
func (*RestoreTarget) GoString() string { return "[configuration recovery target]" }

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
	hash := sha256.Sum256([]byte("config-schema-1\x00" + t.file.Binding()))
	return hex.EncodeToString(hash[:])
}

// RestoreBinding verifies a session against a trusted startup path, without I/O.
func RestoreBinding(path string) (string, error) {
	binding, err := restorejournal.FileBinding(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte("config-schema-1\x00" + binding))
	return hex.EncodeToString(hash[:]), nil
}

func (t *RestoreTarget) Close() error { return t.file.Close() }

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

func validRestoreImage(image restorejournal.Image) bool {
	if !image.Exists || len(image.Data) > restorejournal.MaxImageBytes {
		return false
	}
	_, _, err := InspectBytes(image.Data)
	return err == nil
}

// DraftImage changes only desired services and their revision. A caller still
// must perform the full archive/service validation before passing the result
// to the journal. No applied routes, credentials, listen address or gate change.
func (t *RestoreTarget) DraftImage(ctx context.Context, states map[string]ServiceState) (restorejournal.Image, error) {
	before, err := t.Read(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	cfg, _, _ := InspectBytes(before.Data)
	services := make(map[string]ServiceState, len(states))
	for id, state := range states {
		sources, err := NormalizeSources(state.Sources)
		if err != nil {
			return restorejournal.Image{}, restorejournal.ErrInvalid
		}
		state.Sources = sources
		services[id] = normalizeState(state)
	}
	cfg.Services = services
	cfg.Revision++
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil || len(data) > restorejournal.MaxImageBytes {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return restorejournal.Image{Exists: true, Data: data}, nil
}

// RestoreSession additionally holds this Store's mutex for a complete journal
// transaction. Other in-process calls wait; other Store/process writers fail
// their OS lease without touching the file. Never hold it over user interaction.
// Close must happen after the coordinator has handled the journal outcome.
type RestoreSession struct {
	mu     sync.Mutex
	target *RestoreTarget
	store  *Store
	closed bool
}

func (*RestoreSession) String() string   { return "[configuration restore session]" }
func (*RestoreSession) GoString() string { return "[configuration restore session]" }

func (s *Store) BeginRestore(ctx context.Context) (*RestoreSession, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if !s.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	keep := false
	defer func() {
		if !keep {
			s.mu.Unlock()
		}
	}()
	if s.writeUncertain {
		return nil, restorejournal.ErrRecovery
	}
	target, err := OpenRestoreTarget(s.path)
	if err != nil {
		return nil, err
	}
	image, err := target.Read(ctx)
	if err != nil || image.Exists != s.diskImage.Exists || !bytes.Equal(image.Data, s.diskImage.Data) {
		_ = target.Close()
		if err != nil {
			return nil, err
		}
		return nil, restorejournal.ErrConflict
	}
	keep = true
	return &RestoreSession{target: target, store: s}, nil
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

func (s *RestoreSession) DraftImage(ctx context.Context, states map[string]ServiceState) (restorejournal.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	return s.target.DraftImage(ctx, states)
}

func (s *RestoreSession) Binding() string { return s.target.Binding() }

func (s *RestoreSession) Close() (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	defer s.store.mu.Unlock()
	defer func() {
		if s.target.Close() != nil {
			s.store.writeUncertain = true
			result = restorejournal.ErrRecovery
		}
	}()
	image, err := s.target.Read(context.Background())
	if err != nil {
		s.store.writeUncertain = true
		return restorejournal.ErrRecovery
	}
	cfg, _, err := InspectBytes(image.Data)
	if err != nil {
		s.store.writeUncertain = true
		return restorejournal.ErrRecovery
	}
	s.store.cfg, s.store.diskImage = cfg, image
	return nil
}
