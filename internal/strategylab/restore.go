package strategylab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"sync"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// PrivateSnapshot belongs only in encrypted backups. []byte deliberately uses
// base64 JSON encoding: marshaling must not compact the authenticated file bytes.
type PrivateSnapshot struct {
	Schema  int    `json:"schema"`
	Content []byte `json:"content"`
	SHA256  string `json:"sha256"`
}

func (PrivateSnapshot) String() string   { return "[private StrategyLab snapshot]" }
func (PrivateSnapshot) GoString() string { return "[private StrategyLab snapshot]" }

func decodePrivateState(image restorejournal.Image) (State, error) {
	if !image.Exists {
		if len(image.Data) != 0 {
			return State{}, restorejournal.ErrInvalid
		}
		return emptyState(), nil
	}
	if len(image.Data) == 0 || len(image.Data) > restorejournal.MaxImageBytes || compatibilityJSONUnique(image.Data) != nil {
		return State{}, restorejournal.ErrInvalid
	}
	var state State
	d := json.NewDecoder(bytes.NewReader(image.Data))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil || d.Decode(new(any)) != io.EOF || !supportedStrategySchema(state.SchemaVersion) || len(state.Candidates) > 4096 || len(state.Evidence) > MaxEvidence || len(state.Selections) > 4096 || len(state.PackReceipts) > 4096 {
		return State{}, restorejournal.ErrInvalid
	}
	if supervisedStrategySchema(state.SchemaVersion) {
		return decodeCompatibilityState(image)
	}
	if state.CompatibilitySession != nil || state.CompatibilityFinalizing {
		return State{}, restorejournal.ErrInvalid
	}
	if state.Candidates == nil {
		state.Candidates = map[string]Candidate{}
	}
	if state.Selections == nil {
		state.Selections = map[string]Selection{}
	}
	return state, nil
}

func ValidatePrivateSnapshot(in PrivateSnapshot) error {
	h := sha256.Sum256(in.Content)
	if in.Schema != 1 || in.SHA256 != hex.EncodeToString(h[:]) {
		return restorejournal.ErrInvalid
	}
	_, err := decodePrivateState(restorejournal.Image{Exists: true, Data: in.Content})
	return err
}

func ReviewPrivateSnapshot(in PrivateSnapshot) (int, error) {
	if err := ValidatePrivateSnapshot(in); err != nil {
		return 0, err
	}
	s, _ := decodePrivateState(restorejournal.Image{Exists: true, Data: in.Content})
	return len(s.Candidates), nil
}

func (m *Manager) ExportPrivateIfPresent(ctx context.Context) (*PrivateSnapshot, error) {
	if !m.mu.TryRLock() {
		return nil, restorejournal.ErrBusy
	}
	defer m.mu.RUnlock()
	if m.Path == "" {
		return nil, nil
	}
	// Memory-only uncertainty cannot be represented honestly by the disk image.
	if m.nativeRunning || m.writeBlocked || m.compatibilityUnknown && !m.compatibilityRetainedUnknownOnDisk() {
		return nil, restorejournal.ErrRecovery
	}
	image, err := restorejournal.ReadFileImage(ctx, m.Path)
	if err != nil {
		return nil, err
	}
	if image.Exists != m.image.Exists || !bytes.Equal(image.Data, m.image.Data) {
		return nil, restorejournal.ErrConflict
	}
	if !image.Exists {
		return nil, nil
	}
	h := sha256.Sum256(image.Data)
	in := &PrivateSnapshot{Schema: 1, Content: bytes.Clone(image.Data), SHA256: hex.EncodeToString(h[:])}
	if err := ValidatePrivateSnapshot(*in); err != nil {
		return nil, err
	}
	return in, nil
}

func (m *Manager) compatibilityRetainedUnknownOnDisk() bool {
	state, err := decodePrivateState(m.image)
	if err != nil {
		return false
	}
	if state.SchemaVersion == compatibilityUnknownSchema || state.CompatibilityFinalizing || state.CompatibilitySession != nil && compatibilitySessionUnknown(*state.CompatibilitySession) {
		return true
	}
	for _, candidate := range state.Candidates {
		if candidate.Validation.QuiescenceUnknown {
			return true
		}
	}
	return false
}

func RestoreBinding(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", restorejournal.ErrInvalid
	}
	binding, err := restorejournal.FileBinding(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte("strategy-lab-private-v1\x00" + binding))
	return hex.EncodeToString(h[:]), nil
}

type RestoreTarget struct {
	mu      sync.Mutex
	manager *Manager
	file    *restorejournal.FileTarget
	binding string
	closed  bool
}

func (t *RestoreTarget) Binding() string { return t.binding }

func OpenRestoreTarget(path string) (*RestoreTarget, error) {
	m, err := New(path)
	if err != nil {
		return nil, err
	}
	return m.BeginRestore(context.Background())
}

func (m *Manager) BeginRestore(ctx context.Context) (*RestoreTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !m.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	fail := func(err error) (*RestoreTarget, error) { m.mu.Unlock(); return nil, err }
	if m.Path == "" || m.nativeRunning || m.writeBlocked {
		return fail(restorejournal.ErrRecovery)
	}
	file, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		return fail(err)
	}
	image, err := file.Read(ctx)
	if err != nil || image.Exists != m.image.Exists || !bytes.Equal(image.Data, m.image.Data) {
		file.Close()
		return fail(restorejournal.ErrConflict)
	}
	binding, err := RestoreBinding(m.Path)
	if err != nil {
		file.Close()
		return fail(err)
	}
	return &RestoreTarget{manager: m, file: file, binding: binding}, nil
}

func (t *RestoreTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	return t.file.Read(ctx)
}

func (t *RestoreTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.ErrUnavailable
	}
	if _, err := decodePrivateState(before); err != nil {
		return err
	}
	if _, err := decodePrivateState(after); err != nil {
		return err
	}
	return t.file.CompareAndSwap(ctx, before, after)
}

// RestoreImage preserves the archive unchanged but retires imported validation
// authority. A real validator must assign the next generation; historical
// evidence is never rebound to that generation. Unknown destinations cannot be
// replaced, and native supervised ownership cannot be reconstructed by import.
func (t *RestoreTarget) RestoreImage(ctx context.Context, in PrivateSnapshot) (restorejournal.Image, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	if err := ValidatePrivateSnapshot(in); err != nil {
		return restorejournal.Image{}, err
	}
	if t.manager.compatibilityUnknownLocked() {
		return restorejournal.Image{}, ErrCompatibilityQuiescenceUnknown
	}
	current, err := t.file.Read(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	state, err := decodePrivateState(current)
	if err != nil {
		return restorejournal.Image{}, err
	}
	if state.SchemaVersion == compatibilityUnknownSchema || state.CompatibilityFinalizing || state.CompatibilitySession != nil {
		return restorejournal.Image{}, ErrCompatibilityQuiescenceUnknown
	}
	imported, err := decodePrivateState(restorejournal.Image{Exists: true, Data: in.Content})
	if err != nil {
		return restorejournal.Image{}, err
	}
	if supervisedStrategySchema(imported.SchemaVersion) {
		return restorejournal.Image{}, ErrCompatibilityQuiescenceUnknown
	}
	for id, candidate := range imported.Candidates {
		candidate.Validation.OK = false
		candidate.Validation.Native = false
		candidate.Validation.Code = "RESTORED_REVALIDATION_REQUIRED"
		candidate.Validation.Output = "Restored history requires native validation in the current runtime"
		imported.Candidates[id] = candidate
	}
	data, err := json.MarshalIndent(imported, "", "  ")
	if err != nil {
		return restorejournal.Image{}, err
	}
	after := restorejournal.Image{Exists: true, Data: append(data, '\n')}
	if _, err := decodePrivateState(after); err != nil {
		return restorejournal.Image{}, err
	}
	return after, nil
}

// MergeImage is the common private-restore planner entry point. StrategyLab is
// restored as one CAS image rather than combining unrelated generations.
func (t *RestoreTarget) MergeImage(ctx context.Context, in PrivateSnapshot) (restorejournal.Image, error) {
	return t.RestoreImage(ctx, in)
}

func (t *RestoreTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	image, err := t.file.Read(context.Background())
	if err == nil {
		var state State
		state, err = decodePrivateState(image)
		if err == nil {
			t.manager.state, t.manager.image = state, image
		}
	}
	if err != nil {
		t.manager.writeBlocked, t.manager.compatibilityUnknown = true, true
	}
	closeErr := t.file.Close()
	if closeErr != nil {
		t.manager.writeBlocked, t.manager.compatibilityUnknown = true, true
	}
	t.manager.mu.Unlock()
	if err != nil {
		return err
	}
	return closeErr
}
