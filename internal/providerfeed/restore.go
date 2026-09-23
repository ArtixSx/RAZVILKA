package providerfeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// PrivateSnapshot belongs exclusively inside the encrypted backup payload.
type PrivateSnapshot struct {
	Content json.RawMessage `json:"content"`
	SHA256  string          `json:"sha256"`
}

func (PrivateSnapshot) String() string   { return "[private subscriptions snapshot]" }
func (PrivateSnapshot) GoString() string { return "[private subscriptions snapshot]" }
func ValidatePrivateSnapshot(in PrivateSnapshot) error {
	hash := sha256.Sum256(in.Content)
	if in.SHA256 != hex.EncodeToString(hash[:]) {
		return restorejournal.ErrInvalid
	}
	if _, err := decodeDocument(restorejournal.Image{Exists: true, Data: in.Content}); err != nil {
		return restorejournal.ErrInvalid
	}
	return nil
}
func ReviewPrivateSnapshot(in PrivateSnapshot) (int, error) {
	if ValidatePrivateSnapshot(in) != nil {
		return 0, restorejournal.ErrInvalid
	}
	doc, _ := decodeDocument(restorejournal.Image{Exists: true, Data: in.Content})
	return len(doc.Sources), nil
}
func (m *Manager) ExportPrivateIfPresent(ctx context.Context) (*PrivateSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storage == nil {
		return nil, nil
	}
	if m.closed || m.fenced {
		return nil, ErrStore
	}
	image, err := m.storage.target.Read(ctx)
	if err != nil {
		return nil, ErrStore
	}
	if !image.Exists {
		return nil, nil
	}
	if _, err := decodeDocument(image); err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if json.Compact(&compact, image.Data) != nil {
		return nil, ErrStore
	}
	data := bytes.Clone(compact.Bytes())
	hash := sha256.Sum256(data)
	return &PrivateSnapshot{Content: data, SHA256: hex.EncodeToString(hash[:])}, nil
}
func RestoreBinding(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", restorejournal.ErrInvalid
	}
	binding, err := restorejournal.FileBinding(filepath.Join(path, FileName))
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte("subscriptions-schema-1\x00" + binding))
	return hex.EncodeToString(hash[:]), nil
}

type RestoreTarget struct {
	mu          sync.Mutex
	manager     *Manager
	closed      bool
	ownsManager bool
	binding     string
}

func (t *RestoreTarget) Binding() string { return t.binding }
func OpenRestoreTarget(path string) (*RestoreTarget, error) {
	m, err := Open(nil, path)
	if err != nil {
		return nil, err
	}
	t, err := m.BeginRestore(context.Background())
	if err != nil {
		m.Close()
		return nil, err
	}
	t.ownsManager = true
	return t, nil
}
func (m *Manager) BeginRestore(ctx context.Context) (*RestoreTarget, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if !m.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	if m.storage == nil || m.closed || m.fenced {
		m.mu.Unlock()
		return nil, ErrStore
	}
	if _, err := m.storage.target.Read(ctx); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	binding, err := RestoreBinding(m.storage.path)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	m.restoreGeneration++
	return &RestoreTarget{manager: m, binding: binding}, nil
}
func (t *RestoreTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	return t.manager.storage.target.Read(ctx)
}
func (t *RestoreTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.ErrUnavailable
	}
	if _, err := decodeDocument(before); err != nil {
		return err
	}
	if _, err := decodeDocument(after); err != nil {
		return err
	}
	return t.manager.storage.target.CompareAndSwap(ctx, before, after)
}
func (t *RestoreTarget) MergeImage(ctx context.Context, in PrivateSnapshot) (restorejournal.Image, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	if ValidatePrivateSnapshot(in) != nil {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	before, err := t.manager.storage.target.Read(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	current, err := decodeDocument(before)
	if err != nil {
		return restorejournal.Image{}, err
	}
	imported, _ := decodeDocument(restorejournal.Image{Exists: true, Data: in.Content})
	if current.Revision == ^uint64(0) {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	current.Revision++
	seen := map[string]bool{}
	for _, feed := range current.Sources {
		seen[feed.ID] = true
	}
	for _, feed := range imported.Sources {
		if seen[feed.ID] {
			continue
		} // Preserve current user settings and pauses.
		feed.Enabled = false
		feed.Failures = 0
		feed.Revision = current.Revision
		current.Sources = append(current.Sources, feed)
		s, _ := resolve(feed.Request)
		current.States = append(current.States, persistedState{State: State{SourceID: feed.ID, Name: feed.Name, URL: redacted(s.url), Format: s.format, Status: "saved", Saved: true, Limit: s.limit, RefreshIntervalMinutes: feed.RefreshIntervalMinutes, AcceptPartial: feed.Request.AcceptPartial, Revision: feed.Revision, NextRefreshAt: time.Time{}}})
	}
	if current.Countries == nil {
		current.Countries = map[string]string{}
	}
	for id, code := range imported.Countries {
		if current.Countries[id] == "" {
			current.Countries[id] = code
		}
	}
	data, err := json.Marshal(current)
	if err != nil {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	after := restorejournal.Image{Exists: true, Data: data}
	if _, err := decodeDocument(after); err != nil {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	return after, nil
}
func (t *RestoreTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	err := t.manager.reloadLocked(context.Background())
	if err != nil {
		t.manager.fenced = true
	}
	t.manager.mu.Unlock()
	if t.ownsManager {
		if e := t.manager.Close(); e != nil {
			err = e
		}
	}
	return err
}
