package providerfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/publicfetch"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const (
	FileName              = "subscriptions.private.json"
	MaxStorageBytes       = 256 << 10
	DefaultRefreshMinutes = 360
	MinRefreshMinutes     = 15
	MaxRefreshMinutes     = 7 * 24 * 60
)

// SaveRequest is private: a subscription token can appear anywhere in URL.
type SaveRequest struct {
	Request
	Name                   string `json:"name,omitempty"`
	Enabled                bool   `json:"enabled"`
	RefreshIntervalMinutes int    `json:"refresh_interval_minutes,omitempty"`
	Revision               uint64 `json:"revision,omitempty"`
}

func (SaveRequest) String() string   { return "[private saved feed request]" }
func (SaveRequest) GoString() string { return "[private saved feed request]" }

type subscription struct {
	ID                     string  `json:"id"`
	Request                Request `json:"request"`
	Name                   string  `json:"name"`
	Enabled                bool    `json:"enabled"`
	RefreshIntervalMinutes int     `json:"refresh_interval_minutes"`
	Revision               uint64  `json:"revision"`
	Failures               int     `json:"failures"`
}
type persistedState struct {
	State    State  `json:"state"`
	Identity string `json:"identity,omitempty"`
	ETag     string `json:"etag,omitempty"`
	Modified string `json:"modified,omitempty"`
}
type document struct {
	Schema    int               `json:"schema"`
	Owner     string            `json:"owner"`
	Revision  uint64            `json:"revision"`
	Sources   []subscription    `json:"sources"`
	States    []persistedState  `json:"states"`
	Countries map[string]string `json:"countries,omitempty"`
}

func (document) String() string   { return "[private subscriptions document]" }
func (document) GoString() string { return "[private subscriptions document]" }

type storage struct {
	target *restorejournal.FileTarget
	doc    document
	image  restorejournal.Image
	path   string
}

// Open creates no subscription or network request. It leases a single atomic
// private image in a trusted existing 0700 directory for the process lifetime.
func Open(nodes *nodestore.Store, path string) (*Manager, error) {
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrStore
	}
	if file, statErr := os.Lstat(filepath.Join(path, FileName)); statErr == nil {
		if !file.Mode().IsRegular() || runtime.GOOS != "windows" && file.Mode().Perm()&0077 != 0 {
			return nil, ErrStore
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, ErrStore
	}
	target, err := restorejournal.OpenFileTarget(filepath.Join(path, FileName))
	if err != nil {
		return nil, ErrStore
	}
	m := New(nodes)
	m.storage = &storage{target: target, path: path}
	if err := m.reloadLocked(context.Background()); err != nil {
		target.Close()
		return nil, err
	}
	return m, nil
}

func (m *Manager) Persistent() bool { return m != nil && m.storage != nil }
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.storage != nil {
		return m.storage.target.Close()
	}
	return nil
}

func decodeDocument(image restorejournal.Image) (document, error) {
	if !image.Exists {
		if len(image.Data) != 0 {
			return document{}, ErrStore
		}
		return document{Schema: 1, Owner: "razvilka-subscriptions", Sources: []subscription{}, States: []persistedState{}}, nil
	}
	if len(image.Data) == 0 || len(image.Data) > MaxStorageBytes || !validJSONShape(image.Data) {
		return document{}, ErrStore
	}
	var doc document
	decoder := json.NewDecoder(bytes.NewReader(image.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || doc.Schema != 1 || doc.Owner != "razvilka-subscriptions" || doc.Revision == 0 || len(doc.Sources) > MaxFeeds || len(doc.States) != len(doc.Sources) {
		return document{}, ErrStore
	}
	seen := map[string]bool{}
	if len(doc.Countries) > nodestore.MaxNodes {
		return document{}, ErrStore
	}
	for id, code := range doc.Countries {
		if len(id) != 69 || !strings.HasPrefix(id, "node-") || strings.Trim(id[5:], "0123456789abcdef") != "" || !validCountry(code) {
			return document{}, ErrStore
		}
	}
	for _, feed := range doc.Sources {
		s, err := resolve(feed.Request)
		if err != nil || s.id != feed.ID || seen[feed.ID] || !validName(feed.Name) || feed.Revision == 0 || feed.Revision > doc.Revision || feed.RefreshIntervalMinutes < MinRefreshMinutes || feed.RefreshIntervalMinutes > MaxRefreshMinutes || feed.Failures < 0 || feed.Failures > 16 {
			return document{}, ErrStore
		}
		seen[feed.ID] = true
	}
	for _, cached := range doc.States {
		state := cached.State
		if !seen[state.SourceID] || cached.ETag != safeValidator(cached.ETag) || cached.Modified != safeValidator(cached.Modified) || len(cached.Identity) > 80 || state.Imported < 0 || state.Imported > MaxCandidates || len(state.Name) > 256 || len(state.URL) > 512 || len(state.Status) > 32 || len(state.ErrorCode) > 32 {
			return document{}, ErrStore
		}
		delete(seen, state.SourceID)
	}
	return doc, nil
}

func (m *Manager) reloadLocked(ctx context.Context) error {
	if m.storage == nil || m.closed {
		return ErrStore
	}
	image, err := m.storage.target.Read(ctx)
	if err != nil {
		return ErrStore
	}
	doc, err := decodeDocument(image)
	if err != nil {
		return err
	}
	m.storage.doc, m.storage.image = doc, image
	m.states = map[string]cache{}
	for _, c := range doc.States {
		m.states[c.State.SourceID] = cache{state: c.State, identity: c.Identity, etag: c.ETag, modified: c.Modified}
	}
	for _, feed := range doc.Sources {
		m.decorateSavedLocked(feed)
	}
	return nil
}

func (m *Manager) persistLocked(ctx context.Context) error {
	if m.storage == nil || m.closed || m.fenced {
		return ErrStore
	}
	doc := m.storage.doc
	if doc.Revision == ^uint64(0) {
		return ErrStore
	}
	doc.Revision++
	doc.States = make([]persistedState, 0, len(doc.Sources))
	for _, feed := range doc.Sources {
		m.decorateSavedLocked(feed)
		c := m.states[feed.ID]
		doc.States = append(doc.States, persistedState{State: c.state, Identity: c.identity, ETag: c.etag, Modified: c.modified})
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > MaxStorageBytes {
		return ErrSize
	}
	after := restorejournal.Image{Exists: true, Data: data}
	if _, err := decodeDocument(after); err != nil {
		return err
	}
	if err := m.storage.target.CompareAndSwap(ctx, m.storage.image, after); err != nil {
		// Any write uncertainty fences this instance. Do not keep running a
		// schedule from memory that disagrees with the durable image.
		if !errors.Is(err, restorejournal.ErrAborted) {
			m.fenced = true
		}
		return ErrStore
	}
	m.storage.doc, m.storage.image = doc, after
	return nil
}

func validName(name string) bool {
	return utf8.ValidString(name) && strings.TrimSpace(name) == name && utf8.RuneCountInString(name) > 0 && utf8.RuneCountInString(name) <= 64 && strings.IndexFunc(name, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf) }) < 0
}

func (m *Manager) decorateSavedLocked(feed subscription) {
	c := m.states[feed.ID]
	s, _ := resolve(feed.Request)
	c.state.SourceID, c.state.Name, c.state.URL, c.state.Format = feed.ID, feed.Name, redacted(s.url), s.format
	c.state.Saved, c.state.Enabled, c.state.RefreshIntervalMinutes = true, feed.Enabled, feed.RefreshIntervalMinutes
	c.state.AcceptPartial, c.state.Limit, c.state.Revision = feed.Request.AcceptPartial, s.limit, feed.Revision
	if c.state.Status == "" {
		c.state.Status = "saved"
	}
	m.states[feed.ID] = c
}

func (m *Manager) sourceIndexLocked(id string) int {
	if m.storage != nil {
		for i, feed := range m.storage.doc.Sources {
			if feed.ID == id {
				return i
			}
		}
	}
	return -1
}
func (m *Manager) currentSourceLocked(s source) bool {
	if s.revision == 0 {
		return true
	}
	i := m.sourceIndexLocked(s.id)
	return i >= 0 && m.storage.doc.Sources[i].Revision == s.revision
}

// Save is independent of fetch success; importing candidates is a separate
// operation. URL identity is immutable so a feed cannot inherit another URL's
// validators or provenance. Use a new saved source to change its URL.
func (m *Manager) Save(ctx context.Context, id string, request SaveRequest) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return State{}, ctx.Err()
	}
	undo := m.checkpointLocked()
	state, err := m.saveLocked(ctx, id, request)
	if err != nil && !m.fenced {
		undo()
	}
	return state, err
}

func (m *Manager) checkpointLocked() func() {
	if m.storage == nil {
		return func() {}
	}
	data, _ := json.Marshal(m.storage.doc)
	states := map[string]cache{}
	for id, c := range m.states {
		states[id] = c
	}
	return func() { var doc document; _ = json.Unmarshal(data, &doc); m.storage.doc = doc; m.states = states }
}

func (m *Manager) saveLocked(ctx context.Context, id string, request SaveRequest) (State, error) {
	if m.storage == nil || m.closed || m.fenced {
		return State{}, ErrStore
	}
	i := m.sourceIndexLocked(id)
	if id != "" && i < 0 {
		return State{}, ErrNotFound
	}
	if i >= 0 {
		old := m.storage.doc.Sources[i]
		if request.Revision != old.Revision {
			return State{}, ErrConflict
		}
		if request.PresetID == "" && request.URL == "" {
			request.Request.PresetID, request.Request.URL, request.Request.Format = old.Request.PresetID, old.Request.URL, old.Request.Format
		}
		if request.Name == "" {
			request.Name = old.Name
		}
		if request.Limit == 0 {
			request.Limit = old.Request.Limit
		}
		if request.RefreshIntervalMinutes == 0 {
			request.RefreshIntervalMinutes = old.RefreshIntervalMinutes
		}
	} else if request.Revision != 0 {
		return State{}, ErrConflict
	}
	s, err := resolve(request.Request)
	if err != nil || id != "" && id != s.id {
		return State{}, ErrRequest
	}
	if i < 0 && m.sourceIndexLocked(s.id) >= 0 {
		return State{}, ErrConflict
	}
	if request.RefreshIntervalMinutes == 0 {
		request.RefreshIntervalMinutes = DefaultRefreshMinutes
		for _, preset := range Builtins() {
			if preset.ID == request.PresetID {
				request.RefreshIntervalMinutes = preset.DefaultRefreshIntervalMinutes
				break
			}
		}
	}
	if request.Name == "" {
		request.Name = s.name
	}
	if !validName(request.Name) || request.RefreshIntervalMinutes < MinRefreshMinutes || request.RefreshIntervalMinutes > MaxRefreshMinutes || i < 0 && len(m.storage.doc.Sources) >= MaxFeeds {
		return State{}, ErrRequest
	}
	request.Request.Limit = s.limit
	feed := subscription{ID: s.id, Request: request.Request, Name: request.Name, Enabled: request.Enabled, RefreshIntervalMinutes: request.RefreshIntervalMinutes, Revision: m.storage.doc.Revision + 1}
	if i < 0 {
		m.storage.doc.Sources = append(m.storage.doc.Sources, feed)
	} else {
		m.storage.doc.Sources[i] = feed
	}
	c := m.states[s.id]
	if request.Enabled {
		c.state.NextRefreshAt = m.now().UTC().Add(time.Minute)
		if c.state.RetryAfterAt.After(c.state.NextRefreshAt) {
			c.state.NextRefreshAt = c.state.RetryAfterAt
		}
	} else {
		c.state.NextRefreshAt = time.Time{}
	}
	m.states[s.id] = c
	if err := m.persistLocked(ctx); err != nil {
		return State{}, err
	}
	return m.states[s.id].state, nil
}

func (m *Manager) Delete(ctx context.Context, id string, revision uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.storage == nil || m.closed || m.fenced {
		return ErrStore
	}
	i := m.sourceIndexLocked(id)
	if i < 0 {
		return ErrNotFound
	}
	if revision != m.storage.doc.Sources[i].Revision {
		return ErrConflict
	}
	undo := m.checkpointLocked()
	m.storage.doc.Sources = append(m.storage.doc.Sources[:i], m.storage.doc.Sources[i+1:]...)
	delete(m.states, id)
	err := m.persistLocked(ctx)
	if err != nil && !m.fenced {
		undo()
	}
	return err
}

func (m *Manager) Saved(id string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.fenced {
		return State{}, ErrStore
	}
	if m.sourceIndexLocked(id) < 0 {
		return State{}, ErrNotFound
	}
	return m.states[id].state, nil
}

func (m *Manager) SyncSaved(ctx context.Context, id string) (Result, error) {
	m.mu.Lock()
	i := m.sourceIndexLocked(id)
	if m.closed || m.fenced || i < 0 || m.nodes == nil {
		m.mu.Unlock()
		return Result{}, ErrNotFound
	}
	feed := m.storage.doc.Sources[i]
	s, err := resolve(feed.Request)
	s.revision = feed.Revision
	m.mu.Unlock()
	if err != nil {
		return Result{}, err
	}
	return m.sync(ctx, s, feed.Request.AcceptPartial)
}

func (m *Manager) completeSavedLocked(id string, cause error) {
	i := m.sourceIndexLocked(id)
	if i < 0 {
		return
	}
	feed := &m.storage.doc.Sources[i]
	if cause == nil {
		feed.Failures = 0
	} else if feed.Failures < 16 {
		feed.Failures++
	}
	c := m.states[id]
	delay := time.Duration(feed.RefreshIntervalMinutes) * time.Minute
	if cause != nil {
		delay = time.Duration(1<<min(feed.Failures, 6)) * time.Minute
		if delay < MinRefreshMinutes*time.Minute {
			delay = MinRefreshMinutes * time.Minute
		}
	}
	// Stable per-feed spread avoids synchronized repeated fetches on routers.
	delay += time.Duration([]byte(id)[len(id)-1]%30) * time.Second
	if feed.Enabled {
		c.state.NextRefreshAt = m.now().UTC().Add(delay)
		if c.state.RetryAfterAt.After(c.state.NextRefreshAt) {
			c.state.NextRefreshAt = c.state.RetryAfterAt
		}
	} else {
		c.state.NextRefreshAt = time.Time{}
	}
	m.states[id] = c
}

func (m *Manager) Due(now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storage == nil || m.closed || m.fenced {
		return nil
	}
	var ids []string
	for _, feed := range m.storage.doc.Sources {
		next := m.states[feed.ID].state.NextRefreshAt
		if feed.Enabled && !next.IsZero() && !now.Before(next) {
			ids = append(ids, feed.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := m.states[ids[i]].state.NextRefreshAt, m.states[ids[j]].state.NextRefreshAt
		if a.Equal(b) {
			return ids[i] < ids[j]
		}
		return a.Before(b)
	})
	return ids
}

// redacted is kept separate from private saved material so callers cannot
// accidentally serialize a request while constructing a public state.
func redacted(raw string) string { return publicfetch.RedactedURL(raw) }
