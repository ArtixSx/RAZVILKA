// Package nodestore owns passive copies of imported nodes, never live routes.
package nodestore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var (
	ErrStore    = errors.New("node store unavailable or invalid")
	ErrBusy     = errors.New("node store is already open by another writer")
	ErrImport   = errors.New("node import rejected; existing data preserved")
	ErrPartial  = errors.New("partial node import requires explicit acceptance")
	ErrCapacity = errors.New("node store capacity reached")
	ErrRecovery = errors.New("node store commit uncertain; close and inspect before reopening")
	ErrNotFound = errors.New("node not found")
	ErrAlias    = errors.New("invalid node alias")
)

const (
	fileName     = "nodes.private.json"
	legacySchema = 1
	schema       = 2
	MaxNodes     = 512
	MaxSources   = 64
	maxBytes     = 4 << 20
	maxTTL       = 30 * 24 * time.Hour
)

var sourcePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

// Source deliberately contains no subscription URL/token or untrusted label.
// A future subscription adapter will keep that material in private storage.
type Source struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // manual, file, subscription, community, legacy
}

type Origin struct {
	SourceID   string    `json:"source_id"`
	ReceivedAt time.Time `json:"received_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Health is a public model, not an authority supplied by a source. This first
// storage version can only return not_checked; no health promotion API exists.
type Health struct {
	State string `json:"state"`
}

type Node struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Transport string    `json:"transport,omitempty"`
	TLS       bool      `json:"tls"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	State     string    `json:"state"`
	Trust     string    `json:"trust"`
	AddedAt   time.Time `json:"added_at"`
	Origins   []Origin  `json:"origins"`
	Health    Health    `json:"health"`
	Disabled  bool      `json:"disabled"`
}

type Snapshot struct {
	Generation uint64   `json:"generation"`
	Sources    []Source `json:"sources"`
	Nodes      []Node   `json:"nodes"`
}

// Metadata and credentials live in ONE atomic private envelope. SecretRef is
// internal, never a filesystem path, never an independently written file.
type storedNode struct {
	ID        string    `json:"id"`
	SecretRef string    `json:"secret_ref"`
	AddedAt   time.Time `json:"added_at"`
	Origins   []Origin  `json:"origins"`
	Alias     string    `json:"alias,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
}
type secret struct {
	Ref      string          `json:"ref"`
	Outbound json.RawMessage `json:"outbound"`
}
type document struct {
	Schema      int          `json:"schema"`
	Owner       string       `json:"owner"`
	Generation  uint64       `json:"generation"`
	IdentityKey []byte       `json:"identity_key"`
	Sources     []Source     `json:"sources"`
	Nodes       []storedNode `json:"nodes"`
	Secrets     []secret     `json:"secrets"`
}

func (document) String() string   { return "[private node document]" }
func (document) GoString() string { return "[private node document]" }
func (secret) String() string     { return "[private node material]" }
func (secret) GoString() string   { return "[private node material]" }

type Store struct {
	mu          sync.Mutex
	root        *ownedfs.Root
	target      restorejournal.Target
	closeTarget func() error
	closed      bool
	fenced      bool
	binding     string
}

func (*Store) String() string   { return "[private node store]" }
func (*Store) GoString() string { return "[private node store]" }

// Open requires an existing private directory. Its per-file OS lease remains
// held until Close. POSIX 0700/0600 is access control, not encryption against root.
// No directory, node file, migration or network operation is created implicitly.
func Open(path string) (*Store, error) {
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !info.IsDir() || !privateMode(info) {
		return nil, ErrStore
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, ErrStore
	}
	target, err := restorejournal.OpenFileTarget(filepath.Join(path, fileName))
	if err != nil {
		_ = root.Close()
		if errors.Is(err, restorejournal.ErrBusy) {
			return nil, ErrBusy
		}
		return nil, ErrStore
	}
	binding, err := RestoreBinding(path)
	if err != nil {
		_ = target.Close()
		_ = root.Close()
		return nil, ErrStore
	}
	s := &Store{root: root, target: target, closeTarget: target.Close, binding: binding}
	if _, _, err := s.load(context.Background()); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func privateMode(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.closeTarget()
	if s.root.Close() != nil || err != nil {
		return ErrStore
	}
	return nil
}

func (s *Store) load(ctx context.Context) (document, restorejournal.Image, error) {
	if s.closed {
		return document{}, restorejournal.Image{}, ErrStore
	}
	if s.fenced {
		return document{}, restorejournal.Image{}, ErrRecovery
	}
	if err := ctx.Err(); err != nil {
		return document{}, restorejournal.Image{}, err
	}
	if info, err := s.root.Stat(fileName); err == nil {
		if !info.Mode().IsRegular() || !privateMode(info) || info.Size() > maxBytes {
			return document{}, restorejournal.Image{}, ErrStore
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return document{}, restorejournal.Image{}, ErrStore
	}
	image, err := s.target.Read(ctx)
	if err != nil {
		return document{}, restorejournal.Image{}, ErrStore
	}
	if !image.Exists {
		return document{Schema: schema, Owner: "razvilka-nodes"}, image, nil
	}
	var doc document
	if len(image.Data) > maxBytes || decodeStrict(image.Data, &doc) != nil || validate(doc) != nil {
		return document{}, restorejournal.Image{}, ErrStore
	}
	// Schema 1 did not have user-controlled alias/disabled metadata. Upgrade is
	// in memory and is persisted only by the next explicit mutation/import.
	if doc.Schema == legacySchema {
		doc.Schema = schema
	}
	return doc, image, nil
}

// Import performs no I/O outside this store. Public sources always remain
// quarantined; refresh changes freshness only, not health or active bindings.
func (s *Store) Import(ctx context.Context, source Source, raw string, now time.Time, ttl time.Duration, acceptPartial bool) (Snapshot, error) {
	if !validSource(source) || now.IsZero() || ttl <= 0 || ttl > maxTTL {
		return Snapshot{}, ErrImport
	}
	now = now.UTC()
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	result, err := providerprofile.ParseProfile(raw)
	if err != nil {
		return Snapshot{}, ErrImport
	}
	if len(result.Preview.Rejected) > 0 && !acceptPartial {
		return Snapshot{}, ErrPartial
	}
	materials, err := extract(result.Config)
	if err != nil || len(materials) != result.Preview.NodeCount {
		return Snapshot{}, ErrImport
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, before, err := s.load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if len(doc.IdentityKey) == 0 {
		doc.IdentityKey = make([]byte, 32)
		_, _ = rand.Read(doc.IdentityKey)
	}
	found := false
	for _, existing := range doc.Sources {
		if existing.ID == source.ID {
			if existing.Kind != source.Kind {
				return Snapshot{}, ErrImport
			}
			found = true
		}
	}
	if !found {
		doc.Sources = append(doc.Sources, source)
	}
	for _, material := range materials {
		id := identity(doc.IdentityKey, material)
		index := -1
		for i := range doc.Nodes {
			if doc.Nodes[i].ID == id {
				index = i
				break
			}
		}
		if index < 0 {
			doc.Nodes = append(doc.Nodes, storedNode{ID: id, SecretRef: "secret-" + id, AddedAt: now})
			doc.Secrets = append(doc.Secrets, secret{Ref: "secret-" + id, Outbound: material})
			index = len(doc.Nodes) - 1
		}
		node := &doc.Nodes[index]
		if now.Before(node.AddedAt) {
			return Snapshot{}, ErrImport
		}
		origin := Origin{SourceID: source.ID, ReceivedAt: now, ExpiresAt: now.Add(ttl)}
		updated := false
		for i := range node.Origins {
			if node.Origins[i].SourceID == source.ID {
				if now.Before(node.Origins[i].ReceivedAt) {
					return Snapshot{}, ErrImport
				}
				node.Origins[i] = origin
				updated = true
			}
		}
		if !updated {
			node.Origins = append(node.Origins, origin)
		}
	}
	if len(doc.Nodes) > MaxNodes || len(doc.Sources) > MaxSources || doc.Generation == ^uint64(0) {
		return Snapshot{}, ErrCapacity
	}
	// A repeated copy with identical freshness is a real no-op, not a new
	// revision. No duplicate nodes or unnecessary flash writes.
	if before.Exists {
		candidate, err := json.Marshal(doc)
		if err == nil && bytes.Equal(candidate, before.Data) {
			return snapshot(doc, now), nil
		}
	}
	doc.Generation++
	if validate(doc) != nil {
		return Snapshot{}, ErrStore
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > maxBytes {
		return Snapshot{}, ErrCapacity
	}
	if err := s.target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: data}); err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) {
			s.fenced = true
			return Snapshot{}, ErrRecovery
		}
		return Snapshot{}, ErrStore
	}
	return snapshot(doc, now), nil
}

// CopyLegacyMain is explicit copy-only migration of supplied sing-box/main
// content. The caller retains the original file and rollback. Incomplete copies
// are refused; original routing/DNS/listeners are never stored as node material.
func (s *Store) CopyLegacyMain(ctx context.Context, raw string, now time.Time) (Snapshot, error) {
	return s.Import(ctx, Source{ID: "legacy-sing-box-main", Kind: "legacy"}, raw, now, maxTTL, false)
}

func (s *Store) Snapshot(ctx context.Context, now time.Time) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		return Snapshot{}, ErrStore
	}
	doc, _, err := s.load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot(doc, now.UTC()), nil
}

// SetAlias changes display metadata only. Identity, secret material, origins,
// health and any external engine configuration remain unchanged.
func (s *Store) SetAlias(ctx context.Context, id, alias string, now time.Time) (Snapshot, error) {
	if !validAlias(alias) {
		return Snapshot{}, ErrAlias
	}
	return s.mutate(ctx, id, now, func(doc *document, index int) (bool, error) {
		if doc.Nodes[index].Alias == alias {
			return false, nil
		}
		doc.Nodes[index].Alias = alias
		return true, nil
	})
}

// SetDisabled is fail-closed metadata. It never promotes health or edits a
// runtime; a future binding layer must reject disabled nodes independently.
func (s *Store) SetDisabled(ctx context.Context, id string, disabled bool, now time.Time) (Snapshot, error) {
	return s.mutate(ctx, id, now, func(doc *document, index int) (bool, error) {
		if doc.Nodes[index].Disabled == disabled {
			return false, nil
		}
		doc.Nodes[index].Disabled = disabled
		return true, nil
	})
}

// Delete removes one passive node and its secret atomically. It does not edit
// Sing-box, service bindings or a live route.
func (s *Store) Delete(ctx context.Context, id string, now time.Time) (Snapshot, error) {
	return s.mutate(ctx, id, now, func(doc *document, index int) (bool, error) {
		ref := doc.Nodes[index].SecretRef
		doc.Nodes = append(doc.Nodes[:index], doc.Nodes[index+1:]...)
		for i := range doc.Secrets {
			if doc.Secrets[i].Ref == ref {
				doc.Secrets = append(doc.Secrets[:i], doc.Secrets[i+1:]...)
				break
			}
		}
		used := map[string]bool{}
		for _, node := range doc.Nodes {
			for _, origin := range node.Origins {
				used[origin.SourceID] = true
			}
		}
		kept := doc.Sources[:0]
		for _, source := range doc.Sources {
			if used[source.ID] {
				kept = append(kept, source)
			}
		}
		doc.Sources = kept
		return true, nil
	})
}

// WithSecret grants a bounded in-memory copy to an authenticated caller. The
// callback must not retain it; the copy is overwritten immediately afterwards.
func (s *Store) WithSecret(ctx context.Context, id string, use func([]byte) error) error {
	if use == nil {
		return ErrStore
	}
	s.mu.Lock()
	doc, _, err := s.load(ctx)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	var revealed []byte
	for _, node := range doc.Nodes {
		if node.ID != id {
			continue
		}
		for _, material := range doc.Secrets {
			if material.Ref == node.SecretRef {
				revealed = append([]byte(nil), material.Outbound...)
				break
			}
		}
		break
	}
	s.mu.Unlock()
	if revealed == nil {
		for _, node := range doc.Nodes {
			if node.ID == id {
				return ErrStore
			}
		}
		return ErrNotFound
	}
	defer clear(revealed)
	return use(revealed)
}

func (s *Store) mutate(ctx context.Context, id string, now time.Time, change func(*document, int) (bool, error)) (Snapshot, error) {
	if now.IsZero() || !validNodeID(id) || change == nil {
		return Snapshot{}, ErrStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, before, err := s.load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	index := -1
	for i := range doc.Nodes {
		if doc.Nodes[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return Snapshot{}, ErrNotFound
	}
	changed, err := change(&doc, index)
	if err != nil {
		return Snapshot{}, err
	}
	if !changed {
		return snapshot(doc, now.UTC()), nil
	}
	if len(doc.Nodes) == 0 {
		if err := s.target.CompareAndSwap(ctx, before, restorejournal.Image{}); err != nil {
			if errors.Is(err, restorejournal.ErrRecovery) {
				s.fenced = true
				return Snapshot{}, ErrRecovery
			}
			return Snapshot{}, ErrStore
		}
		return Snapshot{Nodes: []Node{}, Sources: []Source{}}, nil
	}
	if doc.Generation == ^uint64(0) {
		return Snapshot{}, ErrCapacity
	}
	doc.Schema = schema
	doc.Generation++
	if validate(doc) != nil {
		return Snapshot{}, ErrStore
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > maxBytes {
		return Snapshot{}, ErrCapacity
	}
	if err := s.target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: data}); err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) {
			s.fenced = true
			return Snapshot{}, ErrRecovery
		}
		return Snapshot{}, ErrStore
	}
	return snapshot(doc, now.UTC()), nil
}

func identity(key, material []byte) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("razvilka-node-v1\x00"))
	_, _ = h.Write(material)
	return "node-" + hex.EncodeToString(h.Sum(nil))
}

func validSource(s Source) bool {
	if !sourcePattern.MatchString(s.ID) {
		return false
	}
	switch s.Kind {
	case "manual", "file", "subscription", "community", "legacy":
		return true
	}
	return false
}

func validNodeID(id string) bool {
	if len(id) != len("node-")+sha256.Size*2 || !strings.HasPrefix(id, "node-") {
		return false
	}
	_, err := hex.DecodeString(id[len("node-"):])
	return err == nil
}

func validAlias(alias string) bool {
	if alias == "" {
		return true
	}
	if !utf8.ValidString(alias) || utf8.RuneCountInString(alias) > 64 || strings.TrimSpace(alias) != alias {
		return false
	}
	for _, char := range alias {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}
