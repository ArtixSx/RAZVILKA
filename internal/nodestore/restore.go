package nodestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sync"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// PrivateSnapshot is encrypted-backup material, NEVER a public DTO or log.
// It includes the store identity key so IDs survive recovery to an empty store.
type PrivateSnapshot struct {
	Content json.RawMessage `json:"content"`
	SHA256  string          `json:"sha256"`
}

// PrivateReview contains counts only. It never exposes node labels, endpoints,
// source identifiers, credentials or the store identity key.
type PrivateReview struct {
	Nodes   int `json:"nodes"`
	Sources int `json:"sources"`
}

func (PrivateSnapshot) String() string   { return "[private node snapshot]" }
func (PrivateSnapshot) GoString() string { return "[private node snapshot]" }

func decodeImage(image restorejournal.Image) (document, error) {
	if !image.Exists {
		if len(image.Data) != 0 {
			return document{}, restorejournal.ErrInvalid
		}
		return document{Schema: schema, Owner: "razvilka-nodes"}, nil
	}
	var doc document
	if len(image.Data) == 0 || len(image.Data) > maxBytes || decodeStrict(image.Data, &doc) != nil || validate(doc) != nil {
		return document{}, restorejournal.ErrInvalid
	}
	return doc, nil
}

func ValidatePrivateSnapshot(in PrivateSnapshot) error {
	hash := sha256.Sum256(in.Content)
	if len(in.Content) == 0 || len(in.Content) > maxBytes || in.SHA256 != hex.EncodeToString(hash[:]) {
		return restorejournal.ErrInvalid
	}
	_, err := decodeImage(restorejournal.Image{Exists: true, Data: in.Content})
	return err
}

func ReviewPrivateSnapshot(in PrivateSnapshot) (PrivateReview, error) {
	if ValidatePrivateSnapshot(in) != nil {
		return PrivateReview{}, restorejournal.ErrInvalid
	}
	doc, _ := decodeImage(restorejournal.Image{Exists: true, Data: in.Content})
	return PrivateReview{Nodes: len(doc.Nodes), Sources: len(doc.Sources)}, nil
}

// ExportPrivate is only for an authenticated encrypted backup builder. The
// caller must never return this plaintext as an API preview or public export.
func (s *Store) ExportPrivate(ctx context.Context) (PrivateSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, image, err := s.load(ctx)
	if err != nil {
		return PrivateSnapshot{}, err
	}
	if !image.Exists {
		return PrivateSnapshot{}, ErrStore
	}
	// Canonical RawMessage bytes survive encoding inside the backup payload.
	var compact bytes.Buffer
	if json.Compact(&compact, image.Data) != nil {
		return PrivateSnapshot{}, ErrStore
	}
	data := bytes.Clone(compact.Bytes())
	hash := sha256.Sum256(data)
	return PrivateSnapshot{Content: data, SHA256: hex.EncodeToString(hash[:])}, nil
}

// ExportPrivateIfPresent distinguishes an empty store from an unavailable one.
// The returned snapshot is still plaintext secret material and may only be put
// into the authenticated encrypted backup envelope.
func (s *Store) ExportPrivateIfPresent(ctx context.Context) (*PrivateSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, image, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	if !image.Exists {
		return nil, nil
	}
	var compact bytes.Buffer
	if json.Compact(&compact, image.Data) != nil {
		return nil, ErrStore
	}
	data := bytes.Clone(compact.Bytes())
	hash := sha256.Sum256(data)
	return &PrivateSnapshot{Content: data, SHA256: hex.EncodeToString(hash[:])}, nil
}

// RestoreBinding is based on trusted deployment configuration, never archive
// paths. Offline recovery and live Store sessions must match this same binding.
func RestoreBinding(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", restorejournal.ErrInvalid
	}
	binding, err := restorejournal.FileBinding(filepath.Join(path, fileName))
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte("nodestore-schema-1\x00" + binding))
	return hex.EncodeToString(hash[:]), nil
}

// RestoreTarget holds the Store mutex. A live session borrows the existing OS
// lease; offline recovery opens that SAME FileTarget lease before normal Open.
// Only the journal coordinator may write images; no raw HTTP target is exposed.
type RestoreTarget struct {
	mu        sync.Mutex
	store     *Store
	closed    bool
	ownsStore bool
	binding   string
}

func (*RestoreTarget) String() string   { return "[private node restore session]" }
func (*RestoreTarget) GoString() string { return "[private node restore session]" }

func OpenRestoreTarget(path string) (*RestoreTarget, error) {
	s, err := Open(path)
	if err != nil {
		return nil, err
	}
	t, err := s.BeginRestore(context.Background())
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	t.ownsStore = true
	return t, nil
}

func (s *Store) BeginRestore(ctx context.Context) (*RestoreTarget, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if !s.mu.TryLock() {
		return nil, restorejournal.ErrBusy
	}
	if _, _, err := s.load(ctx); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	return &RestoreTarget{store: s, binding: s.binding}, nil
}

func (t *RestoreTarget) Binding() string { return t.binding }

func (t *RestoreTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.Image{}, restorejournal.ErrUnavailable
	}
	_, image, err := t.store.load(ctx)
	return image, err
}

func (t *RestoreTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return restorejournal.ErrUnavailable
	}
	if _, err := decodeImage(before); err != nil {
		return err
	}
	if _, err := decodeImage(after); err != nil {
		return err
	}
	// Byte-exact before-images (including absent) must remain valid for rollback.
	return t.store.target.CompareAndSwap(ctx, before, after)
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
	current, before, err := t.store.load(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	imported, _ := decodeImage(restorejournal.Image{Exists: true, Data: in.Content})
	merged, err := mergeDocuments(current, imported)
	if err != nil {
		return restorejournal.Image{}, err
	}
	data, err := json.Marshal(merged)
	if err != nil || len(data) > maxBytes {
		return restorejournal.Image{}, ErrCapacity
	}
	if before.Exists && bytes.Equal(before.Data, data) {
		return before, nil
	}
	if merged.Generation == ^uint64(0) {
		return restorejournal.Image{}, ErrCapacity
	}
	merged.Generation++
	if validate(merged) != nil {
		return restorejournal.Image{}, restorejournal.ErrInvalid
	}
	data, err = json.Marshal(merged)
	if err != nil || len(data) > maxBytes {
		return restorejournal.Image{}, ErrCapacity
	}
	if ctx.Err() != nil {
		return restorejournal.Image{}, restorejournal.ErrAborted
	}
	return restorejournal.Image{Exists: true, Data: data}, nil
}

func mergeDocuments(current, imported document) (document, error) {
	if len(current.IdentityKey) == 0 {
		current.IdentityKey = bytes.Clone(imported.IdentityKey)
	}
	// A different store uses different IDs. Never silently invalidate future
	// bindings by changing the identity key of a populated target.
	if !bytes.Equal(current.IdentityKey, imported.IdentityKey) {
		return document{}, restorejournal.ErrConflict
	}
	for _, source := range imported.Sources {
		found := false
		for _, existing := range current.Sources {
			if existing.ID == source.ID {
				if existing.Kind != source.Kind {
					return document{}, restorejournal.ErrConflict
				}
				found = true
			}
		}
		if !found {
			current.Sources = append(current.Sources, source)
		}
	}
	for _, node := range imported.Nodes {
		index := -1
		for i := range current.Nodes {
			if current.Nodes[i].ID == node.ID {
				index = i
				break
			}
		}
		if index < 0 {
			current.Nodes = append(current.Nodes, node)
			for _, secret := range imported.Secrets {
				if secret.Ref == node.SecretRef {
					current.Secrets = append(current.Secrets, secret)
					break
				}
			}
			continue
		}
		existing := &current.Nodes[index]
		if node.AddedAt.Before(existing.AddedAt) {
			existing.AddedAt = node.AddedAt
		}
		for _, origin := range node.Origins {
			found := false
			for i := range existing.Origins {
				previous := existing.Origins[i]
				if previous.SourceID != origin.SourceID {
					continue
				}
				found = true
				// A tie may shorten but never extend freshness on restore.
				if origin.ReceivedAt.After(previous.ReceivedAt) || origin.ReceivedAt.Equal(previous.ReceivedAt) && origin.ExpiresAt.Before(previous.ExpiresAt) {
					existing.Origins[i] = origin
				}
			}
			if !found {
				existing.Origins = append(existing.Origins, origin)
			}
		}
	}
	if len(current.Nodes) > MaxNodes || len(current.Sources) > MaxSources {
		return document{}, ErrCapacity
	}
	return current, nil
}

func (t *RestoreTarget) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	// There is no cache to promote. Still validate disk before ordinary writers
	// resume; the coordinator keeps its global recovery fence on blocked outcome.
	_, _, err := t.store.load(context.Background())
	if err != nil {
		t.store.fenced = true
	}
	t.store.mu.Unlock()
	if t.ownsStore && t.store.Close() != nil {
		err = restorejournal.ErrRecovery
	}
	if err != nil {
		return restorejournal.ErrRecovery
	}
	return nil
}
