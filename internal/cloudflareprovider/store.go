package cloudflareprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var (
	ErrStore    = errors.New("Cloudflare private store is unavailable or invalid")
	ErrBusy     = errors.New("Cloudflare private store has another writer; inspect an interrupted import before retrying")
	ErrCapacity = errors.New("Cloudflare snapshot limit reached")
)

const storeFile = "accounts.private.json"
const storeLimit = MaxAccounts*MaxImportBytes*2 + 65536

type storedAccount struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Raw        []byte    `json:"raw"`
	Digest     string    `json:"digest"`
	ImportedAt time.Time `json:"imported_at"`
}

type privateDocument struct {
	Schema   int             `json:"schema"`
	Owner    string          `json:"owner"`
	Accounts []storedAccount `json:"accounts"`
}

// Store owns copies only, not the original wgcf/USQUE files or their runtimes.
// The directory must be explicitly created by the caller with private access.
// POSIX 0700/0600 protect at rest; this is not encryption against root/disk access.
type Store struct {
	root    *ownedfs.Root
	mu      sync.Mutex
	gate    chan struct{}
	binding string
}

func OpenStore(path string) (*Store, error) {
	root, err := openPrivateRoot(path)
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, gate: make(chan struct{}, 1), binding: providerBinding(path)}
	if _, err := s.load(); err != nil {
		_ = root.Close()
		return nil, err
	}
	return s, nil
}

func openPrivateRoot(path string) (*ownedfs.Root, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrStore
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrStore
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return nil, ErrStore
	}
	return root, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root.Close()
}

func (s *Store) List(ctx context.Context) ([]Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	doc, err := s.loadContext(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]Account, 0, len(doc.Accounts))
	for _, record := range doc.Accounts {
		parsed, err := ParseImport(record.Kind, record.Raw)
		if err != nil {
			return nil, ErrStore
		}
		views = append(views, accountView(record, parsed))
	}
	return views, nil
}

func accountView(record storedAccount, imported Import) Account {
	view := imported.Preview()
	view.ID, view.SecretReference = record.ID, "cloudflare:"+record.ID
	view.CreatedAt, view.UpdatedAt = record.ImportedAt, record.ImportedAt
	return view
}

// ImportSnapshot is idempotent for identical bytes and source kind. Different
// input creates a new unverified snapshot and never overwrites an active account.
func (s *Store) ImportSnapshot(ctx context.Context, imported Import) (Account, error) {
	release, err := s.lockWrite(ctx)
	if err != nil {
		return Account{}, err
	}
	defer release()
	parsed, err := ParseImport(imported.kind, imported.raw)
	if err != nil {
		return Account{}, err
	}
	doc, err := s.loadContext(ctx)
	if err != nil {
		return Account{}, err
	}
	hash := digest(parsed.raw)
	for _, record := range doc.Accounts {
		if record.Kind == parsed.kind && record.Digest == hash {
			return accountView(record, parsed), nil
		}
	}
	if len(doc.Accounts) >= MaxAccounts {
		return Account{}, ErrCapacity
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	record := storedAccount{ID: "cf-" + hex.EncodeToString(id[:]), Kind: parsed.kind, Raw: parsed.raw, Digest: hash, ImportedAt: time.Now().UTC()}
	doc.Accounts = append(doc.Accounts, record)
	if err := s.commit(ctx, doc); err != nil {
		return Account{}, err
	}
	return accountView(record, parsed), nil
}

func (s *Store) lockWrite(ctx context.Context) (func(), error) {
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.mu.Lock()
	release := func() { s.mu.Unlock(); <-s.gate }
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	unlock, err := acquireWriterLock(s.root)
	if err != nil {
		release()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		unlock()
		release()
		return nil, err
	}
	return func() { unlock(); release() }, nil
}

func (s *Store) commit(ctx context.Context, doc privateDocument) error {
	if err := validateDocument(doc); err != nil {
		return err
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > storeLimit {
		return ErrStore
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeSnapshotImage(s.root, restorejournal.Image{Exists: true, Data: data})
}

func validID(id string) bool {
	if !strings.HasPrefix(id, "cf-") || len(id) != 35 {
		return false
	}
	b, err := hex.DecodeString(id[3:])
	return err == nil && len(b) == 16
}

func (s *Store) load() (privateDocument, error) {
	return s.loadContext(context.Background())
}

func (s *Store) loadContext(ctx context.Context) (privateDocument, error) {
	image, err := readSnapshotImage(ctx, s.root, storeLimit)
	if err != nil {
		return privateDocument{}, err
	}
	doc, err := snapshotDocument(image, storeLimit)
	if err != nil {
		return privateDocument{}, err
	}
	if err := ctx.Err(); err != nil {
		return privateDocument{}, err
	}
	return doc, nil
}

func validateDocument(doc privateDocument) error {
	if doc.Schema != Schema || doc.Owner != "razvilka" || len(doc.Accounts) > MaxAccounts {
		return ErrStore
	}
	seen := map[string]bool{}
	for _, record := range doc.Accounts {
		if !validID(record.ID) || seen[record.ID] || record.ImportedAt.IsZero() || record.ImportedAt.After(time.Now().Add(5*time.Minute)) || record.Digest != digest(record.Raw) {
			return ErrStore
		}
		seen[record.ID] = true
		if _, err := ParseImport(record.Kind, record.Raw); err != nil {
			return ErrStore
		}
	}
	return nil
}
