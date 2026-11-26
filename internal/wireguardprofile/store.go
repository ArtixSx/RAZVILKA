// Package wireguardprofile stores explicitly imported own-server WireGuard
// profiles. It does not register WARP accounts, run hooks or change networking.
package wireguardprofile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const owner = "razvilka-wireguard-profile-v1"

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var ErrRevision = errors.New("WireGuard profile revision changed")
var ErrForeign = errors.New("WireGuard profile is unowned or invalid; retained without modification")

func ValidID(id string) bool { return id != "main" && idPattern.MatchString(id) }

type Metadata struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Revision     string `json:"revision"`
	Engine       string `json:"engine"`
	Verification string `json:"verification"`
}

type Profile struct {
	metadata Metadata
	config   string
}

func (p Profile) Public() Metadata             { return p.metadata }
func (p Profile) Config() string               { return p.config }
func (p Profile) MarshalJSON() ([]byte, error) { return json.Marshal(p.metadata) }
func (p Profile) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, "[private WireGuard profile]") }

type diskProfile struct {
	Owner    string `json:"owner"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
	Config   string `json:"config"`
}
type Store struct {
	mu   sync.Mutex
	root string
}

func New(root string) *Store { return &Store{root: root} }

func (s *Store) open(create bool) (*ownedfs.Root, error) {
	if !filepath.IsAbs(s.root) {
		return nil, errors.New("WireGuard profile root must be absolute")
	}
	if create {
		if err := os.MkdirAll(s.root, 0o700); err != nil {
			return nil, err
		}
	}
	return ownedfs.Open(s.root)
}

func revision(id, name, config string) string {
	digest := sha256.Sum256([]byte(id + "\x00" + name + "\x00" + config))
	return hex.EncodeToString(digest[:])
}

func read(root *ownedfs.Root, id string) (Profile, error) {
	if !ValidID(id) {
		return Profile{}, errors.New("invalid WireGuard profile ID")
	}
	data, err := root.ReadLimited(id+".json", 2*awgprofile.MaxBytes)
	if err != nil {
		return Profile{}, err
	}
	var stored diskProfile
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&stored) != nil || d.Decode(&struct{}{}) != io.EOF || stored.Owner != owner || stored.ID != id || len(stored.Name) > 160 || strings.TrimSpace(stored.Name) == "" || stored.Revision != revision(stored.ID, stored.Name, stored.Config) {
		return Profile{}, ErrForeign
	}
	p, err := awgprofile.ParsePlainWireGuard(stored.Config)
	if err != nil || p.Config() != stored.Config {
		return Profile{}, ErrForeign
	}
	return Profile{Metadata{ID: id, Name: stored.Name, Revision: stored.Revision, Engine: "wireguard", Verification: "syntax-only"}, stored.Config}, nil
}

func (s *Store) Get(ctx context.Context, id string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	root, err := s.open(false)
	if err != nil {
		return Profile{}, err
	}
	defer root.Close()
	return read(root, id)
}

// Put creates only when expectedRevision is empty and the ID does not exist.
// Replacement requires the exact prior revision; arbitrary existing files are
// never adopted, sanitized in place or overwritten as imported profiles.
func (s *Store) Put(ctx context.Context, id, name, config, expectedRevision string) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	name = strings.TrimSpace(name)
	if !ValidID(id) || name == "" || len(name) > 160 || strings.ContainsAny(name, "\x00\r\n") {
		return Metadata{}, errors.New("invalid WireGuard profile ID or name")
	}
	p, err := awgprofile.ParsePlainWireGuard(config)
	if err != nil {
		return Metadata{}, err
	}
	root, err := s.open(true)
	if err != nil {
		return Metadata{}, err
	}
	defer root.Close()
	old, err := read(root, id)
	if err == nil {
		if expectedRevision == "" || old.Public().Revision != expectedRevision {
			return Metadata{}, ErrRevision
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Metadata{}, ErrForeign
	} else if expectedRevision != "" {
		return Metadata{}, ErrRevision
	}
	stored := diskProfile{Owner: owner, ID: id, Name: name, Config: p.Config()}
	stored.Revision = revision(id, name, stored.Config)
	data, err := json.Marshal(stored)
	if err != nil {
		return Metadata{}, err
	}
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	if err := root.WriteAtomic(id+".json", data, 0o600); err != nil {
		return Metadata{}, err
	}
	return Metadata{ID: id, Name: name, Revision: stored.Revision, Engine: "wireguard", Verification: "syntax-only"}, nil
}

func (s *Store) List(ctx context.Context) ([]Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Metadata{}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := s.open(false)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	if len(entries) > 256 {
		return nil, errors.New("WireGuard profile directory exceeds bounded catalog")
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.Name() == id || !ValidID(id) {
			continue
		}
		p, err := read(root, id)
		if err != nil {
			continue
		} // Foreign files are neither exposed nor mutated.
		out = append(out, p.Public())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Delete is an explicit catalog action, not runtime Stop or reserve eviction.
// The caller must reject removal of an active or transaction-selected profile.
func (s *Store) Delete(ctx context.Context, id, expectedRevision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := s.open(false)
	if err != nil {
		return err
	}
	defer root.Close()
	p, err := read(root, id)
	if err != nil {
		return err
	}
	if expectedRevision == "" || p.Public().Revision != expectedRevision {
		return ErrRevision
	}
	return root.Remove(id + ".json")
}
