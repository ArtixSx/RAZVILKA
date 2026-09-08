package cloudflareprovider

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var (
	ErrLegacySource  = errors.New("Cloudflare legacy source is unavailable or unsafe")
	ErrLegacyMissing = errors.New("Cloudflare legacy source does not exist")
	ErrLegacyChanged = errors.New("Cloudflare legacy source differs from the reviewed copy")
)

// LegacySpec is startup configuration, never decoded from an HTTP request.
// Registry construction and listing do not touch the filesystem.
type LegacySpec struct {
	ID    string
	Label string
	Kind  string
	Path  string
}

type LegacyLocation struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"source_kind"`
}

type LegacyReview struct {
	SourceID string  `json:"source_id"`
	Digest   string  `json:"review_digest"`
	Account  Account `json:"account"`
}

type LegacySources struct{ specs []LegacySpec }

func NewLegacySources(specs []LegacySpec) (*LegacySources, error) {
	if len(specs) > 8 {
		return nil, ErrLegacySource
	}
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.ID == "" || len(spec.ID) > 48 || seen[spec.ID] || len(spec.Label) == 0 || len(spec.Label) > 200 || !filepath.IsAbs(spec.Path) || filepath.Clean(spec.Path) != spec.Path || filepath.Base(spec.Path) == "." {
			return nil, ErrLegacySource
		}
		for _, char := range spec.ID {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return nil, ErrLegacySource
			}
		}
		if spec.Kind != SourceUSQUE && spec.Kind != SourceWGCF && spec.Kind != SourceWireGuard {
			return nil, ErrLegacySource
		}
		seen[spec.ID] = true
	}
	return &LegacySources{specs: append([]LegacySpec(nil), specs...)}, nil
}

func (s *LegacySources) Locations() []LegacyLocation {
	items := make([]LegacyLocation, 0, len(s.specs))
	for _, spec := range s.specs {
		items = append(items, LegacyLocation{ID: spec.ID, Label: spec.Label, Kind: spec.Kind})
	}
	return items
}

func (s *LegacySources) Preview(ctx context.Context, id string) (LegacyReview, error) {
	imported, err := s.read(ctx, id)
	if err != nil {
		return LegacyReview{}, err
	}
	return LegacyReview{SourceID: id, Digest: migrationDigest(id, imported), Account: imported.Preview()}, nil
}

// Copy checks the same source again and imports only the reviewed bytes. It
// owns the new snapshot, never the external file or runtime. There is no rename,
// deletion, chmod, registration, runtime stop or network access in this path.
func (s *LegacySources) Copy(ctx context.Context, store *Store, id, reviewedDigest string) (Account, error) {
	if len(reviewedDigest) != 64 {
		return Account{}, ErrLegacyChanged
	}
	imported, err := s.read(ctx, id)
	if err != nil {
		return Account{}, err
	}
	if migrationDigest(id, imported) != reviewedDigest {
		return Account{}, ErrLegacyChanged
	}
	if store == nil {
		return Account{}, ErrStore
	}
	return store.ImportSnapshot(ctx, imported)
}

func migrationDigest(id string, imported Import) string {
	return digest([]byte(id + "\x00" + imported.kind + "\x00" + digest(imported.raw)))
}

func (s *LegacySources) read(ctx context.Context, id string) (Import, error) {
	if err := ctx.Err(); err != nil {
		return Import{}, err
	}
	var selected *LegacySpec
	for _, spec := range s.specs {
		if spec.ID == id {
			copy := spec
			selected = &copy
			break
		}
	}
	if selected == nil {
		return Import{}, ErrLegacySource
	}
	root, err := ownedfs.Open(filepath.Dir(selected.Path))
	if errors.Is(err, os.ErrNotExist) {
		return Import{}, ErrLegacyMissing
	}
	if err != nil {
		return Import{}, ErrLegacySource
	}
	defer root.Close()
	name := filepath.Base(selected.Path)
	before, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Import{}, ErrLegacyMissing
	}
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > MaxImportBytes {
		return Import{}, ErrLegacySource
	}
	file, err := openLegacyFile(root, name)
	if err != nil {
		return Import{}, ErrLegacySource
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return Import{}, ErrLegacyChanged
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxImportBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxImportBytes {
		return Import{}, ErrLegacySource
	}
	after, err := file.Stat()
	current, pathErr := root.Stat(name)
	if err != nil || pathErr != nil || !os.SameFile(opened, current) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) || current.Size() != after.Size() || !current.ModTime().Equal(after.ModTime()) || int64(len(raw)) != after.Size() {
		return Import{}, ErrLegacyChanged
	}
	if err := ctx.Err(); err != nil {
		return Import{}, err
	}
	return ParseImport(selected.Kind, raw)
}
