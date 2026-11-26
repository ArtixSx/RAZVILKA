// Package nativeenrollment stores a bounded, inert WARP enrollment image.
// It has no network, engine, route or configuration-activation capability.
package nativeenrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const FileName = "native-enrollment.private.json"
const MaxBytes = 4 << 20
const MaxFiles = 258

var ErrState = errors.New("native enrollment image is unavailable or invalid")
var ErrConflict = errors.New("native enrollment conflicts with retained state; unresolved registration was preserved")

type File struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}
type Document struct {
	Schema int    `json:"schema"`
	Files  []File `json:"files"`
}
type Snapshot struct {
	Content json.RawMessage `json:"content"`
	SHA256  string          `json:"sha256"`
}

func (Document) String() string   { return "[private native enrollment image]" }
func (Document) GoString() string { return "[private native enrollment image]" }
func (Snapshot) String() string   { return "[private native enrollment snapshot]" }
func (Snapshot) GoString() string { return "[private native enrollment snapshot]" }

func Sum(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (d Document) Get(name string) []byte {
	for _, f := range d.Files {
		if f.Name == name {
			return bytes.Clone(f.Data)
		}
	}
	return nil
}
func (d Document) Has(name string) bool {
	for _, f := range d.Files {
		if f.Name == name {
			return true
		}
	}
	return false
}
func (d *Document) Set(name string, data []byte) {
	for i := range d.Files {
		if d.Files[i].Name == name {
			d.Files[i].Data = bytes.Clone(data)
			return
		}
	}
	d.Files = append(d.Files, File{Name: name, Data: bytes.Clone(data)})
}
func (d *Document) Delete(name string) {
	for i := range d.Files {
		if d.Files[i].Name == name {
			d.Files = append(d.Files[:i], d.Files[i+1:]...)
			return
		}
	}
}

func ValidDirectory(name string) bool {
	if len(name) != 40 || !strings.HasPrefix(name, "attempt-") {
		return false
	}
	for _, c := range name[8:] {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func fileLimit(name string) int {
	if name == "current.json" || name == "pending.json" {
		return 4096
	}
	parts := strings.Split(name, "/")
	if len(parts) < 2 || !ValidDirectory(parts[0]) {
		return 0
	}
	if len(parts) == 3 && parts[1] == "provider" && parts[2] == "accounts.private.json" {
		return 1 << 20
	}
	if len(parts) != 2 {
		return 0
	}
	switch parts[1] {
	case "private-key.bin":
		return 32
	case "response.private.json":
		return 64 << 10
	case "registration.private.json":
		return 256 << 10
	}
	return 0
}
func Encode(d Document) ([]byte, error) {
	if d.Schema != 1 || len(d.Files) > MaxFiles {
		return nil, ErrState
	}
	d.Files = append([]File(nil), d.Files...)
	sort.Slice(d.Files, func(i, j int) bool { return d.Files[i].Name < d.Files[j].Name })
	seen := map[string]bool{}
	for _, file := range d.Files {
		limit := fileLimit(file.Name)
		if limit == 0 || len(file.Data) > limit || seen[file.Name] {
			return nil, ErrState
		}
		seen[file.Name] = true
	}
	data, err := json.Marshal(d)
	if err != nil || len(data) > MaxBytes {
		return nil, ErrState
	}
	return data, nil
}
func Decode(image restorejournal.Image) (Document, error) {
	if !image.Exists && len(image.Data) == 0 {
		return Document{Schema: 1}, nil
	}
	if !image.Exists || len(image.Data) == 0 || len(image.Data) > MaxBytes {
		return Document{}, ErrState
	}
	var d Document
	decoder := json.NewDecoder(bytes.NewReader(image.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Document{}, ErrState
	}
	if _, err := Encode(d); err != nil {
		return Document{}, err
	}
	return d, nil
}
func ValidateSnapshot(s Snapshot) error {
	if len(s.Content) == 0 || s.SHA256 != Sum(s.Content) {
		return ErrState
	}
	_, err := Decode(restorejournal.Image{Exists: true, Data: s.Content})
	return err
}
func SnapshotOf(d Document) (Snapshot, error) {
	data, err := Encode(d)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Content: data, SHA256: Sum(data)}, nil
}

// ReadEffective is read-only. The legacy tree is an immutable migration input;
// once the canonical file exists, only that leased atomic file is authoritative.
func ReadEffective(ctx context.Context, path string) (restorejournal.Image, error) {
	image, err := restorejournal.ReadFileImage(ctx, filepath.Join(path, FileName))
	if err != nil {
		return image, err
	}
	if image.Exists {
		_, err = Decode(image)
		return image, err
	}
	return legacyImage(ctx, path)
}
func legacyImage(ctx context.Context, path string) (restorejournal.Image, error) {
	legacy := filepath.Join(path, "native-enrollment")
	info, err := os.Lstat(legacy)
	if errors.Is(err, os.ErrNotExist) {
		return restorejournal.Image{}, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return restorejournal.Image{}, ErrState
	}
	root, err := ownedfs.Open(legacy)
	if err != nil {
		return restorejournal.Image{}, ErrState
	}
	defer root.Close()
	d := Document{Schema: 1}
	read := func(name string) error {
		data, err := root.ReadLimited(filepath.FromSlash(name), int64(fileLimit(name)))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return ErrState
		}
		d.Set(name, data)
		return nil
	}
	for _, name := range []string{"current.json", "pending.json"} {
		if err := read(name); err != nil {
			return restorejournal.Image{}, err
		}
	}
	entries, err := os.ReadDir(legacy)
	if err != nil || len(entries) > MaxFiles {
		return restorejournal.Image{}, ErrState
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return restorejournal.Image{}, err
		}
		if !ValidDirectory(entry.Name()) {
			continue
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return restorejournal.Image{}, ErrState
		}
		for _, leaf := range []string{"private-key.bin", "response.private.json", "registration.private.json", "provider/accounts.private.json"} {
			if err := read(entry.Name() + "/" + leaf); err != nil {
				return restorejournal.Image{}, err
			}
		}
	}
	if len(d.Files) == 0 {
		return restorejournal.Image{}, nil
	}
	data, err := Encode(d)
	return restorejournal.Image{Exists: true, Data: data}, err
}

type Target struct {
	file *restorejournal.FileTarget
	path string
}

func Open(path string) (*Target, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrState
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, ErrState
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrState
	}
	f, err := restorejournal.OpenFileTarget(filepath.Join(path, FileName))
	if err != nil {
		return nil, err
	}
	t := &Target{file: f, path: path}
	if _, err := t.Read(context.Background()); err != nil {
		f.Close()
		return nil, err
	}
	return t, nil
}
func (t *Target) Close() error { return t.file.Close() }
func Binding(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrState
	}
	b, err := restorejournal.FileBinding(filepath.Join(path, FileName))
	if err != nil {
		return "", err
	}
	return Sum([]byte("native-enrollment-v1\x00" + b)), nil
}
func (t *Target) Binding() string { b, _ := Binding(t.path); return b }
func (t *Target) Read(ctx context.Context) (restorejournal.Image, error) {
	image, err := t.file.Read(ctx)
	if err != nil {
		return image, err
	}
	if image.Exists {
		_, err = Decode(image)
		return image, err
	}
	return legacyImage(ctx, t.path)
}
func (t *Target) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if _, err := Decode(after); err != nil {
		return err
	}
	current, err := t.Read(ctx)
	if err != nil {
		return err
	}
	if current.Exists != before.Exists || !bytes.Equal(current.Data, before.Data) {
		return restorejournal.ErrConflict
	}
	actual, err := t.file.Read(ctx)
	if err != nil {
		return err
	}
	// A virtual legacy before-image becomes a canonical copy on successful
	// migration or rollback. Original directories are never changed or deleted.
	return t.file.CompareAndSwap(ctx, actual, after)
}
func (t *Target) Save(ctx context.Context, before restorejournal.Image, d Document) (restorejournal.Image, error) {
	data, err := Encode(d)
	if err != nil {
		return before, err
	}
	after := restorejournal.Image{Exists: true, Data: data}
	err = t.CompareAndSwap(ctx, before, after)
	return after, err
}

func markerDirectory(data []byte) string {
	var v struct {
		Directory string `json:"directory"`
	}
	if json.Unmarshal(data, &v) != nil || !ValidDirectory(v.Directory) {
		return ""
	}
	return v.Directory
}
func (t *Target) MergeImage(ctx context.Context, snapshot Snapshot) (restorejournal.Image, error) {
	if ValidateSnapshot(snapshot) != nil {
		return restorejournal.Image{}, ErrState
	}
	before, err := t.Read(ctx)
	if err != nil {
		return before, err
	}
	current, err := Decode(before)
	if err != nil {
		return before, err
	}
	incoming, err := Decode(restorejournal.Image{Exists: true, Data: snapshot.Content})
	if err != nil {
		return before, err
	}
	oldPending, newPending := current.Get("pending.json"), incoming.Get("pending.json")
	// Never erase an existing unresolved request by importing an older archive.
	if current.Has("pending.json") && (!incoming.Has("pending.json") || !bytes.Equal(oldPending, newPending)) {
		return before, ErrConflict
	}
	// Decisions about stale pending intent use only the pre-import state.
	completed := markerDirectory(current.Get("current.json"))
	for _, f := range incoming.Files {
		old := current.Get(f.Name)
		if f.Name == "current.json" {
			if !current.Has(f.Name) {
				current.Set(f.Name, f.Data)
			}
			continue
		}
		if f.Name == "pending.json" && !current.Has(f.Name) {
			id := markerDirectory(f.Data)
			if id == "" {
				return before, ErrState
			}
			if completed == id {
				continue
			}
		}
		if current.Has(f.Name) && !bytes.Equal(old, f.Data) {
			return before, ErrConflict
		}
		current.Set(f.Name, f.Data)
	}
	data, err := Encode(current)
	return restorejournal.Image{Exists: true, Data: data}, err
}
