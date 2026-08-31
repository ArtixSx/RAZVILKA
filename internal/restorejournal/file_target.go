package restorejournal

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var ErrConflict = errors.New("state file changed since it was read")

// FileTarget is a bounded, descriptor-anchored file adapter. It keeps a
// per-filename OS lease until Close; all participating writers MUST use this
// adapter. It does not protect against root, legacy writers or hardlink/path
// aliases. Targets are configured at startup, never taken from an archive.
type FileTarget struct {
	mu      sync.Mutex
	root    *ownedfs.Root
	name    string
	binding string
	release func()
	closed  bool
	write   func(Image) error
}

func (*FileTarget) String() string   { return "[private state file]" }
func (*FileTarget) GoString() string { return "[private state file]" }

// OpenFileTarget does not create the parent directory or target. Legacy
// files may be readable by others; replacements are always 0600. Secret stores
// must additionally require private parent-directory permissions.
func OpenFileTarget(path string) (*FileTarget, error) {
	full, err := targetPath(path)
	if err != nil {
		return nil, err
	}
	root, err := ownedfs.Open(filepath.Dir(full))
	if err != nil {
		return nil, ErrUnavailable
	}
	name := filepath.Base(full)
	leaseName := name
	if runtime.GOOS == "windows" {
		leaseName = strings.ToLower(leaseName)
	}
	key := sum([]byte(leaseName))
	release, err := acquireNamedLease(root, ".state-"+key+".lock", "RAZVILKA state file writer v1 "+key+"\n")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	binding, _ := FileBinding(full)
	f := &FileTarget{root: root, name: name, release: release, binding: binding}
	f.write = func(after Image) error {
		var err error
		if after.Exists {
			err = root.WriteAtomic(name, after.Data, 0o600)
		} else {
			err = root.Remove(name)
		}
		if err != nil {
			return err
		}
		return syncJournalDir(root)
	}
	if _, err := f.Read(context.Background()); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// Binding contains no path. Include it AND the typed adapter's schema/version
// in the trusted journal scope; never substitute a value from an HTTP request.
func (f *FileTarget) Binding() string { return f.binding }

// FileBinding computes the trusted lexical destination identity without opening
// a file or taking a second lease. It does not attest inode/symlink aliases.
func FileBinding(path string) (string, error) {
	full, err := targetPath(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		full = strings.ToLower(full)
	}
	return sum([]byte("state-file-v1\x00" + full)), nil
}

func (f *FileTarget) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	f.release()
	if f.root.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

func (f *FileTarget) Read(ctx context.Context) (Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return Image{}, ErrUnavailable
	}
	return readTarget(ctx, f.root, f.name)
}

func (f *FileTarget) CompareAndSwap(ctx context.Context, before, after Image) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return ErrUnavailable
	}
	if !validImage(before) || !validImage(after) {
		return ErrInvalid
	}
	current, err := readTarget(ctx, f.root, f.name)
	if err != nil {
		return err
	}
	if !equal(current, before) {
		return ErrConflict
	}
	if equal(before, after) {
		return nil
	}
	if ctx.Err() != nil {
		return ErrAborted
	}
	// Failure may be AFTER rename/unlink or directory sync. It is not a
	// confirmed rollback without rereading the target.
	if f.write(clone(after)) != nil {
		return ErrRecovery
	}
	return nil
}

// ReadFileImage creates no file/lease/directory. Readers see an atomic image,
// but it may be stale immediately afterwards: writers still need CAS + lease.
func ReadFileImage(ctx context.Context, path string) (Image, error) {
	full, err := targetPath(path)
	if err != nil {
		return Image{}, err
	}
	root, err := ownedfs.Open(filepath.Dir(full))
	if errors.Is(err, os.ErrNotExist) {
		return Image{}, nil
	}
	if err != nil {
		return Image{}, ErrUnavailable
	}
	defer root.Close()
	return readTarget(ctx, root, filepath.Base(full))
}

func targetPath(path string) (string, error) {
	if path == "" {
		return "", ErrInvalid
	}
	// Check before Abs as well: Windows may normalize a DOS device spelling
	// into a different namespace or strip a trailing dot/space.
	if runtime.GOOS == "windows" && invalidWindowsName(filepath.Base(path)) {
		return "", ErrInvalid
	}
	full, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	name := filepath.Base(full)
	if !filepath.IsLocal(name) || name == "." || strings.EqualFold(name, journalFile) || strings.EqualFold(name, leaseFile) || strings.HasPrefix(strings.ToLower(name), ".state-") || strings.ContainsAny(name, ":\x00") || runtime.GOOS == "windows" && invalidWindowsName(name) {
		return "", ErrInvalid
	}
	return full, nil
}

func invalidWindowsName(name string) bool {
	if strings.TrimRight(name, ". ") != name {
		return true
	}
	base, _, _ := strings.Cut(strings.ToUpper(name), ".")
	base = strings.TrimRight(base, " ")
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	for _, prefix := range []string{"COM", "LPT"} {
		if strings.HasPrefix(base, prefix) {
			suffix := strings.TrimPrefix(base, prefix)
			if len([]rune(suffix)) == 1 && strings.ContainsAny(suffix, "123456789¹²³") {
				return true
			}
		}
	}
	return false
}

func readTarget(ctx context.Context, root *ownedfs.Root, name string) (Image, error) {
	if ctx.Err() != nil {
		return Image{}, ErrAborted
	}
	info, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Image{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxImageBytes {
		return Image{}, ErrInvalid
	}
	f, err := openReadOnly(root, name)
	if err != nil {
		return Image{}, ErrUnavailable
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(info, actual) {
		return Image{}, ErrConflict
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxImageBytes+1))
	if err != nil || len(data) > MaxImageBytes {
		return Image{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return Image{}, ErrAborted
	}
	return Image{Exists: true, Data: data}, nil
}
