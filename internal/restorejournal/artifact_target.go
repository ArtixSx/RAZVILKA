package restorejournal

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
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// ArtifactImage is a small closed reference to an immutable binary in a
// trusted, prepopulated artifact root. Imported journal bytes never supply a
// filesystem path. Every read/copy verifies the actual complete file again.
func ArtifactImage(sha string, size int64) (Image, error) {
	ref := artifactReference{SHA256: sha, Size: size}
	if !ref.valid() {
		return Image{}, ErrInvalid
	}
	data, _ := json.Marshal(ref)
	return Image{Exists: true, Data: data}, nil
}

type artifactReference struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func (r artifactReference) valid() bool {
	v, err := hex.DecodeString(r.SHA256)
	return err == nil && len(v) == 32 && hex.EncodeToString(v) == r.SHA256 && r.Size > 0 && r.Size <= ownedfs.MaxAtomicArtifactBytes
}
func artifactImageReference(image Image) (artifactReference, error) {
	var ref artifactReference
	if !image.Exists || json.Unmarshal(image.Data, &ref) != nil || !ref.valid() {
		return ref, ErrInvalid
	}
	canonical, _ := json.Marshal(ref)
	if !bytes.Equal(canonical, image.Data) {
		return ref, ErrInvalid
	}
	return ref, nil
}

// ArtifactFileTarget retains the SAME per-file writer lease as FileTarget.
// Its journal scope must name the artifact image format, destination mode and
// trusted artifact root; it is not interchangeable with a byte-image target.
// Component ownership and process inactivity remain the caller's obligations.
type ArtifactFileTarget struct {
	closeMu       sync.Mutex
	closed        bool
	closeErr      error
	file          *FileTarget
	artifacts     *ownedfs.Root
	artifactPath  string
	artifactOwner os.FileInfo
	targetPath    string
	targetOwner   os.FileInfo
}

func OpenArtifactExecutableTarget(path, artifacts string) (*ArtifactFileTarget, error) {
	return openArtifactExecutableTarget(path, artifacts, false)
}
func OpenExistingArtifactExecutableTarget(path, artifacts string) (*ArtifactFileTarget, error) {
	return openArtifactExecutableTarget(path, artifacts, true)
}
func openArtifactExecutableTarget(path, artifacts string, existing bool) (*ArtifactFileTarget, error) {
	if runtime.GOOS != "linux" || !filepath.IsAbs(artifacts) || filepath.Clean(artifacts) != artifacts {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(artifacts)
	if err != nil || !info.IsDir() || !existingOwner(info, true) {
		return nil, ErrUnavailable
	}
	root, err := ownedfs.Open(artifacts)
	if err != nil {
		return nil, err
	}
	held, err := root.RootInfo()
	if err != nil || !os.SameFile(info, held) {
		_ = root.Close()
		return nil, ErrConflict
	}
	f, err := openFileTargetMode(path, existing, 0755)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	full, err := targetPath(path)
	parent, statErr := f.root.RootInfo()
	named, pathErr := os.Lstat(filepath.Dir(full))
	if err != nil || statErr != nil || pathErr != nil || !os.SameFile(parent, named) || !existingOwner(parent, false) {
		_ = f.Close()
		_ = root.Close()
		return nil, ErrUnavailable
	}
	return &ArtifactFileTarget{file: f, artifacts: root, artifactPath: artifacts, artifactOwner: info, targetPath: full, targetOwner: parent}, nil
}
func (t *ArtifactFileTarget) Binding() string {
	return sum([]byte("artifact-file-v1:0755\x00" + t.file.Binding() + "\x00" + t.artifactPath))
}
func (t *ArtifactFileTarget) Close() error {
	if t == nil || t.file == nil {
		return ErrUnavailable
	}
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	if t.closed {
		return t.closeErr
	}
	t.closed = true
	t.closeErr = errors.Join(t.file.Close(), t.artifacts.Close())
	return t.closeErr
}
func (t *ArtifactFileTarget) current() error {
	if t == nil || t.file == nil || t.file.closed || t.artifacts == nil {
		return ErrUnavailable
	}
	if err := t.file.checkExistingLease(); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(t.targetPath))
	heldParent, parentErr := t.file.root.RootInfo()
	if err != nil || parentErr != nil || !os.SameFile(parent, t.targetOwner) || !os.SameFile(heldParent, t.targetOwner) || !existingOwner(parent, false) || !existingOwner(heldParent, false) {
		return ErrConflict
	}
	path, err := os.Lstat(t.artifactPath)
	if err != nil || !os.SameFile(path, t.artifactOwner) || !existingOwner(path, true) {
		return ErrConflict
	}
	held, err := t.artifacts.RootInfo()
	if err != nil || !os.SameFile(held, t.artifactOwner) || !existingOwner(held, true) {
		return ErrConflict
	}
	return nil
}

type artifactContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r artifactContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func artifactFileImage(ctx context.Context, root *ownedfs.Root, name string, mode os.FileMode) (Image, os.FileInfo, error) {
	if ctx == nil || ctx.Err() != nil {
		return Image{}, nil, ErrAborted
	}
	before, err := root.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return Image{}, nil, nil
	}
	if err != nil || !before.Mode().IsRegular() || !existingOwner(before, false) || before.Mode().Perm() != mode || before.Size() < 1 || before.Size() > ownedfs.MaxAtomicArtifactBytes {
		return Image{}, nil, ErrInvalid
	}
	f, err := openReadOnly(root, name)
	if err != nil {
		return Image{}, nil, err
	}
	held, statErr := f.Stat()
	if statErr != nil || !samePublicationFile(before, held) {
		_ = f.Close()
		return Image{}, nil, ErrConflict
	}
	hash := sha256.New()
	n, readErr := io.CopyBuffer(hash, io.LimitReader(artifactContextReader{ctx, f}, before.Size()+1), make([]byte, 64<<10))
	afterFD, fdErr := f.Stat()
	closeErr := f.Close()
	after, pathErr := root.Stat(name)
	if readErr != nil || fdErr != nil || closeErr != nil || pathErr != nil || !samePublicationFile(held, afterFD) || !samePublicationFile(held, after) || !existingOwner(after, false) || n != before.Size() || after.Size() != n || afterFD.Size() != n || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(afterFD.ModTime()) {
		return Image{}, nil, errors.Join(ErrConflict, readErr, fdErr, closeErr, pathErr)
	}
	image, err := ArtifactImage(hex.EncodeToString(hash.Sum(nil)), n)
	return image, held, err
}

func (t *ArtifactFileTarget) source(ctx context.Context, ref artifactReference) (*os.File, os.FileInfo, error) {
	if err := t.current(); err != nil {
		return nil, nil, err
	}
	name := ref.SHA256 + ".bin"
	image, info, err := artifactFileImage(ctx, t.artifacts, name, 0555)
	wanted, _ := ArtifactImage(ref.SHA256, ref.Size)
	if err != nil || !equal(image, wanted) {
		return nil, nil, errors.Join(ErrConflict, err)
	}
	f, err := openReadOnly(t.artifacts, name)
	if err != nil {
		return nil, nil, err
	}
	held, err := f.Stat()
	if err != nil || !samePublicationFile(info, held) || !info.ModTime().Equal(held.ModTime()) || held.Size() != ref.Size || !existingOwner(held, false) {
		_ = f.Close()
		return nil, nil, ErrConflict
	}
	return f, held, nil
}
func (t *ArtifactFileTarget) read(ctx context.Context) (Image, os.FileInfo, error) {
	if err := t.current(); err != nil {
		return Image{}, nil, err
	}
	image, info, err := artifactFileImage(ctx, t.file.root, t.file.name, 0755)
	if err != nil || !image.Exists {
		return image, info, err
	}
	ref, err := artifactImageReference(image)
	if err != nil {
		return Image{}, nil, err
	}
	source, _, err := t.source(ctx, ref)
	if err != nil {
		return Image{}, nil, err
	}
	if err := source.Close(); err != nil {
		return Image{}, nil, err
	}
	return image, info, t.current()
}
func (t *ArtifactFileTarget) Read(ctx context.Context) (Image, error) {
	if t == nil || t.file == nil {
		return Image{}, ErrUnavailable
	}
	t.file.mu.Lock()
	defer t.file.mu.Unlock()
	image, _, err := t.read(ctx)
	return image, err
}
func (t *ArtifactFileTarget) CompareAndSwap(ctx context.Context, before, after Image) error {
	return t.CompareAndSwapWithRenameAdmission(ctx, before, after, func(_ context.Context, rename func() error) error { return rename() })
}
func (t *ArtifactFileTarget) CompareAndSwapWithRenameAdmission(ctx context.Context, before, after Image, admit func(context.Context, func() error) error) (result error) {
	if t == nil || t.file == nil || ctx == nil || admit == nil {
		return ErrInvalid
	}
	t.file.mu.Lock()
	defer t.file.mu.Unlock()
	if !validImage(before) || !validImage(after) {
		return ErrInvalid
	}
	current, original, err := t.read(ctx)
	if err != nil {
		return err
	}
	if !equal(current, before) {
		return ErrConflict
	}
	if equal(before, after) {
		return t.current()
	}
	if !after.Exists {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := t.file.root.Remove(t.file.name); err != nil {
			return &filePublicationError{ErrRecovery, err}
		}
		if err := t.file.syncDir(); err != nil {
			return &filePublicationError{ErrRecovery, err}
		}
		current, _, err = t.read(ctx)
		if err != nil || current.Exists {
			return &filePublicationError{ErrRecovery, errors.Join(ErrConflict, err)}
		}
		return t.current()
	}
	ref, err := artifactImageReference(after)
	if err != nil {
		return err
	}
	source, sourceInfo, err := t.source(ctx, ref)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, source.Close()) }()
	raw, _ := hex.DecodeString(ref.SHA256)
	var digest [32]byte
	copy(digest[:], raw)
	attempted, err := t.file.root.WriteAtomicStreamWithRenameAdmission(ctx, t.file.name, source, ref.Size, digest, 0755, func(rename func() error) error { return admit(ctx, rename) }, func() error {
		if err := t.current(); err != nil {
			return err
		}
		fresh, closing, err := t.read(ctx)
		if err != nil || !equal(fresh, before) || !samePublicationFile(original, closing) {
			return errors.Join(ErrConflict, err)
		}
		actual, err := source.Stat()
		path, pathErr := t.artifacts.Stat(ref.SHA256 + ".bin")
		if err != nil || pathErr != nil || !samePublicationFile(sourceInfo, actual) || !samePublicationFile(sourceInfo, path) || actual.Size() != ref.Size || !actual.ModTime().Equal(sourceInfo.ModTime()) || !existingOwner(path, false) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		kind := ErrRecovery
		if !attempted && !errors.Is(err, ownedfs.ErrStagedCleanup) {
			kind = ErrAborted
		}
		return &filePublicationError{kind, err}
	}
	if err := t.file.syncDir(); err != nil {
		return &filePublicationError{ErrRecovery, err}
	}
	current, _, err = t.read(ctx)
	if err != nil || !equal(current, after) {
		return &filePublicationError{ErrRecovery, errors.Join(ErrConflict, err)}
	}
	return t.current()
}
