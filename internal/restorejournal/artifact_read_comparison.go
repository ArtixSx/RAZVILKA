package restorejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type artifactReadFileID struct {
	device, inode, rdev, links                         uint64
	mode, uid, gid                                     uint32
	size, blocks, blocksize                            int64
	mtimeSeconds, mtimeNanos, ctimeSeconds, ctimeNanos int64
}

// ArtifactSourceComparison is only a synchronous comparison with the actual
// descriptor whose complete bytes were hashed in this read. It is never an
// image, a writer/admission token, a native owner or a reusable hash cache.
type ArtifactSourceComparison struct {
	mu            sync.Mutex
	self          *ArtifactSourceComparison
	target        *ArtifactFileTarget
	ctx           context.Context
	open          bool
	hashed        *os.File
	managedHeld   *os.File // Optional exact managed hash FD, retained by expected-image reader.
	poolName      string
	pool, managed artifactReadFileID
}
type artifactSourceComparisonKey struct{}

func (*ArtifactSourceComparison) String() string { return "[private synchronous artifact comparison]" }
func (*ArtifactSourceComparison) GoString() string {
	return "[private synchronous artifact comparison]"
}

func artifactComparisonContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrAborted, err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrInvalid
	}
	if !time.Now().Before(deadline) {
		return errors.Join(ErrAborted, context.DeadlineExceeded)
	}
	return nil
}

// WithReadComparison retains the per-file writer lease/mutex and the ACTUAL
// hashed pool descriptor throughout a pure read callback. Callback code must
// not reenter this target or perform effects. Default Read/CAS are unchanged.
func (t *ArtifactFileTarget) WithReadComparison(ctx context.Context, read func(context.Context, Image, *ArtifactSourceComparison) error) (result error) {
	if t == nil || t.file == nil || read == nil {
		return ErrUnavailable
	}
	if err := artifactComparisonContext(ctx); err != nil {
		return err
	}
	t.file.mu.Lock()
	defer t.file.mu.Unlock()
	if err := t.current(); err != nil {
		return err
	}
	image, managedInfo, err := artifactFileImage(ctx, t.file.root, t.file.name, 0755)
	if err != nil || !image.Exists {
		return errors.Join(ErrConflict, err)
	}
	managed, err := artifactReadFingerprint(managedInfo)
	if err != nil {
		return err
	}
	ref, err := artifactImageReference(image)
	if err != nil {
		return err
	}
	if err := t.current(); err != nil {
		return err
	}
	name := ref.SHA256 + ".bin"
	hashed, pool, source, err := artifactReadHashedDescriptor(ctx, t.artifacts, name)
	if err != nil {
		return err
	}
	// Preserve the original source reopen/owner/identity comparison, but do
	// not substitute that reopened descriptor for the one actually hashed.
	proof := &ArtifactSourceComparison{target: t, hashed: hashed, poolName: name, pool: pool, managed: managed, open: true}
	proof.self = proof
	proof.ctx = context.WithValue(ctx, artifactSourceComparisonKey{}, proof)
	defer func() {
		proof.mu.Lock()
		proof.open = false // waits for every in-flight MatchHeld comparison
		closing := proof.currentLocked()
		closeErr := proof.hashed.Close()
		proof.mu.Unlock()
		result = errors.Join(result, closing, closeErr, artifactComparisonContext(ctx))
	}()
	if !equal(source, image) {
		return ErrConflict
	}
	reopened, err := openReadOnly(t.artifacts, name)
	if err != nil {
		return err
	}
	held, statErr := reopened.Stat()
	heldID, idErr := artifactReadFingerprint(held)
	closeErr := reopened.Close()
	if statErr != nil || idErr != nil || closeErr != nil || heldID != pool || held.Size() != ref.Size || !existingOwner(held, false) {
		return errors.Join(ErrConflict, statErr, idErr, closeErr)
	}
	if err := proof.currentLocked(); err != nil {
		return err
	}
	return read(proof.ctx, Image{Exists: image.Exists, Data: append([]byte(nil), image.Data...)}, proof)
}

func artifactReadHashedDescriptor(ctx context.Context, root *ownedfs.Root, name string) (file *os.File, id artifactReadFileID, image Image, result error) {
	if err := artifactComparisonContext(ctx); err != nil {
		return nil, id, image, err
	}
	before, err := root.Stat(name)
	if err != nil || !before.Mode().IsRegular() || !existingOwner(before, false) || before.Mode().Perm() != 0555 || before.Size() < 1 || before.Size() > ownedfs.MaxAtomicArtifactBytes {
		return nil, id, image, ErrInvalid
	}
	wanted, err := artifactReadFingerprint(before)
	if err != nil {
		return nil, id, image, err
	}
	file, err = openReadOnly(root, name)
	if err != nil {
		return nil, id, image, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, file.Close())
			file = nil
		}
	}()
	held, err := file.Stat()
	actual, fpErr := artifactReadFingerprint(held)
	if err != nil || fpErr != nil || actual != wanted {
		return file, id, image, errors.Join(ErrConflict, err, fpErr)
	}
	hash := sha256.New()
	n, readErr := io.CopyBuffer(hash, io.LimitReader(artifactContextReader{ctx, file}, before.Size()+1), make([]byte, 64<<10))
	afterFD, fdErr := file.Stat()
	after, statErr := root.Stat(name)
	afterID, afterErr := artifactReadFingerprint(after)
	fdID, fdIDErr := artifactReadFingerprint(afterFD)
	if readErr != nil || fdErr != nil || statErr != nil || afterErr != nil || fdIDErr != nil || wanted != afterID || wanted != fdID || !existingOwner(after, false) || n != before.Size() {
		return file, id, image, errors.Join(ErrConflict, readErr, fdErr, statErr, afterErr, fdIDErr)
	}
	image, err = ArtifactImage(hex.EncodeToString(hash.Sum(nil)), n)
	if err != nil {
		return file, id, image, err
	}
	return file, wanted, image, nil
}

func (p *ArtifactSourceComparison) currentLocked() error {
	if p == nil || p.self != p || p.target == nil || p.hashed == nil {
		return ErrUnavailable
	}
	if err := p.target.current(); err != nil {
		return err
	}
	managed, managedErr := p.target.file.root.Stat(p.target.file.name)
	pool, poolErr := p.target.artifacts.Stat(p.poolName)
	hashed, hashErr := p.hashed.Stat()
	managedID, managedIDErr := artifactReadFingerprint(managed)
	poolID, poolIDErr := artifactReadFingerprint(pool)
	hashID, hashIDErr := artifactReadFingerprint(hashed)
	if p.managedHeld != nil {
		held, err := p.managedHeld.Stat()
		id, idErr := artifactReadFingerprint(held)
		if err != nil || idErr != nil || id != p.managed {
			return errors.Join(ErrConflict, err, idErr)
		}
	}
	if managedErr != nil || poolErr != nil || hashErr != nil || managedIDErr != nil || poolIDErr != nil || hashIDErr != nil || managedID != p.managed || poolID != p.pool || hashID != p.pool || !existingOwner(managed, false) || !existingOwner(pool, false) || !existingOwner(hashed, false) {
		return errors.Join(ErrConflict, managedErr, poolErr, hashErr, managedIDErr, poolIDErr, hashIDErr)
	}
	return p.target.current()
}

// MatchHeld accepts a duplicate of the same actual hashed file, never a
// same-byte different inode or a descriptor replaced since the hash read.
func (p *ArtifactSourceComparison) MatchHeld(ctx context.Context, held *os.File) error {
	if p == nil {
		return ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.self != p || !p.open || p.ctx == nil || held == nil || ctx == nil || ctx.Value(artifactSourceComparisonKey{}) != p {
		return ErrUnavailable
	}
	if err := errors.Join(artifactComparisonContext(p.ctx), artifactComparisonContext(ctx)); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	original, _ := p.ctx.Deadline()
	if deadline.After(original) {
		return ErrUnavailable
	}
	opening := p.currentLocked()
	before, err := held.Stat()
	beforeID, beforeErr := artifactReadFingerprint(before)
	after, afterErr := held.Stat()
	afterID, afterIDErr := artifactReadFingerprint(after)
	closing := p.currentLocked()
	if err != nil || beforeErr != nil || afterErr != nil || afterIDErr != nil || beforeID != p.pool || afterID != p.pool || !existingOwner(before, false) || !existingOwner(after, false) {
		return errors.Join(ErrConflict, opening, err, beforeErr, afterErr, afterIDErr, closing)
	}
	return errors.Join(opening, closing, artifactComparisonContext(ctx), artifactComparisonContext(p.ctx))
}
