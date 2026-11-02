package restorejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// WithExpectedReadComparison hashes BOTH complete original files. The already
// held immutable expected image selects the pool name; it never substitutes
// for either byte read. Two independent retained FDs/ReadAt streams permit
// parallel hashing without sharing offsets. Ordinary Read/CAS remain unchanged.
func (t *ArtifactFileTarget) WithExpectedReadComparison(ctx context.Context, expected Image, read func(context.Context, Image, *ArtifactSourceComparison) error) error {
	return t.withExpectedReadComparison(ctx, expected, read, nil)
}

type expectedArtifactRead struct {
	file       *os.File
	id         artifactReadFileID
	image      Image
	err        error
	panicValue any
	returned   bool
}

// Public/default callers never supply the private model fault seam.
func (t *ArtifactFileTarget) withExpectedReadComparison(ctx context.Context, expected Image, read func(context.Context, Image, *ArtifactSourceComparison) error, fault func(string, string) error) (result error) {
	if t == nil || t.file == nil || read == nil {
		return ErrUnavailable
	}
	if err := artifactComparisonContext(ctx); err != nil {
		return err
	}
	ref, err := artifactImageReference(expected)
	if err != nil || !expected.Exists {
		return errors.Join(ErrInvalid, err)
	}
	t.file.mu.Lock()
	defer t.file.mu.Unlock()
	if err := t.current(); err != nil {
		return err
	}
	name := ref.SHA256 + ".bin"
	managedOpening, err := t.file.root.Stat(t.file.name)
	if err != nil {
		return err
	}
	managedID, err := artifactReadFingerprint(managedOpening)
	if err != nil {
		return err
	}
	poolOpening, err := t.artifacts.Stat(name)
	if err != nil {
		return err
	}
	poolID, err := artifactReadFingerprint(poolOpening)
	if err != nil {
		return err
	}
	var managed, pool expectedArtifactRead
	var proof *ArtifactSourceComparison
	var workers sync.WaitGroup
	// All started workers are joined before ANY descriptor close, callback,
	// error or panic leaves this invocation. No reader borrows a shared offset.
	defer func() {
		workers.Wait()
		if proof != nil {
			proof.mu.Lock()
			proof.open = false
			result = errors.Join(result, proof.currentLocked())
			proof.mu.Unlock()
		}
		for _, file := range []*os.File{managed.file, pool.file} {
			if file != nil {
				result = errors.Join(result, file.Close())
			}
		}
		result = errors.Join(result, artifactComparisonContext(ctx))
	}()
	launch := func(out *expectedArtifactRead, root *ownedfs.Root, name, role string, mode os.FileMode) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				if value := recover(); value != nil {
					out.panicValue = value
				}
			}()
			out.file, out.id, out.image, out.err = expectedArtifactHashDescriptor(ctx, root, name, role, mode, fault)
			out.returned = true
		}()
	}
	launch(&managed, t.file.root, t.file.name, "managed", 0755)
	launch(&pool, t.artifacts, name, "pool", 0555)
	workers.Wait()
	if managed.panicValue != nil {
		panic(managed.panicValue)
	}
	if pool.panicValue != nil {
		panic(pool.panicValue)
	}
	if !managed.returned || !pool.returned {
		return ErrUnavailable
	}
	if err := errors.Join(managed.err, pool.err); err != nil {
		return err
	}
	if managed.id != managedID || pool.id != poolID || !equal(managed.image, expected) || !equal(pool.image, expected) {
		return ErrConflict
	}
	if err := artifactComparisonContext(ctx); err != nil {
		return err
	}
	if err := t.current(); err != nil {
		return err
	}
	if fault != nil {
		if err := fault("joined", "before-reopen"); err != nil {
			return err
		}
	}
	// Preserve the independent fresh pool reopen/owner comparison and its
	// Close ACK; this descriptor never replaces either actual hash reader.
	reopened, err := openReadOnly(t.artifacts, name)
	if err != nil {
		return err
	}
	held, statErr := reopened.Stat()
	heldID, idErr := artifactReadFingerprint(held)
	closeErr := reopened.Close()
	if statErr != nil || idErr != nil || closeErr != nil || heldID != pool.id || held.Size() != ref.Size || !existingOwner(held, false) {
		return errors.Join(ErrConflict, statErr, idErr, closeErr)
	}
	proof = &ArtifactSourceComparison{target: t, hashed: pool.file, managedHeld: managed.file, poolName: name, pool: pool.id, managed: managed.id, open: true}
	proof.self = proof
	proof.ctx = context.WithValue(ctx, artifactSourceComparisonKey{}, proof)
	if err := proof.currentLocked(); err != nil {
		return err
	}
	return read(proof.ctx, Image{Exists: true, Data: append([]byte(nil), managed.image.Data...)}, proof)
}

func expectedArtifactHashDescriptor(ctx context.Context, root *ownedfs.Root, name, role string, mode os.FileMode, fault func(string, string) error) (file *os.File, id artifactReadFileID, image Image, result error) {
	if err := artifactComparisonContext(ctx); err != nil {
		return nil, id, image, err
	}
	before, err := root.Stat(name)
	if err != nil || !before.Mode().IsRegular() || !existingOwner(before, false) || before.Mode().Perm() != mode || before.Size() < 1 || before.Size() > ownedfs.MaxAtomicArtifactBytes {
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
	returned := false
	defer func() {
		if !returned || result != nil {
			result = errors.Join(result, file.Close())
			file = nil
		}
	}()
	held, err := file.Stat()
	actual, fpErr := artifactReadFingerprint(held)
	if err != nil || fpErr != nil || actual != wanted {
		return file, id, image, errors.Join(ErrConflict, err, fpErr)
	}
	if fault != nil {
		if err := fault(role, "opened"); err != nil {
			return file, id, image, err
		}
	}
	hash := sha256.New()
	// SectionReader uses ReadAt on this retained FD; native MatchHeld and the
	// other hash stream can never alter its offset or replace its descriptor.
	n, readErr := io.CopyBuffer(hash, artifactContextReader{ctx, io.NewSectionReader(file, 0, before.Size()+1)}, make([]byte, 64<<10))
	if fault != nil {
		if err := fault(role, "hashed"); err != nil {
			return file, id, image, err
		}
	}
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
	returned = true
	return file, wanted, image, nil
}
