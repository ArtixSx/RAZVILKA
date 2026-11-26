package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// MihomoReplacementReview is an original live writer-session comparison. It
// cannot be reconstructed from receipts or used to adopt, stop or start a
// process. Only the acknowledged CAS cursor can change its expected vector.
type MihomoReplacementReview struct {
	mu             sync.Mutex
	self           *MihomoReplacementReview
	manager        *Manager
	session        *mihomoReleaseSession
	root           *ownedfs.Root
	old            restorejournal.Image
	ref            mihomoArtifactReference
	expected       map[string]restorejournal.Image
	next           int
	closed, failed bool
}

func newMihomoReplacementReview(ctx context.Context, m *Manager, s *mihomoReleaseSession, old restorejournal.Image) (*MihomoReplacementReview, error) {
	ref, err := mihomoArtifactReferenceOf(old)
	if err != nil {
		return nil, err
	}
	_, _, artifacts, _, err := m.mihomoReleaseLayout()
	if err != nil {
		return nil, err
	}
	root, err := ownedfs.Open(artifacts)
	if err != nil {
		return nil, err
	}
	r := &MihomoReplacementReview{manager: m, session: s, root: root, old: cloneMihomoImage(old), ref: ref, expected: map[string]restorejournal.Image{}}
	r.self = r
	for _, id := range []string{"a_binary", "b_receipt", "c_lifecycle"} {
		image, err := s.files[id].Read(ctx)
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		r.expected[id] = cloneMihomoImage(image)
	}
	if err := r.Current(ctx); err != nil {
		_ = root.Close()
		return nil, err
	}
	return r, nil
}

func cloneMihomoImage(image restorejournal.Image) restorejournal.Image {
	return restorejournal.Image{Exists: image.Exists, Data: append([]byte(nil), image.Data...)}
}
func sameMihomoImage(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}

// OwnedBy is only an identity comparison, never an inactivity grant.
func (r *MihomoReplacementReview) OwnedBy(m *Manager) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.self == r && !r.closed && !r.failed && r.manager == m
}

func (r *MihomoReplacementReview) Current(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrRecoveryAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}
func (r *MihomoReplacementReview) currentLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.self != r || r.closed || r.failed || r.manager == nil || r.session == nil || r.root == nil {
		return ErrRecoveryAuthority
	}
	for _, id := range []string{"a_binary", "b_receipt", "c_lifecycle"} {
		actual, err := r.session.files[id].Read(ctx)
		if err != nil || !sameMihomoImage(actual, r.expected[id]) {
			return errors.Join(restorejournal.ErrConflict, err)
		}
	}
	return verifyMihomoArtifact(ctx, r.root, r.ref.SHA256+".bin", r.old)
}

// MatchesProcessImage compares complete bounded bytes with the old artifact
// retained by this session. It exposes no serialized process authority.
func (r *MihomoReplacementReview) MatchesProcessImage(ctx context.Context, path string) (bool, error) {
	if r == nil || ctx == nil {
		return false, ErrRecoveryAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.self != r || r.closed || r.failed {
		return false, ErrRecoveryAuthority
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !before.Mode().IsRegular() {
		return false, ErrRecoveryAuthority
	}
	if before.Size() != r.ref.Size {
		return false, nil
	}
	if err := r.currentLocked(ctx); err != nil {
		return false, err
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.LimitReader(mihomoContextReader{ctx, f}, r.ref.Size+1), make([]byte, 64<<10))
	if err != nil || n != r.ref.Size {
		return false, errors.Join(restorejournal.ErrConflict, err)
	}
	after, err := f.Stat()
	named, namedErr := os.Stat(path)
	if err != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return false, restorejournal.ErrConflict
	}
	if err := r.currentLocked(ctx); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == r.ref.SHA256, nil
}

func (r *MihomoReplacementReview) acknowledge(id string, before, after restorejournal.Image, casErr error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order := [...]string{"a_binary", "b_receipt", "c_lifecycle"}
	if r.self != r || r.closed || r.failed || r.next >= len(order) || order[r.next] != id || !sameMihomoImage(r.expected[id], before) {
		r.failed = true
		return ErrRecoveryAuthority
	}
	if casErr != nil {
		r.failed = true
		return casErr
	}
	r.expected[id] = cloneMihomoImage(after)
	r.next++
	return nil
}
func (r *MihomoReplacementReview) close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.root != nil {
		return r.root.Close()
	}
	return nil
}
