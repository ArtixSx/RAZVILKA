package components

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// HEVReplacementReview belongs to one original component writer. It compares
// original bytes; it never adopts/stops a process or grants runtime inactivity.
// Only acknowledged forward CAS changes the expected binary/receipt/lifecycle.
type HEVReplacementReview struct {
	mu                     sync.Mutex
	self                   *HEVReplacementReview
	manager                *Manager
	session                *hevReleaseSession
	originalSession        *hevReleaseSession
	files                  map[string]*restorejournal.FileTarget
	paths                  map[string]string
	stateDir, binDir, arch string
	old                    restorejournal.Image
	oldSHA                 [32]byte
	desired                restorejournal.Image
	desiredSHA             [32]byte
	expected               map[string]restorejournal.Image
	next                   int
	closed, failed         bool
}

var hevReplacementOrder = [...]string{"a_binary", "b_receipt", "c_lifecycle"}

func cloneHEVImage(i restorejournal.Image) restorejournal.Image {
	return restorejournal.Image{Exists: i.Exists, Data: append([]byte(nil), i.Data...)}
}
func sameHEVImage(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}

func newHEVReplacementReview(ctx context.Context, m *Manager, s *hevReleaseSession, original map[string]restorejournal.Image, desired restorejournal.Image) (*HEVReplacementReview, error) {
	if ctx == nil || m == nil || s == nil || s.owner != m || s.replacement != nil || len(original) != 3 {
		return nil, ErrRecoveryAuthority
	}
	old := original["a_binary"]
	if !old.Exists || len(old.Data) == 0 || len(old.Data) > restorejournal.MaxImageBytes || !desired.Exists || len(desired.Data) == 0 || len(desired.Data) > restorejournal.MaxImageBytes {
		return nil, ErrRecoveryAuthority
	}
	r := &HEVReplacementReview{manager: m, session: s, originalSession: s, stateDir: m.StateDir, binDir: m.BinDir, arch: m.Arch, old: cloneHEVImage(old), oldSHA: sha256.Sum256(old.Data), desired: cloneHEVImage(desired), desiredSHA: sha256.Sum256(desired.Data), expected: map[string]restorejournal.Image{}, files: map[string]*restorejournal.FileTarget{}, paths: map[string]string{}}
	r.self = r
	for _, id := range hevReplacementOrder {
		image, ok := original[id]
		if !ok || s.files[id] == nil {
			r.close()
			return nil, ErrRecoveryAuthority
		}
		r.expected[id] = cloneHEVImage(image)
		r.files[id] = s.files[id]
		r.paths[id] = s.paths[id]
	}
	s.replacement = r
	if err := r.Current(ctx); err != nil {
		s.replacement = nil
		r.close()
		return nil, err
	}
	return r, nil
}
func (r *HEVReplacementReview) identityLocked() bool {
	return r.self == r && !r.closed && !r.failed && r.manager != nil && r.session != nil && r.session == r.originalSession && r.session.owner == r.manager && r.session.replacement == r && r.manager.StateDir == r.stateDir && r.manager.BinDir == r.binDir && r.manager.Arch == r.arch
}

// OwnedBy is an identity comparison only, never an inactivity grant.
func (r *HEVReplacementReview) OwnedBy(m *Manager) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.identityLocked() && r.manager == m
}
func (r *HEVReplacementReview) Current(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrRecoveryAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentLocked(ctx)
}
func (r *HEVReplacementReview) currentLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !r.identityLocked() {
		return ErrRecoveryAuthority
	}
	for _, id := range hevReplacementOrder {
		if r.session.files[id] != r.files[id] || r.session.paths[id] != r.paths[id] {
			return ErrRecoveryAuthority
		}
		actual, err := r.files[id].Read(ctx)
		if err != nil || !sameHEVImage(actual, r.expected[id]) {
			return errors.Join(restorejournal.ErrConflict, err)
		}
	}
	return ctx.Err()
}

// MatchesProcessImage observes fresh complete bounded file bytes and closing
// FD/path metadata. Both old and desired bytes are refusal comparisons; the
// old image remains available after binary CAS. Neither is a process exemption.
func (r *HEVReplacementReview) MatchesProcessImage(ctx context.Context, path string) (bool, error) {
	if r == nil || ctx == nil {
		return false, ErrRecoveryAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.currentLocked(ctx); err != nil {
		return false, err
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
	if before.Size() != int64(len(r.old.Data)) && before.Size() != int64(len(r.desired.Data)) {
		return false, r.currentLocked(ctx)
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	defer clear(buf)
	n, err := io.CopyBuffer(h, io.LimitReader(hevReplacementContextReader{ctx, f}, before.Size()+1), buf)
	if err != nil || n != before.Size() {
		return false, errors.Join(restorejournal.ErrConflict, err)
	}
	after, statErr := f.Stat()
	named, namedErr := os.Stat(path)
	if statErr != nil || namedErr != nil || !os.SameFile(before, after) || !os.SameFile(before, named) || before.Mode() != after.Mode() || before.Mode() != named.Mode() || before.Size() != after.Size() || before.Size() != named.Size() || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(named.ModTime()) {
		return false, restorejournal.ErrConflict
	}
	if err := r.currentLocked(ctx); err != nil {
		return false, err
	}
	digest := h.Sum(nil)
	return before.Size() == int64(len(r.old.Data)) && bytes.Equal(digest, r.oldSHA[:]) || before.Size() == int64(len(r.desired.Data)) && bytes.Equal(digest, r.desiredSHA[:]), nil
}

type hevReplacementContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r hevReplacementContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
func (r *HEVReplacementReview) acknowledge(id string, before, after restorejournal.Image, casErr error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.identityLocked() || r.next >= len(hevReplacementOrder) || hevReplacementOrder[r.next] != id || !sameHEVImage(r.expected[id], before) {
		r.failed = true
		return ErrRecoveryAuthority
	}
	if casErr != nil {
		r.failed = true
		return casErr
	}
	clear(r.expected[id].Data)
	r.expected[id] = cloneHEVImage(after)
	r.next++
	return nil
}
func (r *HEVReplacementReview) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	clear(r.old.Data)
	clear(r.oldSHA[:])
	clear(r.desired.Data)
	clear(r.desiredSHA[:])
	for _, image := range r.expected {
		clear(image.Data)
	}
}
