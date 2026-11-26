package components

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Private comparison only, issued from the same held native descriptor around
// a full byte read. It never escapes a synchronous observation callback.
type mihomoLiveReadFileID struct {
	device, inode, rdev, links                         uint64
	mode, uid, gid                                     uint32
	size, blocks, blocksize                            int64
	mtimeSeconds, mtimeNanos, ctimeSeconds, ctimeNanos int64
}
type mihomoLiveReadFingerprint struct {
	child  *MihomoLiveProcess
	native mihomoLiveNative
	file   mihomoLiveReadFileID
}

func (p *MihomoLiveProcess) readFingerprint(ctx context.Context) (*mihomoLiveReadFingerprint, error) {
	if p == nil || p.self != p {
		return nil, ErrMihomoLiveOwner
	}
	if err := mihomoLiveFinite(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.native == nil {
		return nil, ErrMihomoLiveOwner
	}
	file, err := p.native.readFingerprint(ctx)
	if err != nil {
		return nil, err
	}
	return &mihomoLiveReadFingerprint{child: p, native: p.native, file: file}, nil
}
func (f *mihomoLiveReadFingerprint) same(g *mihomoLiveReadFingerprint) bool {
	return f != nil && g != nil && f.child == g.child && f.native == g.native && f.file == g.file
}
func (p *MihomoLiveProcess) currentReadBoundary(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) error {
	return p.currentNativeReadComparison(ctx, cleanup)
}
func (p *MihomoLiveProcess) openReadFingerprint(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) (*mihomoLiveReadFingerprint, error) {
	before, err := p.readFingerprint(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.currentReadBoundary(ctx, cleanup); err != nil {
		return nil, err
	}
	after, err := p.readFingerprint(ctx)
	if err != nil || !before.same(after) {
		return nil, errors.Join(ErrMihomoLiveOwner, err)
	}
	return before, nil
}
func (p *MihomoLiveProcess) closeReadFingerprint(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview, original *mihomoLiveReadFingerprint) error {
	before, beforeErr := p.readFingerprint(ctx)
	// Full closing byte comparisons are mandatory even when the metadata
	// changed or the callback already failed. Never short-circuit this read.
	fullErr := p.currentReadBoundary(ctx, cleanup)
	after, afterErr := p.readFingerprint(ctx)
	var identityErr error
	if !original.same(before) || !original.same(after) {
		identityErr = ErrMihomoLiveOwner
	}
	return errors.Join(beforeErr, fullErr, afterErr, identityErr)
}
