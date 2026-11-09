package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"sync/atomic"
	"time"
)

const xrayDomainTCPImageScratchLimit = 64 << 20

// One process-wide storage slot, never an observation or cached digest. Its
// first allocation fixes capacity: a later larger image uses the original SHA
// path, even when below the limit. No waiting, resizing or second backing array.
// Retained backing is bounded; this is not a bound on allocator/GC RSS.
type xrayDomainTCPImageScratch struct {
	busy atomic.Bool
	data []byte
}

var domainTCPImageScratch xrayDomainTCPImageScratch

type xrayDomainTCPImageLease struct {
	self    *xrayDomainTCPImageLease
	scratch *xrayDomainTCPImageScratch
	closed  atomic.Bool
	data    []byte
}

func (s *xrayDomainTCPImageScratch) borrow(size int64) *xrayDomainTCPImageLease {
	if s == nil || size <= 0 || size > xrayDomainTCPImageScratchLimit || !s.busy.CompareAndSwap(false, true) {
		return nil
	}
	keep := false
	defer func() {
		if !keep {
			s.busy.Store(false) // Also releases the slot if allocation panics.
		}
	}()
	if s.data == nil {
		finish := domainTCPMeasure("executable-image-storage")
		s.data = make([]byte, size)
		finish(size)
	}
	if int64(len(s.data)) < size {
		return nil
	}
	keep = true
	l := &xrayDomainTCPImageLease{scratch: s, data: s.data[:size]}
	l.self = l
	return l
}

func (l *xrayDomainTCPImageLease) release() {
	if l != nil && l.self == l && l.closed.CompareAndSwap(false, true) {
		clear(l.scratch.data)
		l.scratch.busy.Store(false)
	}
}

// This object stays local to the outer synchronous observation. It
// is never installed in a file view, context, resource or callback argument.
// Every independent opening authenticates freshly captured bytes with SHA;
// closing rereads every byte, even after a mismatch, with the same32KiB reads.
type xrayDomainTCPImageRead struct {
	self       *xrayDomainTCPImageRead
	resource   *XrayDomainTCPExecutionResource
	executable *xrayDomainTCPExecutable
	file       *os.File
	info       os.FileInfo
	path, hash string
	ctx        context.Context
	deadline   time.Time
	lease      *xrayDomainTCPImageLease
	phase      atomic.Uint32 // 0=new, 1=capturing, 2=authenticated, 3=closing, 4=revoked
}

func (r *XrayDomainTCPExecutionResource) borrowFileObservationImage(ctx context.Context) *xrayDomainTCPImageRead {
	if r == nil || r.self != r || r.descriptorsClosed.Load() || r.root == nil || r.config == nil || r.configInfo == nil || r.executable == nil || r.executable.file == nil || r.executable.info == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || xraySelectedTCPFinite(ctx) != nil {
		return nil
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return nil
	}
	lease := domainTCPImageScratch.borrow(r.executable.info.Size())
	if lease == nil {
		return nil
	}
	p := r.executable
	i := &xrayDomainTCPImageRead{resource: r, executable: p, file: p.file, info: p.info, path: p.path, hash: p.sha256, ctx: ctx, deadline: deadline, lease: lease}
	i.self = i
	return i
}

func (i *xrayDomainTCPImageRead) belongsTo(r *XrayDomainTCPExecutionResource) bool {
	return i != nil && i.self == i && i.lease != nil && i.lease.self == i.lease && !i.lease.closed.Load() && i.info != nil && int64(len(i.lease.data)) == i.info.Size() && r != nil && r.self == r && i.resource == r && i.executable == r.executable && r.executable != nil && i.file == r.executable.file && i.info == r.executable.info && i.path == r.executable.path && i.hash == r.executable.sha256
}

func (i *xrayDomainTCPImageRead) contextCurrent(ctx context.Context) error {
	if i == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != i.ctx {
		return ErrXrayDomainTCPOriginal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(i.deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (i *xrayDomainTCPImageRead) captured() bool { return i != nil && i.phase.Load() == 2 }

func (i *xrayDomainTCPImageRead) release() {
	if i != nil && i.self == i {
		i.phase.Store(4)
		i.lease.release()
	}
}

func (i *xrayDomainTCPImageRead) current(ctx context.Context) (result error) {
	if i == nil {
		return ErrXrayDomainTCPOriginal
	}
	if !i.belongsTo(i.resource) || i.contextCurrent(ctx) != nil {
		return errors.Join(ErrXrayDomainTCPOriginal, i.contextCurrent(ctx))
	}
	opening := i.phase.CompareAndSwap(0, 1)
	if !opening && !i.phase.CompareAndSwap(2, 3) {
		return ErrXrayDomainTCPOriginal
	}
	defer func() {
		if result != nil || !opening {
			i.phase.Store(4)
		}
	}()
	p := i.executable
	if err := p.metadataCurrent(ctx); err != nil {
		return err
	}
	name := "executable-image-compare"
	if opening {
		name = "executable-image-capture"
	}
	finish := domainTCPMeasure(name)
	var readBytes int64
	defer func() { finish(readBytes) }()
	h := sha256.New()
	var block [32 << 10]byte
	equal := true
	var readErr error
	for offset := int64(0); offset < i.info.Size(); {
		if readErr = ctx.Err(); readErr != nil {
			break
		}
		want := min(int64(len(block)), i.info.Size()-offset)
		target := block[:want]
		if opening {
			target = i.lease.data[offset : offset+want]
		}
		n, err := i.file.ReadAt(target, offset)
		readBytes += int64(n)
		if int64(n) != want || err != nil && err != io.EOF {
			readErr = errors.Join(ErrXrayDomainTCPOriginal, err)
			break
		}
		if readErr = ctx.Err(); readErr != nil {
			break
		}
		if opening {
			_, _ = h.Write(target)
		} else if !bytes.Equal(target, i.lease.data[offset:offset+want]) {
			equal = false
		}
		offset += int64(n)
	}
	closing := errors.Join(p.metadataCurrent(ctx), i.contextCurrent(ctx))
	if readErr != nil || closing != nil || !i.belongsTo(i.resource) || !equal || opening && hex.EncodeToString(h.Sum(nil)) != i.hash {
		return errors.Join(ErrXrayDomainTCPOriginal, readErr, closing)
	}
	if opening && !i.phase.CompareAndSwap(1, 2) {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}
