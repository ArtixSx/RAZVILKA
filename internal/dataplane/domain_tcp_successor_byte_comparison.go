package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

// Authenticated bytes only. This never supplies an old process observation,
// Current, cleanup or effect grant. The fixed pre-Add, guard and prior readers
// revoke and join byte readers before successor closing/clear.
type domainTCPSuccessorByteComparison struct {
	self   *domainTCPSuccessorByteComparison
	mu     sync.Mutex
	active bool
	loan   *domainTCPPreAddLoan
	guard  *domainTCPGuardReadLoan
	prior  *domainTCPPriorReadLoan
	image  *xrayDomainTCPImageRead
}

type domainTCPPriorByteRead struct {
	self       *domainTCPPriorByteRead
	comparison *domainTCPSuccessorByteComparison
	read       *domainTCPSuccessorRead
	old        *XrayDomainTCPExecutionResource
	executable *xrayDomainTCPExecutable
	file       *os.File
	info       os.FileInfo
	path, hash string
}

// Ordinary observations retain their existing private-image implementation.
// Only this pre-Add producer can bind an authenticated image to a typed loan.
func (r *XrayDomainTCPExecutionResource) withPreAddFileObservation(ctx context.Context, loan *domainTCPPreAddLoan, use func(*xrayDomainTCPFileObservation) error) (result error) {
	if loan == nil || loan.self != loan || loan.ctx != ctx || loan.read == nil || loan.read.self != loan.read || loan.read.process != r || loan.bytes != nil || use == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if r == nil || r.scope == nil || r.scope.domainSuccessor == nil {
		return r.withFileObservation(ctx, use)
	}
	image := r.borrowFileObservationImage(ctx)
	if image == nil {
		return r.withFileObservation(ctx, use)
	}
	defer func() { image.release(); result = errors.Join(result, image.contextCurrent(ctx)) }()
	if err := r.filesCurrentForImageRead(ctx, nil, image); err != nil {
		return err
	}
	return r.withFileObservationAfterOpeningImage(ctx, nil, func(files *xrayDomainTCPFileObservation) error {
		c := &domainTCPSuccessorByteComparison{active: true, loan: loan, image: image}
		c.self = c
		loan.bytes = c
		defer c.revoke()
		return use(files)
	}, image)
}

func (c *domainTCPSuccessorByteComparison) revoke() {
	if c == nil || c.self != c {
		return
	}
	c.mu.Lock()
	c.active = false
	c.mu.Unlock()
}

// Caller holds c.mu. Only local associations and original held metadata are
// inspected here; no provider/tool/control callback runs under this mutex.
func (c *domainTCPSuccessorByteComparison) valid(read *domainTCPSuccessorRead, ctx context.Context, old *XrayDomainTCPExecutionResource) error {
	if c == nil || c.self != c || !c.active || c.image == nil || !c.image.captured() || !c.image.belongsTo(c.image.resource) || c.image.contextCurrent(c.image.ctx) != nil || read == nil || read.process != c.image.resource || read.current(ctx, read.witness, old) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	if c.prior != nil {
		if c.loan != nil || c.guard != nil || read.loan != nil || read.guard != nil || read.priorRead != c.prior || c.prior.bytes != c || c.prior.ctx != c.image.ctx {
			return ErrDomainPolicyTCPConsumer
		}
	} else if read.priorRead != nil {
		return ErrDomainPolicyTCPConsumer
	} else if c.guard != nil {
		if c.loan != nil || read.loan != nil || read.guard != c.guard || c.guard.bytes != c || c.guard.ctx != c.image.ctx {
			return ErrDomainPolicyTCPConsumer
		}
	} else if read.guard != nil || c.loan == nil || c.loan.bytes != c || read.loan != c.loan || c.loan.ctx != c.image.ctx {
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}

func (read *domainTCPSuccessorRead) priorFilesCurrent(ctx context.Context, old *XrayDomainTCPExecutionResource) error {
	if read == nil {
		return old.filesCurrent(ctx)
	}
	if read.current(ctx, read.witness, old) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	var c *domainTCPSuccessorByteComparison
	if read.priorRead != nil {
		c = read.priorRead.bytes
	} else if read.guard != nil {
		c = read.guard.bytes
	} else {
		c = read.loan.bytes
	}
	if c == nil {
		return old.filesCurrent(ctx)
	}
	c.mu.Lock()
	if err := c.valid(read, ctx, old); err != nil {
		c.mu.Unlock()
		return err
	}
	p := old.executable
	if p == nil || p.info == nil || p.file == nil {
		c.mu.Unlock()
		return ErrXrayDomainTCPOriginal
	}
	// A different immutable image is unsupported by this optional comparison.
	// Decide fallback BEFORE binding. A late change to a bound pair must refuse.
	if !os.SameFile(p.info, c.image.info) || p.info.Size() != c.image.info.Size() || p.sha256 != c.image.hash {
		c.mu.Unlock()
		return old.filesCurrent(ctx)
	}
	prior := &domainTCPPriorByteRead{comparison: c, read: read, old: old, executable: p, file: p.file, info: p.info, path: p.path, hash: p.sha256}
	prior.self = prior
	c.mu.Unlock()
	return old.filesCurrentForExecutableComparison(ctx, nil, nil, prior)
}

func (p *domainTCPPriorByteRead) bound(ctx context.Context) error {
	if p == nil || p.self != p || p.comparison == nil || p.old == nil || p.old.executable != p.executable || p.executable == nil || p.executable.file != p.file || p.executable.info != p.info || p.executable.path != p.path || p.executable.sha256 != p.hash {
		return ErrXrayDomainTCPOriginal
	}
	c := p.comparison
	if c.valid(p.read, ctx, p.old) != nil || !os.SameFile(p.info, c.image.info) || p.info.Size() != c.image.info.Size() || p.hash != c.image.hash {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}

func (p *domainTCPPriorByteRead) current(ctx context.Context) error {
	if p == nil || p.self != p || p.comparison == nil {
		return ErrXrayDomainTCPOriginal
	}
	c := p.comparison
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := p.bound(ctx); err != nil {
		return err
	}
	if err := p.executable.metadataCurrent(ctx); err != nil {
		return err
	}
	finish := domainTCPMeasure("successor-prior-executable-byte-read")
	var readBytes int64
	defer func() { finish(readBytes) }()
	var block [32 << 10]byte
	equal := true
	for offset := int64(0); offset < p.info.Size(); {
		if err := errors.Join(ctx.Err(), c.image.contextCurrent(c.image.ctx)); err != nil {
			return err
		}
		want := min(int64(len(block)), p.info.Size()-offset)
		n, err := p.file.ReadAt(block[:want], offset)
		readBytes += int64(n)
		if int64(n) != want || err != nil && err != io.EOF {
			return errors.Join(ErrXrayDomainTCPOriginal, err)
		}
		if !bytes.Equal(block[:want], c.image.lease.data[offset:offset+want]) {
			equal = false
		}
		offset += int64(n)
	}
	if !equal {
		return errors.Join(ErrXrayDomainTCPOriginal, ctx.Err(), c.image.contextCurrent(c.image.ctx))
	}
	return errors.Join(p.executable.metadataCurrent(ctx), p.bound(ctx), ctx.Err())
}
