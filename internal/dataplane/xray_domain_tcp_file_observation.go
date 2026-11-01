package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync/atomic"
)

// One synchronous read of THIS original child. This is not a Start, cleanup,
// publication or reusable Current grant. Every independent observer still
// hashes the whole held executable before AND after its actual kernel reads.
type xrayDomainTCPFileObservation struct {
	self           *xrayDomainTCPFileObservation
	resource       *XrayDomainTCPExecutionResource
	executable     *xrayDomainTCPExecutable
	file           *os.File
	executableInfo os.FileInfo
	path, sha256   string
	config         *os.File
	info           os.FileInfo
	ctx            context.Context
	open           atomic.Bool
}

func (r *XrayDomainTCPExecutionResource) withFileObservation(ctx context.Context, use func(*xrayDomainTCPFileObservation) error) (result error) {
	if use == nil {
		return ErrXrayDomainTCPOriginal
	}
	if err := r.filesCurrent(ctx); err != nil {
		return err
	}
	return r.withFileObservationAfterOpening(ctx, nil, use)
}

func (r *XrayDomainTCPExecutionResource) withFileObservationAfterOpening(ctx context.Context, opening *xrayDomainTCPFileOpening, use func(*xrayDomainTCPFileObservation) error) (result error) {
	if use == nil {
		return ErrXrayDomainTCPOriginal
	}
	if opening != nil && opening.consume(ctx, r) != nil {
		return ErrXrayDomainTCPOriginal
	}
	v := &xrayDomainTCPFileObservation{resource: r, executable: r.executable, file: r.executable.file, executableInfo: r.executable.info, path: r.executable.path, sha256: r.executable.sha256, config: r.config, info: r.configInfo, ctx: ctx}
	v.self = v
	v.open.Store(true)
	defer v.open.Store(false) // Also revoked on panic; no positive result escapes.
	if err := r.filesCurrentForObservation(ctx, v); err != nil {
		return err
	}
	result = use(v)
	v.open.Store(false)
	if ctx.Err() != nil {
		return errors.Join(result, ctx.Err())
	}
	if !v.sameOriginal(ctx, r) {
		return errors.Join(result, ErrXrayDomainTCPOriginal)
	}
	return errors.Join(result, r.filesCurrent(ctx), ctx.Err())
}

func (v *xrayDomainTCPFileObservation) current(ctx context.Context, r *XrayDomainTCPExecutionResource) error {
	if v == nil || !v.open.Load() || !v.sameOriginal(ctx, r) {
		return ErrXrayDomainTCPOriginal
	}
	return v.executable.metadataCurrent(ctx)
}

func (v *xrayDomainTCPFileObservation) sameOriginal(ctx context.Context, r *XrayDomainTCPExecutionResource) bool {
	return v != nil && v.self == v && ctx != nil && reflect.TypeOf(ctx).Comparable() && ctx == v.ctx && r != nil && r.self == r && v.resource == r && v.executable == r.executable && r.executable != nil && v.file == r.executable.file && v.executableInfo == r.executable.info && v.path == r.executable.path && v.sha256 == r.executable.sha256 && v.config == r.config && v.info == r.configInfo
}

// A single explicit handoff of originalContext's completed full-byte opening.
// Only listenerCurrent creates this immediately after that check; no effect or
// independent observer accepts it. The process-read lifetime owns revocation.
type xrayDomainTCPFileOpening struct {
	self  *xrayDomainTCPFileOpening
	files *xrayDomainTCPFileObservation
	read  *xrayDomainTCPProcessRead
	used  atomic.Bool
}

func (r *XrayDomainTCPExecutionResource) fileOpeningAfterOriginalRead(ctx context.Context) *xrayDomainTCPFileOpening {
	read, _ := ctx.Value(xrayDomainTCPProcessReadKey{}).(*xrayDomainTCPProcessRead)
	v := &xrayDomainTCPFileObservation{resource: r, executable: r.executable, file: r.executable.file, executableInfo: r.executable.info, path: r.executable.path, sha256: r.executable.sha256, config: r.config, info: r.configInfo, ctx: ctx}
	v.self = v
	o := &xrayDomainTCPFileOpening{files: v, read: read}
	o.self = o
	return o
}

func (o *xrayDomainTCPFileOpening) consume(ctx context.Context, r *XrayDomainTCPExecutionResource) error {
	if o == nil || o.self != o || o.files == nil || o.read == nil || o.read.self != o.read || !o.read.open.Load() || o.read.resource != r || o.read.process == nil || r == nil || r.child != o.read.process || ctx == nil || ctx.Err() != nil || ctx.Value(xrayDomainTCPProcessReadKey{}) != o.read || !o.files.sameOriginal(o.files.ctx, r) || !o.used.CompareAndSwap(false, true) {
		return ErrXrayDomainTCPOriginal
	}
	return nil
}
