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
// observes all held executable bytes before AND after its actual kernel reads.
type xrayDomainTCPFileObservation struct {
	self           *xrayDomainTCPFileObservation
	parent         *xrayDomainTCPFileObservation
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
	if image := r.borrowFileObservationImage(ctx); image != nil {
		// Neither use nor its derived file views can access this private image.
		// The inner observation revokes its views before this defer clears bytes,
		// including when use panics. Contention never waits or allocates again.
		defer func() {
			image.release()
			result = errors.Join(result, image.contextCurrent(ctx))
		}()
		if err := r.filesCurrentForImageRead(ctx, nil, image); err != nil {
			return err
		}
		return r.withFileObservationAfterOpeningImage(ctx, nil, use, image)
	}
	if err := r.filesCurrent(ctx); err != nil {
		return err
	}
	return r.withFileObservationAfterOpening(ctx, nil, use)
}

func (r *XrayDomainTCPExecutionResource) withFileObservationAfterOpening(ctx context.Context, opening *xrayDomainTCPFileOpening, use func(*xrayDomainTCPFileObservation) error) (result error) {
	return r.withFileObservationAfterOpeningImage(ctx, opening, use, nil)
}

func (r *XrayDomainTCPExecutionResource) withFileObservationAfterOpeningImage(ctx context.Context, opening *xrayDomainTCPFileOpening, use func(*xrayDomainTCPFileObservation) error, image *xrayDomainTCPImageRead) (result error) {
	if use == nil {
		return ErrXrayDomainTCPOriginal
	}
	if image != nil && (opening != nil || !image.belongsTo(r) || !image.captured() || image.contextCurrent(ctx) != nil) {
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
	return errors.Join(result, r.filesCurrentForImageRead(ctx, nil, image), ctx.Err())
}

func (v *xrayDomainTCPFileObservation) current(ctx context.Context, r *XrayDomainTCPExecutionResource) error {
	if v == nil || !v.open.Load() || !v.sameOriginal(ctx, r) {
		return ErrXrayDomainTCPOriginal
	}
	depth := 0
	for parent := v.parent; parent != nil; parent = parent.parent {
		depth++
		if depth > 4 || !parent.open.Load() || !parent.sameOriginal(parent.ctx, r) {
			return ErrXrayDomainTCPOriginal
		}
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

// One read-only Guard, never a COMMON mutation/Start. Complete original source,
// child/kernel identity and complete executable bytes bracket its nested readers.
func (r *XrayDomainTCPExecutionResource) withCurrentFileObservation(ctx context.Context, use func(*xrayDomainTCPFileObservation) error) (result error) {
	if use == nil {
		return ErrXrayDomainTCPOriginal
	}
	// Full bytes bracket the entire pure operation. Both original material,
	// control and actual child/listener comparisons remain inside that same
	// file view, retaining their independent metadata/config readbacks without
	// repeating its full SHA. Native/effect admission never accepts this view.
	return r.withFileObservation(ctx, func(v *xrayDomainTCPFileObservation) error {
		if err := r.currentWithFiles(ctx, v); err != nil {
			return err
		}
		result := use(v)
		return errors.Join(result, r.currentWithFiles(ctx, v), ctx.Err())
	})
}

func (v *xrayDomainTCPFileObservation) forOriginalProcessRead(parent, child context.Context, r *XrayDomainTCPExecutionResource) (*xrayDomainTCPFileObservation, func(), error) {
	if v.current(parent, r) != nil || !xrayDomainTCPOriginalProcessRead(child, r.child) {
		return nil, nil, ErrXrayDomainTCPOriginal
	}
	// The explicit caller creates child from this same original context. The
	// only provider derivation retains that exact original process-read carrier.
	parentRead, _ := parent.Value(xrayDomainTCPProcessReadKey{}).(*xrayDomainTCPProcessRead)
	childRead, _ := child.Value(xrayDomainTCPProcessReadKey{}).(*xrayDomainTCPProcessRead)
	if parentRead != nil && parentRead != childRead {
		return nil, nil, ErrXrayDomainTCPOriginal
	}
	nested := &xrayDomainTCPFileObservation{parent: v, resource: v.resource, executable: v.executable, file: v.file, executableInfo: v.executableInfo, path: v.path, sha256: v.sha256, config: v.config, info: v.info, ctx: child}
	nested.self = nested
	nested.open.Store(true)
	return nested, func() { nested.open.Store(false) }, nil
}

// Called only by observeToolsWithFiles inside the same original tool source's
// synchronous callback. The outer complete-byte opening/closing remains live;
// this child preserves every nested file/config/metadata observation.
func (v *xrayDomainTCPFileObservation) forOriginalToolRead(parent, child context.Context, r *XrayDomainTCPExecutionResource) (*xrayDomainTCPFileObservation, func(), error) {
	if v.current(parent, r) != nil || child == nil || child.Err() != nil || parent.Err() != nil {
		return nil, nil, ErrXrayDomainTCPOriginal
	}
	parentDeadline, parentFinite := parent.Deadline()
	childDeadline, childFinite := child.Deadline()
	if !parentFinite || !childFinite || childDeadline.After(parentDeadline) || child.Value(xrayDomainTCPProcessReadKey{}) != parent.Value(xrayDomainTCPProcessReadKey{}) {
		return nil, nil, ErrXrayDomainTCPOriginal
	}
	nested := &xrayDomainTCPFileObservation{parent: v, resource: v.resource, executable: v.executable, file: v.file, executableInfo: v.executableInfo, path: v.path, sha256: v.sha256, config: v.config, info: v.info, ctx: child}
	nested.self = nested
	nested.open.Store(true)
	return nested, func() { nested.open.Store(false) }, nil
}

func (r *XrayDomainTCPExecutionResource) withNestedFileObservation(ctx context.Context, files *xrayDomainTCPFileObservation, use func(*xrayDomainTCPFileObservation) error) error {
	if use == nil || files.current(ctx, r) != nil {
		return ErrXrayDomainTCPOriginal
	}
	if err := r.filesCurrentForObservation(ctx, files); err != nil {
		return err
	}
	result := use(files)
	return errors.Join(result, r.filesCurrentForObservation(ctx, files), ctx.Err())
}
