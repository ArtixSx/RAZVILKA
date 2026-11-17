package dataplane

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type domainTCPToolObserver interface {
	WithReadOnlyToolObservation(context.Context, netidentity.Identity, string, func(context.Context) error) error
}

// Only one synchronous readonly COMMON callback borrows this original source.
// Every mutation/actual Start uses its caller's original context, after this
// scope has revoked and joined its held readers and closed its complete SHA.
func (r *domainTCPCaptureExecutionResource) observeTools(ctx context.Context, use func(context.Context) error) error {
	if use == nil {
		return ErrDomainPolicyTCPConsumer
	}
	if err := r.local(ctx); err != nil {
		return err
	}
	original, ok := r.backend.reader.Runner.(domainTCPToolObserver)
	if !ok {
		return use(ctx)
	} // Existing producers retain their full-check path.
	return original.WithReadOnlyToolObservation(ctx, r.tools.Identity, r.tools.ReviewSHA256, use)
}

// The original tool producer supplies this derived context synchronously. A
// file view is rebound only here, never from an arbitrary caller context.
func (r *domainTCPCaptureExecutionResource) observeToolsWithFiles(ctx context.Context, files *xrayDomainTCPFileObservation, use func(context.Context, *xrayDomainTCPFileObservation) error) error {
	if use == nil {
		return ErrDomainPolicyTCPConsumer
	}
	return r.observeTools(ctx, func(observed context.Context) error {
		if files == nil || observed == ctx {
			return use(observed, files)
		}
		child, closeChild, err := files.forOriginalToolRead(ctx, observed, r.process)
		if err != nil {
			return err
		}
		defer closeChild()
		result := use(observed, child)
		return errors.Join(result, child.current(observed, r.process), files.current(ctx, r.process))
	})
}

func (r *syntheticBaselineExecutionResource) observeTools(ctx context.Context, use func(context.Context) error) error {
	if use == nil {
		return ErrSyntheticBaselineTransition
	}
	if err := r.local(ctx); err != nil {
		return err
	}
	original, ok := r.backend.reader.Runner.(domainTCPToolObserver)
	if !ok {
		return use(ctx)
	}
	return original.WithReadOnlyToolObservation(ctx, r.tools.Identity, r.tools.ReviewSHA256, use)
}

func (r *syntheticBaselineExecutionResource) observeOriginalFiles(ctx context.Context, use func(*xrayDomainTCPFileObservation) error) error {
	if use == nil {
		return ErrSyntheticBaselineTransition
	}
	if r == nil || r.self != r {
		return ErrSyntheticBaselineTransition
	}
	if r.capture == nil || r.capture.xray == nil || r.capture.xray.resource == nil {
		return use(nil)
	}
	process := r.capture.xray.resource
	if process.material == nil || process.material.binding != r.binding {
		return ErrSyntheticBaselineTransition
	}
	return process.withCurrentFileObservation(ctx, use)
}

// Pure standalone standby reads and Guard use this byte bracket. currentWithFiles
// already performs BOTH original capture/process Currents, including their
// independent material/control/metadata/config/listener reads. Share only the
// immutable executable SHA across those same two calls. The view is revoked
// before returning to any inspector read, actual command Start or effect.
func (r *syntheticBaselineExecutionResource) currentInOriginalFileObservation(ctx context.Context) error {
	return r.compareInOriginalFileObservation(ctx, r.currentWithFiles)
}

// The standalone prepared-baseline comparison contains four complete source/
// process reads plus its actual inventory and receipt bookends. Share only
// immutable executable bytes; registration and COMMON effects follow return.
func (r *syntheticBaselineExecutionResource) currentBaselineInOriginalFileObservation(ctx context.Context) error {
	return r.compareInOriginalFileObservation(ctx, r.currentBaselineWithFiles)
}

// Only the two hardcoded readonly comparisons above call this helper. It is
// neither an observation cache nor a permission for a callback/effect.
func (r *syntheticBaselineExecutionResource) compareInOriginalFileObservation(ctx context.Context, compare func(context.Context, *xrayDomainTCPFileObservation) error) error {
	if err := r.local(ctx); err != nil {
		return err
	}
	if r.capture == nil || r.capture.xray == nil || r.capture.xray.resource == nil {
		return compare(ctx, nil) // Existing modeled/generic producers keep full path.
	}
	capture, xray := r.capture, r.capture.xray
	owner, original := capture.owner.(*DomainTCPOriginalScope)
	if !original {
		return compare(ctx, nil) // Custom producers retain every full-byte read.
	}
	if owner == nil || owner.self != owner {
		return ErrSyntheticBaselineTransition
	}
	process := xray.resource
	if capture.self != capture || process.self != process || process.material == nil || process.material.binding != r.binding || process.scope != r.binding.scope {
		return ErrSyntheticBaselineTransition
	}
	read := func(observed context.Context) error {
		return withDomainTCPPreAddFiles(observed, process, r, nil, false, func(files *xrayDomainTCPFileObservation) error {
			return compare(observed, files)
		})
	}
	// This standalone comparison has no typed guard-loan consumer. Do not
	// derive a new context from a present guard carrier or treat it as absent.
	if ctx.Value(domainTCPGuardReadKey{}) != nil {
		return ErrSyntheticBaselineTransition
	}
	// Existing private pre-Add loans require their EXACT context. Preserve that
	// original validator, including refusal of a foreign/expired present key.
	// Cleanup and custom tool producers retain the previous full-check path.
	_, toolObserver := r.backend.reader.Runner.(domainTCPToolObserver)
	if !toolObserver || ctx.Value(domainTCPPreAddKey{}) != nil || ctx.Value(domainTCPBaselineCleanupKey{}) != nil || ctx.Value(domainTCPCaptureCleanupKey{}) != nil || ctx.Value(domainTCPFailureCleanupKey{}) != nil {
		result := read(ctx)
		if r.capture != capture || capture.owner != owner || capture.xray != xray || xray.resource != process || process.material == nil || process.material.binding != r.binding || process.scope != r.binding.scope {
			return errors.Join(result, ErrSyntheticBaselineTransition)
		}
		return result
	}
	material, binding, scope := process.material, r.binding, process.scope
	listener := capture.listener
	tools, backend, inspector, control, mapping := r.tools, r.backend, r.inspector, r.control, r.mapping
	source, runner, toolRunner := owner.source, backend.reader.Runner, tools.Runner
	association := func(observed context.Context) error {
		if err := domainTCPBaselineCurrentReadContext(ctx, observed); err != nil {
			return err
		}
		if r.capture != capture || capture.owner != owner || capture.xray != xray || xray.resource != process || process.material != material || material.binding != binding || r.binding != binding || process.scope != scope || binding.scope != scope || r.tools != tools || r.backend != backend || r.inspector != inspector || r.control != control || r.mapping != mapping || !sameNetworkPolicyDependency(owner.source, source) || !sameNetworkPolicyDependency(backend.reader.Runner, runner) || !sameNetworkPolicyDependency(tools.Runner, toolRunner) {
			return ErrSyntheticBaselineTransition
		}
		return errors.Join(r.local(observed), capture.originalReadAssociation(observed, owner, xray, process, material, binding, listener))
	}
	if err := association(ctx); err != nil {
		return err
	}
	// This encloses ONLY one of the two hardcoded pure comparisons. Full tool
	// bytes bookend all its unchanged metadata/child/version/kernel callbacks;
	// the revoked scope cannot reach the caller's record, Run or Start.
	finish := domainTCPMeasure("baseline-standalone-tool-read")
	var enteredOriginal atomic.Bool
	result := domainTCPBaselineToolComparison(ctx, func(parent context.Context, use func(context.Context) error) error {
		return r.observeTools(parent, func(observed context.Context) error {
			// The actual outer tool producer derives this context before our
			// callback protocol derives its cancellation child. Nested existing
			// scopes and fallback do not count as a new standalone bracket.
			if !sameNetworkPolicyDependency(observed, parent) {
				enteredOriginal.Store(true)
			}
			return use(observed)
		})
	}, func(observed context.Context) error {
		if err := association(observed); err != nil {
			return err
		}
		return errors.Join(read(observed), association(observed))
	})
	result = errors.Join(result, association(ctx))
	if result == nil && enteredOriginal.Load() {
		finish(0) // Complete original body plus both file/tool closings only.
	}
	return result
}

// Keep the existing synchronous callback protocol: even an early-returning
// observer cannot leave a comparison running after this helper returns.
func domainTCPBaselineToolComparison(ctx context.Context, observe func(context.Context, func(context.Context) error) error, read func(context.Context) error) (result error) {
	if ctx == nil || ctx.Err() != nil || observe == nil || read == nil {
		return ErrSyntheticBaselineTransition
	}
	var mu sync.Mutex
	open, entered, complete, misuse := true, false, false, false
	var revoke context.CancelFunc
	var bodyErr error
	done := make(chan struct{})
	// Also seals/cancels/joins on an observer panic. No callback owns this mutex.
	defer func() {
		mu.Lock()
		open = false
		didEnter, cancel := entered, revoke
		mu.Unlock()
		if didEnter {
			select {
			case <-done:
			default:
				mu.Lock()
				misuse = true
				mu.Unlock()
				cancel()
				<-done
			}
		}
		mu.Lock()
		defer mu.Unlock()
		result = errors.Join(result, bodyErr, ctx.Err())
		if !didEnter || !complete || misuse {
			result = errors.Join(result, ErrSyntheticBaselineTransition)
		}
	}()
	return observe(ctx, func(ownerCtx context.Context) error {
		mu.Lock()
		if !open || entered || ownerCtx == nil {
			misuse = true
			mu.Unlock()
			return ErrSyntheticBaselineTransition
		}
		entered = true
		observed, cancel := context.WithCancel(ownerCtx)
		revoke = cancel
		mu.Unlock()
		defer close(done)
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		if ctx.Err() != nil {
			cancel()
		}
		err := domainTCPBaselineCurrentReadContext(ctx, observed)
		if err == nil {
			err = errors.Join(read(observed), domainTCPBaselineCurrentReadContext(ctx, observed))
		}
		mu.Lock()
		bodyErr, complete = err, true
		mu.Unlock()
		return err
	})
}
