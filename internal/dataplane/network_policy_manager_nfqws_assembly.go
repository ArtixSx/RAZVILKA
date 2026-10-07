package dataplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

// Private assembly inputs come from the reviewed owner. Process and queue
// proofs are deliberately not supplied by the caller: they use the actual
// managed lease and kernel observer with the issuer's eight-field binding.
// This is not a production constructor, adapter registration or saved grant.
type nfqwsExecutionRuntime struct {
	Runner             NFQWS2Runner
	Tools              PolicyEffectTools
	VerifyLAN          func(context.Context, *LANPolicyRuntimePlan) error
	AdditionalReadback func(context.Context, *NFQWSScopedPlan) error
}

type nfqwsExecutionAssembly struct {
	ctx      context.Context
	adapter  *NFQWS2Adapter
	command  nfqws2ManagedProcessCommand
	prefix   []string
	resource *NFQWSExecutionResource
	binding  *NFQWSScopedBinding
}

func nfqwsExecutionCommandMatches(command nfqws2ManagedProcessCommand, spec NFQWSScopedSpec) error {
	if nfqws2ValidateManagedCommand(command) != nil || spec.Queue == 0 || spec.SessionID != command.ID ||
		spec.BootID != command.Parent.BootID || spec.CommandSHA256 != nfqws2ManagedCommandDigest(command) ||
		spec.Candidate.ArgumentsSHA256 != components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args) {
		return ErrNFQWSScopedOwner
	}
	queue, intercept := 0, 0
	for _, arg := range command.Args {
		// The pinned producer uses getopt_long_only: both single-dash long
		// options and unique abbreviations can replace reserved globals.
		// Its first positional @/$ file also replaces the entire argv. Close
		// this launch grammar to exact full option names and attached values;
		// no positional, alias, split value or unknown global reaches Start.
		key, value, attached := strings.Cut(arg, "=")
		switch key {
		case "--qnum":
			if arg != "--qnum="+strconv.Itoa(int(spec.Queue)) {
				return ErrNFQWSScopedOwner
			}
			queue++
		case "--intercept":
			if arg != "--intercept=1" {
				return ErrNFQWSScopedOwner
			}
			intercept++
		case "--new":
			if arg != "--new" {
				return ErrNFQWSScopedOwner
			}
		case "--lua-init", "--blob", "--filter-tcp", "--filter-udp", "--filter-l7", "--payload", "--lua-desync":
			// Preserve the reviewed base and all current managed candidate
			// option names (strategylab.ExportableArguments). Their semantic
			// values/provenance remain the original owner's review, not a
			// new candidate or asset grant from this lexical boundary.
			if !attached || value == "" {
				return ErrNFQWSScopedOwner
			}
		default:
			return ErrNFQWSScopedOwner
		}
	}
	if queue != 1 || intercept != 1 {
		return ErrNFQWSScopedOwner
	}
	return nil
}

func newNFQWSExecutionAssembly(ctx context.Context, adapter *NFQWS2Adapter, command nfqws2ManagedProcessCommand, spec NFQWSScopedSpec, prefix []string, runtime nfqwsExecutionRuntime) (*nfqwsExecutionAssembly, error) {
	command.Args, command.Assets = slices.Clone(command.Args), slices.Clone(command.Assets)
	spec.Candidate.Traffic = slices.Clone(spec.Candidate.Traffic)
	if ctx == nil || adapter == nil || runtime.Runner == nil || runtime.Tools.IPTables == "" || runtime.Tools.IP6Tables == "" || runtime.VerifyLAN == nil || runtime.AdditionalReadback == nil {
		return nil, ErrNFQWSScopedOwner
	}
	if err := nfqwsExecutionCommandMatches(command, spec); err != nil {
		return nil, err // Refuse wrong queue/argv before reservation or Start.
	}
	owner, err := adapter.owner()
	if err != nil || adapter.StateRoot != command.StateRoot || owner != command.Owner {
		return nil, errors.Join(ErrNFQWSScopedOwner, err)
	}
	bounded, cancel, err := nfqws2ManagedStartContext(ctx, command.Deadline)
	if err != nil {
		return nil, err
	}
	defer cancel()
	e := &nfqwsExecutionAssembly{ctx: ctx, adapter: adapter, command: command, prefix: slices.Clone(prefix)}
	readback := nfqwsExecutionReadback(func(c context.Context, p *NFQWSScopedPlan, root string, mode nfqwsExecutionReadbackMode) error {
		if e.resource == nil || p != e.resource.Plan() || root != e.resource.Root() {
			return ErrNFQWSScopedOwner
		}
		switch mode {
		case nfqwsExecutionBeforeStart:
			return nfqwsScopedBeforeStartCurrent(c, e.binding, p, e.current)
		case nfqwsExecutionPrepared:
			return nfqwsScopedPreparedCurrent(c, e.binding, p, root, e.current)
		case nfqwsExecutionRemoved:
			return e.binding.VerifyInactive(c, p, root)
		default:
			return ErrNFQWSScopedOwner
		}
	})
	e.resource, err = AcquireNFQWSExecutionResource(context.WithValue(bounded, nfqwsExecutionReadbackKey{}, readback), spec)
	if err != nil {
		return nil, err
	}
	r := e.resource
	e.binding = &NFQWSScopedBinding{Runner: runtime.Runner, Tools: runtime.Tools, ApplyGuard: r.ApplyGuard, CleanupGuard: r.CleanupGuard,
		VerifyLAN: runtime.VerifyLAN, AdditionalReadback: runtime.AdditionalReadback, QueueCheck: CheckNFQWSScopedQueue,
		queueReadiness: nfqwsScopedQueueReadiness,
		ProcessRunning: func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
			return nfqwsScopedReadExecutionProcess(c, adapter, p, r.Binding(), false)
		},
		ProcessInactive: func(c context.Context, p *NFQWSScopedPlan) (NFQWSScopedProcessProof, error) {
			return nfqwsScopedReadExecutionProcess(c, adapter, p, r.Binding(), true)
		}}
	return e, nil
}

func (e *nfqwsExecutionAssembly) current(ctx context.Context, p *NFQWSScopedPlan) error {
	if e == nil || e.resource == nil || p != e.resource.Plan() {
		return ErrNFQWSScopedOwner
	}
	return e.resource.Current(ctx, e.resource.Binding())
}

// Start ACK precedes userspace queue registration. The separate after-Start
// owner readback permits a positively observed empty-to-exact-owned transition
// across LAN/all-capture preflight. Any failed/unknown observation fences the
// attempt. This does not retry Start or the one-shot resource.Prepared.
func nfqwsExecutionAwaitQueue(ctx context.Context, b *NFQWSScopedBinding, p *NFQWSScopedPlan, current func(context.Context, *NFQWSScopedPlan) error) error {
	if ctx == nil || b == nil || p == nil || current == nil || b.ProcessRunning == nil || b.queueReadiness == nil {
		return ErrNFQWSScopedOwner
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrNFQWSScopedOwner
	}
	for {
		ready, err := nfqwsScopedAfterStartCurrent(ctx, b, p, current)
		if err != nil {
			return fmt.Errorf("after-start owner readiness: %w", err)
		}
		if err := current(ctx, p); err != nil {
			return fmt.Errorf("closing current after readiness: %w", err)
		}
		if ready {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("empty queue wait: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// run uses the producer's synchronous lifetime. Capture and the bounded
// action run inside Prepared, after actual ACK/queue/LAN proof and durable
// capture-ready. Returning from the action stops that same helper, whose sole
// Wait and ACK must finish before any receipt-owned removal or settlement.
func (e *nfqwsExecutionAssembly) run(action func(context.Context, *NFQWSExecutionResource, *NFQWSScopedBinding) error) error {
	if e == nil || e.resource == nil || e.binding == nil || action == nil {
		return ErrNFQWSScopedOwner
	}
	processCtx, stop := context.WithCancel(e.ctx)
	defer stop()
	applyAttempted, completed := false, false
	r := e.resource
	admission := nfqws2ManagedProcessAdmission{Binding: r.Binding(), BeforeStart: r.BeforeStart, WithStart: r.WithStart, Current: r.Current,
		Prepared: func(ctx context.Context, binding NFQWSExecutionBinding) error {
			defer stop()
			if binding != r.Binding() {
				return ErrNFQWSScopedOwner
			}
			if err := nfqwsExecutionAwaitQueue(ctx, e.binding, r.Plan(), e.current); err != nil {
				return fmt.Errorf("NFQWS queue readiness: %w", err)
			}
			if err := r.Prepared(ctx, binding); err != nil {
				return fmt.Errorf("NFQWS prepared readback: %w", err)
			}
			applyAttempted = true
			if err := e.binding.Apply(ctx, r.Plan(), r.Root()); err != nil {
				return fmt.Errorf("NFQWS capture apply: %w", err)
			}
			if err := action(ctx, r, e.binding); err != nil {
				return fmt.Errorf("NFQWS action: %w", err)
			}
			if err := e.current(ctx, r.Plan()); err != nil {
				return fmt.Errorf("NFQWS closing current: %w", err)
			}
			completed = true
			return nil
		}}
	lease, runErr := e.adapter.runManagedNFQWSProcessWithAdmission(processCtx, e.command, e.prefix, admission)
	if !applyAttempted {
		return errors.Join(runErr, ErrNFQWSScopedOwner) // No original unused proof: retain fence.
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 5*time.Second)
	defer cancel()
	// Inspect is read-only and requires the existing common receipt/lock. A
	// missing receipt never acquires a new deletion or synthetic unused grant.
	status, cleanupErr := e.binding.Inspect(cleanupCtx, r.Plan(), r.Root())
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("NFQWS receipt inspect: %w", cleanupErr)
	}
	if cleanupErr == nil && (status.Unknown || status.Promoted) {
		cleanupErr = fmt.Errorf("NFQWS receipt state (complete=%t removed=%t unknown=%t promoted=%t added=%d pending=%d cleaned=%d): %w",
			status.Complete, status.Removed, status.Unknown, status.Promoted, status.Added, status.Pending, status.Cleaned, ErrNFQWSScopedOwner)
	}
	if cleanupErr == nil {
		if err := e.binding.Remove(cleanupCtx, r.Plan(), r.Root()); err != nil {
			cleanupErr = fmt.Errorf("NFQWS capture remove: %w", err)
		}
	}
	if cleanupErr == nil {
		if err := r.SettleRemoved(cleanupCtx); err != nil {
			cleanupErr = fmt.Errorf("NFQWS removed settlement: %w", err)
		}
	}
	if cleanupErr == nil && completed && e.ctx.Err() == nil && nfqwsScopedLeaseExecutionMatches(lease, r.Plan(), r.Binding()) &&
		lease.Acknowledged && lease.Receipt.WaitECHILD && nfqws2ValidateManagedLease(lease) == nil && nfqwsExecutionOnlyCanceled(runErr, 0) {
		runErr = nil // Only the deliberate internal stop, independently settled above.
	}
	return errors.Join(runErr, cleanupErr, e.ctx.Err())
}

// errors.Is alone could hide an unknown launch/action/ACK error joined with
// cancellation. Every leaf must be exactly the internal cancellation sentinel.
func nfqwsExecutionOnlyCanceled(err error, depth int) bool {
	if err == nil || depth > 64 {
		return false
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !nfqwsExecutionOnlyCanceled(child, depth+1) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return nfqwsExecutionOnlyCanceled(one.Unwrap(), depth+1)
	}
	return err == context.Canceled
}
