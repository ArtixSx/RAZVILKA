package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
)

type nfqws2ActiveCommandOwner struct {
	execution *nfqws2ActiveExecution
	resource  *NFQWSExecutionResource
	index     int
	cleanup   bool
}

// WithNFQWSScopedCommandStart is the stateless admission used by the original
// held-fd tool producer at its actual Cmd.Start. It accepts only the original
// private NFQ participant and COMMON's current one-use command invocation.
// A name/argv/digest, receipt or detached context cannot issue either owner.
// Full source, process, queue, LAN and tool/NI checks precede tool execution;
// this leaf performs only local owner/receipt bookends and control admission.
// begin must be ONLY the actual synchronous Cmd.Start. Wait and all full
// closing readbacks belong to the existing producers after this returns.
func WithNFQWSScopedCommandStart(ctx context.Context, name string, args []string, toolReviewSHA string, begin func() error) error {
	if begin == nil {
		return ErrNFQWSScopedOwner
	}
	frozen := slices.Clone(args)
	owner, err := nfqws2ReviewActiveCommandOwner(ctx, name, frozen, toolReviewSHA)
	if err != nil {
		return err
	}
	r := owner.resource
	invocation, err := observePolicyEffectCommandInvocation(ctx, r.plan.mixed, r.root, name, frozen)
	if err != nil || invocation == nil || invocation.index != owner.index || invocation.cleanup != owner.cleanup {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	return invocation.withStart(ctx, func() error {
		opening, err := nfqws2ReviewActiveCommandOwner(ctx, name, frozen, toolReviewSHA)
		if err != nil || opening != owner {
			return errors.Join(ErrNFQWSScopedOwner, err)
		}
		control := owner.execution.material.control
		if owner.cleanup {
			cleanup, reviewErr := r.commandCleanupReview(ctx)
			if reviewErr != nil {
				return reviewErr
			}
			err = control.WithCleanupStart(ctx, cleanup, begin)
		} else {
			err = control.WithStart(ctx, begin)
		}
		closing, closeErr := nfqws2ReviewActiveCommandOwner(ctx, name, frozen, toolReviewSHA)
		if closeErr != nil || closing != owner {
			return errors.Join(err, ErrNFQWSScopedOwner, closeErr)
		}
		return err
	})
}

// Pure original-owner/command comparison at the actual tool Start boundary.
// The actual tool runner already holds its own descriptor/NI locks here. Do
// not call Source.Current, owner guards, CheckTools, a provider, inventory or
// process/readiness callbacks: the original full prechecks precede that runner.
func nfqws2ReviewActiveCommandOwner(ctx context.Context, name string, args []string, digest string) (nfqws2ActiveCommandOwner, error) {
	var out nfqws2ActiveCommandOwner
	if nfqws2ActiveOperation(ctx) != nil || !lanPolicyHash(digest) {
		return out, ErrNFQWSScopedOwner
	}
	e, ok := ctx.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution)
	if !ok || e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.manager == nil || e.material.adapter == nil ||
		e.material.control == nil || e.inventory.review != digest || e.binding == nil || e.inventory.reader.IPTables == "" || e.inventory.reader.IP6Tables == "" ||
		e.inventory.reader.IPTables == e.inventory.reader.IP6Tables || e.binding.Tools.IPTables != e.inventory.reader.IPTables || e.binding.Tools.IP6Tables != e.inventory.reader.IP6Tables ||
		e.material.manager.StateRoot != e.material.managerRoot || e.material.adapter.StateRoot != e.material.command.StateRoot || nfqws2ActiveCommandMatchesSpec(e.material.command, e.spec) != nil {
		return out, ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	r, prepared := e.resource, e.prepared
	live := e.started && e.launchInvoked && !e.retired
	e.mu.Unlock()
	if !live || r == nil || r.scope == nil || r.plan == nil || prepared == nil || prepared.owner == nil ||
		!reflect.DeepEqual(r.plan.spec, e.spec) || !nfqws2ActiveSamePlan(e.plan, r.scope.plan) || r.scope.manager != e.material.manager || r.scope.adapterOwner != e.material.adapter ||
		r.root != filepath.Join(r.scope.root, r.relative) || r.scope.root != filepath.Join(e.material.managerRoot, "transactions", e.plan.PlanID) {
		return out, ErrNFQWSScopedOwner
	}
	effects, err := r.plan.Effects()
	if err != nil {
		return out, err
	}
	index, cleanup := -1, false
	for i, effect := range effects.Effects {
		if effect.Tool != PolicyEffectIPTables && effect.Tool != PolicyEffectIP6Tables || name != e.binding.Tools.command(effect.Tool) {
			continue
		}
		add, remove := slices.Equal(args, effect.Add), slices.Equal(args, effect.Delete)
		if add && remove || (add || remove) && index != -1 {
			return out, ErrNFQWSScopedOwner
		}
		if add || remove {
			index, cleanup = i, remove
		}
	}
	if index < 0 {
		return out, ErrNFQWSScopedOwner
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	i, err := r.matching(r.binding)
	if err != nil || r.activeCommand == nil || !reflect.DeepEqual(*r.activeCommand, e.material.command) || r.preparedOwner != prepared ||
		r.transferGuards == nil || r.transferGuards.control != e.material.control || !r.startACK || !r.preparedUsed ||
		(!cleanup && r.scope.execution.Resources[i].Phase != "capture-ready") {
		return out, errors.Join(ErrNFQWSScopedOwner, err)
	}
	if err := r.scope.checkOriginalOwner(ctx, &executionTransitResource{relative: r.relative, anchor: r.anchor}, !cleanup, cleanup); err != nil {
		return out, err
	}
	nfqws2ActiveAdapterMu.Lock()
	defer nfqws2ActiveAdapterMu.Unlock()
	o := prepared.owner
	if e.material.adapter.activeExecution != e || e.material.adapter.activeProcess != o || o.adapter != e.material.adapter {
		return out, ErrNFQWSScopedOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.prepared != prepared || o.admission.Binding != r.binding || !reflect.DeepEqual(o.command, e.material.command) {
		return out, ErrNFQWSScopedOwner
	}
	if cleanup {
		// The full original inactive/ECHILD/receipt/queue proof was checked
		// before tools were entered. Its sole actual Wait must remain joined.
		if !nfqws2ActiveDone(o.done) || o.result == nil || (o.finalACK && (r.finalOwner == nil || r.finalOwner != o.active || r.finalOwner.owner != o)) {
			return out, ErrNFQWSScopedOwner
		}
	} else if o.detached || o.finalACK || o.stopRequested || nfqws2ActiveDone(o.done) || (o.state != "starting" && o.state != "prepared") {
		return out, ErrNFQWSScopedOwner
	}
	return nfqws2ActiveCommandOwner{execution: e, resource: r, index: index, cleanup: cleanup}, nil
}
