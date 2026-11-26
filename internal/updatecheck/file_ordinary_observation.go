package updatecheck

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// OrdinaryInstallerControllerObservation is a read-only, single-callback
// observation of the original ordinary installer group. No facts or roles are
// exported, and a copied, escaped, expired or concurrent reader cannot grant a
// peer role. Construction is restricted to the platform's original reader.
type OrdinaryInstallerControllerObservation struct {
	self      *OrdinaryInstallerControllerObservation
	original  context.Context
	deadline  time.Time
	source    ordinaryObservationSource
	members   []bootstrapControllerFact
	active    atomic.Bool
	finishing atomic.Bool
	failure   atomic.Pointer[ordinaryObservationFailure]
	mu        sync.Mutex
	cleared   sync.Once
}

type ordinaryObservationKey struct{}
type ordinaryObservationFailure struct{ cause error }

// The fixed platform reader alone supplies these private leaves. Tests model
// them to exercise the aggregate contract without claiming a native role.
type ordinaryObservationSource struct {
	review        fileReview
	record        updateRecord
	identity      fileHelperIdentity
	command       fileCommandReceipt
	caller        int
	joined        bool
	installerJoin *ordinaryInstallerJoin
	read          func(int) (bootstrapControllerFact, error)
	check         func(context.Context, bool) error
	clear         func()
}

// WithOrdinaryInstallerControllerObservation authenticates the complete
// original group before use and freshly closes it after use, including an
// unsuccessful callback. Closing errors are returned, never deferred away.
// This grants no effect, inactivity, health, retirement or cross-call cache.
func (a *SelfUpdateFileAdapter) WithOrdinaryInstallerControllerObservation(ctx context.Context, id string, use func(context.Context, *OrdinaryInstallerControllerObservation) error) error {
	if a == nil || ctx == nil || use == nil || !jobIDPattern.MatchString(id) {
		return ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || !deadline.After(time.Now()) || ctx.Err() != nil {
		return errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err())
	}
	return a.withOrdinaryInstallerControllerObservation(ctx, id, use)
}

func runOrdinaryControllerObservation(ctx context.Context, source ordinaryObservationSource, use func(context.Context, *OrdinaryInstallerControllerObservation) error) (result error) {
	deadline, _ := ctx.Deadline()
	o := &OrdinaryInstallerControllerObservation{original: ctx, deadline: deadline, source: source}
	o.self = o
	o.active.Store(true)
	// This also runs while a panic unwinds; the panic itself is not recovered.
	defer func() { result = errors.Join(result, o.finish()) }()
	if err := o.open(); err != nil {
		return o.poison(err)
	}
	held := context.WithValue(ctx, ordinaryObservationKey{}, o)
	return use(held, o)
}

func (o *OrdinaryInstallerControllerObservation) contextCurrent(ctx context.Context) error {
	if o == nil || o.self != o || o.original == nil || ctx == nil {
		return ErrOrdinaryInstallerControllerRole
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline.After(o.deadline) || !o.deadline.After(time.Now()) || ctx.Err() != nil || o.original.Err() != nil {
		return errors.Join(ErrOrdinaryInstallerControllerRole, ctx.Err(), o.original.Err())
	}
	return nil
}

func (o *OrdinaryInstallerControllerObservation) poison(err error) error {
	if o != nil && o.self == o {
		o.failure.CompareAndSwap(nil, &ordinaryObservationFailure{err})
		o.active.Store(false)
	}
	return errors.Join(ErrOrdinaryInstallerControllerRole, err)
}

func (o *OrdinaryInstallerControllerObservation) open() error {
	if err := o.contextCurrent(o.original); err != nil {
		return ordinaryInstallerRoleAt("source", err)
	}
	if o.source.read == nil || o.source.check == nil || o.source.clear == nil {
		return ordinaryInstallerRoleAt("source", ErrFileProtocol)
	}
	if err := o.source.check(o.original, false); err != nil {
		return err
	}
	if owner := o.source.installerJoin; owner != nil {
		command, err := owner.joined(o.original, owner.adapter, o.source.review.ID, o.source.caller)
		if err != nil || command != o.source.command {
			return ordinaryInstallerRoleAt("join-opening", err)
		}
		fact, err := o.source.read(o.source.identity.Process.PID)
		if err != nil || fact.Process.PID != o.source.caller || ordinaryJoinedInstallerRole(o.source.review, o.source.record, o.source.identity, command, fact) != "ordinary-installer" {
			return ordinaryInstallerRoleAt("helper-opening", err)
		}
		o.members = append(o.members, fact)
		return o.contextCurrent(o.original)
	}
	pids := []int{o.source.identity.Process.PID, o.source.command.Supervisor.PID}
	stages := []string{"helper-opening", "supervisor-opening", "child-opening"}
	roles := []string{"ordinary-installer", "quiesce-supervisor", "quiesce-child"}
	if !o.source.joined {
		pids = append(pids, o.source.command.DirectPID)
	}
	for i, pid := range pids {
		fact, err := o.source.read(pid)
		if err != nil || ordinaryControllerRole(o.source.review, o.source.record, o.source.identity, o.source.command, fact) != roles[i] {
			return ordinaryInstallerRoleAt(stages[i], err)
		}
		o.members = append(o.members, fact)
	}
	for _, fact := range o.members {
		if fact.Process.PID == o.source.caller && ordinaryControllerReadRole(ordinaryControllerRole(o.source.review, o.source.record, o.source.identity, o.source.command, fact), o.source.caller, o.source.caller, o.source.joined, true) {
			return o.contextCurrent(o.original)
		}
	}
	return ordinaryInstallerRoleAt("caller-opening", nil)
}

// VerifyPeer freshly reads this occurrence's complete executable bytes and
// argv/parent/birth bookends. The original group is not reread for each peer.
// All metadata is nevertheless freshly checked before and after the read.
func (o *OrdinaryInstallerControllerObservation) VerifyPeer(ctx context.Context, pid int) (result error) {
	if o == nil || o.self != o {
		if o != nil && o.self != nil && o.self.self == o.self {
			o.self.poison(ErrOrdinaryInstallerControllerRole)
		}
		return ErrOrdinaryInstallerControllerRole
	}
	if err := o.contextCurrent(ctx); err != nil {
		return o.poison(err)
	}
	if !o.active.Load() || ctx.Value(ordinaryObservationKey{}) != o || pid <= 1 {
		return o.poison(ErrOrdinaryInstallerControllerRole)
	}
	if !o.mu.TryLock() {
		return o.poison(ErrOrdinaryInstallerControllerRole)
	}
	defer func() {
		if result != nil {
			result = o.poison(result)
		}
		if o.finishing.Load() {
			o.cleanup()
			result = errors.Join(result, o.contextCurrent(ctx))
		}
		o.mu.Unlock()
	}()
	if !o.active.Load() {
		return ErrOrdinaryInstallerControllerRole
	}
	if o.source.installerJoin != nil {
		return ordinaryInstallerRoleAt("peer-opening", nil)
	}
	var original *bootstrapControllerFact
	for i := range o.members {
		if o.members[i].Process.PID == pid {
			original = &o.members[i]
			break
		}
	}
	if original == nil || !ordinaryControllerReadRole(ordinaryControllerRole(o.source.review, o.source.record, o.source.identity, o.source.command, *original), pid, o.source.caller, o.source.joined, false) {
		return ordinaryInstallerRoleAt("peer-opening", nil)
	}
	if err := o.source.check(ctx, false); err != nil {
		return err
	}
	fresh, err := o.source.read(pid)
	if err != nil || !reflect.DeepEqual(fresh, *original) {
		return ordinaryInstallerRoleAt("peer-opening", err)
	}
	if err := o.source.check(ctx, false); err != nil {
		return err
	}
	if !o.active.Load() {
		return ErrOrdinaryInstallerControllerRole
	}
	return o.contextCurrent(ctx)
}

func (o *OrdinaryInstallerControllerObservation) cleanup() {
	o.cleared.Do(func() {
		if o.source.clear != nil {
			o.source.clear()
		}
		o.members = nil
		o.source = ordinaryObservationSource{}
	})
}

func (o *OrdinaryInstallerControllerObservation) finish() (result error) {
	o.finishing.Store(true)
	o.active.Store(false)
	// Concurrent/escaped use is a refusal. Its reader owns final cleanup while
	// holding the shared image lock; the callback cannot report success.
	if !o.mu.TryLock() {
		return errors.Join(ordinaryInstallerRoleAt("facts-closing", nil), o.poison(ErrOrdinaryInstallerControllerRole), o.original.Err())
	}
	defer o.mu.Unlock()
	defer func() {
		o.cleanup()
		// Clearing a large image is part of the same finite observation.
		result = errors.Join(result, o.contextCurrent(o.original))
		if failed := o.failure.Load(); failed != nil {
			result = errors.Join(result, failed.cause)
		}
	}()
	if o.source.check == nil || o.source.read == nil {
		return ordinaryInstallerRoleAt("source", nil)
	}
	result = o.source.check(o.original, true)
	for _, before := range o.members {
		after, err := o.source.read(before.Process.PID)
		if err != nil || !reflect.DeepEqual(before, after) {
			result = errors.Join(result, ordinaryInstallerRoleAt("facts-closing", err))
		}
	}
	result = errors.Join(result, o.source.check(o.original, false))
	if err := o.contextCurrent(o.original); err != nil {
		result = errors.Join(result, ordinaryInstallerRoleAt("context-closing", err))
	}
	return result
}
