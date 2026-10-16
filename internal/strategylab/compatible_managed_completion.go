package strategylab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const managedCompatibilityCleanupTimeout = 5 * time.Second

// These fields are written only by the actual producer, Cmd.Start, its sole
// joined Wait and exact terminal/ACK CAS. They are never accepted from a caller.
type managedCompatibilityPhase struct {
	session                                    compatibilitySession
	before                                     State
	beforeImage, intentImage                   restorejournal.Image
	launched, joined, rolledBack, acknowledged bool
	helper                                     components.NFQWSSupervisionIdentity
	terminal                                   State
	terminalImage, ackImage                    restorejournal.Image
}

func managedInvocation(ctx context.Context, p *SupervisedCompatibilityProvider) *managedCompatibilityInvocation {
	if !managedCompatibilityRun(ctx, p) {
		return nil
	}
	i, _ := ctx.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation)
	return i
}

func managedLaunchPhase(ctx context.Context, id string) *managedCompatibilityPhase {
	if ctx == nil {
		return nil
	}
	i, _ := ctx.Value(managedCompatibilityContextKey{}).(*managedCompatibilityInvocation)
	if i == nil || !managedCompatibilityRun(ctx, i.provider) || len(i.phases) == 0 {
		return nil
	}
	p := i.phases[len(i.phases)-1]
	active := compatibilityActiveInvocation(&p.session)
	if active == nil || active.Command.ID != id {
		return nil
	}
	return p
}

func compatibilityImageEqual(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}

func compatibilityImageCopy(image restorejournal.Image) restorejournal.Image {
	return restorejournal.Image{Exists: image.Exists, Data: bytes.Clone(image.Data)}
}

func compatibilityStateCopy(state State) (State, error) {
	data, err := json.Marshal(state)
	var copied State
	if err == nil {
		err = json.Unmarshal(data, &copied)
	}
	return copied, err
}

// Caller holds Manager.mu, before the actual durable intent is attempted.
func (i *managedCompatibilityInvocation) preparePhaseLocked(session compatibilitySession) (*managedCompatibilityPhase, error) {
	before, err := compatibilityStateCopy(i.manager.state)
	if err != nil {
		return nil, err
	}
	next := before
	next.SchemaVersion, next.CompatibilitySession, next.CompatibilityFinalizing = compatibilitySupervisedSchema, &session, true
	intent, err := compatibilityStateImage(next)
	if err != nil {
		return nil, err
	}
	p := &managedCompatibilityPhase{session: session, before: before, beforeImage: compatibilityImageCopy(i.manager.image), intentImage: intent}
	i.phases = append(i.phases, p)
	return p, nil
}

func (i *managedCompatibilityInvocation) cleanupCurrent(ctx context.Context) (resultErr error) {
	endTiming := i.beginTiming(ctx, "cleanup-owner-current", "cleanup")
	defer func() { endTiming(resultErr) }()
	if i == nil || i.cleanup == nil || i.manager == nil || i.provider == nil || i.provider.manager != i.manager || i.runtime == nil || i.binding.manager != i.manager {
		return ErrCompatibilityQuiescenceUnknown
	}
	p := i.provider
	if p.managedControl == nil || !p.managedControl.MatchesControlRoot(p.review.ControlPath) {
		return errAdaptiveManagedValidator
	}
	if err := p.managedControl.CurrentForCleanup(ctx); err != nil {
		return err
	}
	if !i.runtimeClosed {
		runtimeTiming := i.beginTiming(ctx, "cleanup-runtime-check", "cleanup")
		runtimeErr := i.runtime.Check(ctx)
		runtimeTiming(runtimeErr)
		if runtimeErr != nil {
			return runtimeErr
		}
		if !compatibilityJSONEqual(i.runtime.Descriptor(), p.managedDescriptor) || p.managedReviewMaterial(ctx) != nil {
			return errAdaptiveManagedValidator
		}
	}
	filesTiming := i.beginTiming(ctx, "cleanup-paths-file-hashes", "cleanup")
	filesErr := errors.Join(compatibilityProtectedReview(i.manager.Path, p.review), compatibilityFilesUnchanged(p.review), selectedReviewContext(ctx))
	filesTiming(filesErr)
	return filesErr
}

func (i *managedCompatibilityInvocation) withCleanup(use func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), managedCompatibilityCleanupTimeout)
	defer cancel()
	return i.cleanup.WithCurrent(ctx, func() error {
		if err := i.cleanupCurrent(ctx); err != nil {
			return err
		}
		return errors.Join(use(ctx), i.cleanupCurrent(ctx))
	})
}

// Only an actual failed/unattempted helper Start permits rollback of our exact
// intent. There is no fabricated helper receipt, PID absence or restart proof.
func (i *managedCompatibilityInvocation) rollbackUnstarted(p *managedCompatibilityPhase) error {
	if p == nil || p.launched || p.joined {
		return ErrCompatibilityQuiescenceUnknown
	}
	return i.withCleanup(func(ctx context.Context) error {
		m := i.manager
		m.mu.Lock()
		defer m.mu.Unlock()
		target, err := restorejournal.OpenFileTarget(m.Path)
		if err != nil {
			return err
		}
		defer target.Close()
		image, err := target.Read(ctx)
		if err != nil {
			return err
		}
		switch {
		case compatibilityImageEqual(image, p.intentImage):
			if err := target.CompareAndSwap(ctx, image, p.beforeImage); err != nil {
				return err
			}
		case compatibilityImageEqual(image, p.beforeImage):
		default:
			return restorejournal.ErrConflict
		}
		confirmed, err := target.Read(ctx)
		if err != nil || !compatibilityImageEqual(confirmed, p.beforeImage) {
			return errors.Join(restorejournal.ErrRecovery, err)
		}
		m.state, m.image = p.before, compatibilityImageCopy(p.beforeImage)
		m.compatibilityUnknown, m.writeBlocked = false, false
		p.rolledBack = true
		return nil
	})
}

func compatibilityHelperMatches(r compatibilityReceipt, helper components.NFQWSSupervisionIdentity) bool {
	return helper.PID > 1 && helper.Group == helper.PID && compatibilityPositiveDecimal(helper.Start) && r.PID == helper.PID && r.Group == helper.Group && r.Start == helper.Start && r.BootID == helper.BootID
}

// Caller retains the original operation. Even after cancellation, actual Wait
// must have joined and the helper's exact ECHILD terminal must be read and ACKed.
func (i *managedCompatibilityInvocation) acknowledgePhase(p *managedCompatibilityPhase) error {
	if p == nil || !p.launched || !p.joined {
		return ErrCompatibilityQuiescenceUnknown
	}
	return i.withCleanup(func(ctx context.Context) error {
		m := i.manager
		m.mu.Lock()
		defer m.mu.Unlock()
		state, image, err := m.readCompatibilityResultLocked(ctx, p.session)
		if err != nil {
			return err
		}
		active := compatibilityActiveInvocation(state.CompatibilitySession)
		if active == nil || !compatibilityHelperMatches(active.Receipt, p.helper) || !compatibilityReceiptTerminal(active.Receipt) {
			return ErrCompatibilityQuiescenceUnknown
		}
		proposal, err := compatibilityStateCopy(state)
		if err != nil {
			return err
		}
		compatibilityActiveInvocation(proposal.CompatibilitySession).Acknowledged = true
		ack, err := compatibilityStateImage(proposal)
		if err != nil {
			return err
		}
		p.terminal, p.terminalImage, p.ackImage = state, compatibilityImageCopy(image), ack
		if err := m.acknowledgeCompatibilityResultLocked(ctx, state, image); err != nil {
			return err
		}
		p.acknowledged = true
		return nil
	})
}

func (p *SupervisedCompatibilityProvider) completeManagedPhase(i *managedCompatibilityInvocation, phase *managedCompatibilityPhase, launchErr error) (CompatibilityCompletion, error) {
	if !phase.launched {
		if err := i.rollbackUnstarted(phase); err != nil {
			return CompatibilityCompletion{}, errors.Join(ErrCompatibilityQuiescenceUnknown, launchErr, err)
		}
		// Physical no-start was proved by our actual Start and exact rollback.
		// A generic error from executable/admission lookup is not ECHILD unknown.
		return CompatibilityCompletion{Quiescent: true}, errors.New("compatibility helper was not started")
	}
	if err := i.acknowledgePhase(phase); err != nil {
		return CompatibilityCompletion{}, errors.Join(ErrCompatibilityQuiescenceUnknown, launchErr, err)
	}
	m := i.manager
	m.mu.RLock()
	completed, err := compatibilityStateCopy(m.state)
	m.mu.RUnlock()
	if err != nil || completed.CompatibilitySession == nil {
		return CompatibilityCompletion{}, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
	}
	p.mu.Lock()
	p.session = completed.CompatibilitySession
	p.mu.Unlock()
	active := compatibilityActiveInvocation(completed.CompatibilitySession)
	result := CompatibilityCompletion{Output: []byte(active.Output), Started: active.Receipt.Started, Quiescent: true}
	if !compatibilityInvocationSucceeded(*active) || launchErr != nil {
		return result, fmt.Errorf("compatibility command completed with refusal (exit %d, cancelled %t)", active.Receipt.ExitCode, active.Receipt.Cancelled)
	}
	return result, nil
}

func (i *managedCompatibilityInvocation) phasesKnown() bool {
	for _, phase := range i.phases {
		if phase == nil || (!phase.rolledBack && (!phase.launched || !phase.joined || !phase.acknowledged)) {
			return false
		}
	}
	return true
}

func (i *managedCompatibilityInvocation) finish() error {
	i.finished = true // Validate/Run/Wait have all returned synchronously.
	if !i.phasesKnown() {
		return ErrCompatibilityQuiescenceUnknown
	}
	return i.withCleanup(func(ctx context.Context) error {
		m := i.manager
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.nativeRunning || m.compatibilityUnknownLocked() || m.writeBlocked {
			return ErrCompatibilityQuiescenceUnknown
		}
		image, err := restorejournal.ReadFileImage(ctx, m.Path)
		if err != nil || !compatibilityImageEqual(image, m.image) {
			return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
		if i.file, err = selectedReviewFileIdentity(m.Path); err != nil {
			return err
		}
		if i.parent, err = selectedReviewFileIdentity(filepath.Dir(m.Path)); err != nil {
			return err
		}
		i.image = compatibilityImageCopy(image)
		i.settled = true
		return nil
	})
}

// RetireKnown releases only the exact original managed lease after actual
// synchronous completion, terminal/ACK or no-start rollback, source readback
// and original cleanup-owner bookends. A timeout/copy/receipt cannot release it.
// App releases its original admission only after this succeeds once.
func (r *ManagedCompatibilityCompletion) RetireKnown(ctx context.Context) (resultErr error) {
	if r == nil || r.self != r || selectedReviewContext(ctx) != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.invocation
	if r.retired || i == nil || !i.finished || i.stageUnknown {
		return ErrCompatibilityQuiescenceUnknown
	}
	retireTiming := i.beginTiming(ctx, "completion-retire", "cleanup")
	defer func() { retireTiming(resultErr) }()
	if !i.settled {
		if err := i.recoverOriginal(ctx); err != nil {
			return err
		}
	}
	if !i.phasesKnown() || i.file == nil || i.parent == nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	err := i.cleanup.WithCurrent(ctx, func() error {
		if err := i.cleanupCurrent(ctx); err != nil {
			return err
		}
		m, p := i.manager, i.provider
		m.mu.Lock()
		defer m.mu.Unlock()
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.managedInvocation != i || p.running || p.unknown || m.nativeRunning || m.compatibilityUnknownLocked() || m.writeBlocked || !compatibilityImageEqual(m.image, i.image) {
			return ErrCompatibilityQuiescenceUnknown
		}
		file, err := selectedReviewFileIdentity(m.Path)
		parent, parentErr := selectedReviewFileIdentity(filepath.Dir(m.Path))
		image, readErr := restorejournal.ReadFileImage(ctx, m.Path)
		if err != nil || parentErr != nil || readErr != nil || !os.SameFile(file, i.file) || !os.SameFile(parent, i.parent) || !compatibilityImageEqual(image, i.image) {
			return errors.Join(ErrCompatibilityQuiescenceUnknown, err, parentErr, readErr)
		}
		if err := i.cleanupCurrent(ctx); err != nil {
			return err
		}
		if !i.runtimeClosed {
			if err := i.runtime.Close(); err != nil {
				return err
			}
			i.runtimeClosed = true // Only this successful actual Close writes it.
		}
		if err := p.managedControl.CurrentForCleanup(ctx); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	i.provider.mu.Lock()
	defer i.provider.mu.Unlock()
	if i.provider.managedInvocation != i {
		return ErrCompatibilityQuiescenceUnknown
	}
	i.provider.managedRetiredSession = i.provider.session
	i.provider.managedInvocation, r.retired = nil, true
	return nil
}
