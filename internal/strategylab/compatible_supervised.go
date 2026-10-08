package strategylab

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// SupervisedCompatibilityProvider owns only the two closed no-intercept
// compatibility phases. CORE binds it to the same Manager used for Validate.
// Approval comes from the component owner, never from HTTP or candidate data.
// A helper receives only an invocation ID and reads its frozen command from
// this Manager's existing StrategyLab state file.
type SupervisedCompatibilityProvider struct {
	self    *SupervisedCompatibilityProvider
	manager *Manager
	review  compatibilityReview
	mu      sync.Mutex
	running bool
	unknown bool
	session *compatibilitySession
	// Set only by the actual managed-material constructor, before any Run.
	managedControl    *operationgate.ControlEpochReview
	managedDescriptor components.NFQWSRuntimeDescriptor
	managedInvocation *managedCompatibilityInvocation
	// Written only after successful original completion retirement. Reopening
	// saved receipt data never manufactures this process-lifetime proof.
	managedRetiredSession *compatibilitySession
	// Tests use their own fixed helper entry in the Go test executable.
	// Production always uses the early CORE CLI dispatch shown below.
	helperPrefix []string
}

func NewSupervisedCompatibilityProvider(manager *Manager, approval CompatibilityApproval) (*SupervisedCompatibilityProvider, error) {
	if manager == nil || !compatibilityCleanPath(manager.Path) {
		return nil, errors.New("supervised compatibility requires its existing private StrategyLab file")
	}
	review, err := compatibilityReviewApproved(approval)
	if err != nil {
		return nil, err
	}
	if err := compatibilityProtectedReview(manager.Path, review); err != nil {
		return nil, err
	}
	manager.mu.RLock()
	unknown := manager.compatibilityUnknownLocked() || manager.writeBlocked
	manager.mu.RUnlock()
	if unknown {
		return nil, ErrCompatibilityQuiescenceUnknown
	}
	provider := &SupervisedCompatibilityProvider{manager: manager, review: review}
	provider.self = provider
	return provider, nil
}

func compatibilityProtectedReview(statePath string, review compatibilityReview) error {
	if err := compatibilityProtectedPath(statePath, true); err != nil {
		return err
	}
	if err := compatibilityPrivateStateParent(statePath); err != nil {
		return err
	}
	if err := compatibilityProtectedPath(filepath.Join(review.ControlPath, "current-v1.json"), false); err != nil {
		return err
	}
	for _, file := range append([]compatibilityFileBinding{review.Binary}, review.Assets...) {
		if err := compatibilityProtectedPath(file.Path, false); err != nil {
			return err
		}
	}
	return nil
}

func (p *SupervisedCompatibilityProvider) Run(parent context.Context, binary string, args ...string) (result CompatibilityCompletion, err error) {
	result.Quiescent = true // Rejections before intent/launch have no owned tree.
	if parent == nil {
		return result, errors.New("compatibility context is required")
	}
	if p.managedControl != nil {
		if err := p.managedMaterialCurrent(parent); err != nil {
			return result, err
		}
	}
	p.mu.Lock()
	if p.unknown {
		p.mu.Unlock()
		return CompatibilityCompletion{}, ErrCompatibilityQuiescenceUnknown
	}
	if p.running {
		p.mu.Unlock()
		return result, errCompatibilityBusy
	}
	p.running = true
	prior := p.session
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.running = false
		if !result.Quiescent || errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
			p.unknown = true
			result.Quiescent = false
			err = errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
		p.mu.Unlock()
	}()
	if err := parent.Err(); err != nil {
		return result, err
	}
	if binary != p.review.Binary.Path {
		return result, errors.New("compatibility binary differs from owner approval")
	}
	phase, err := compatibilityCommandPhase(p.review.BaseArguments, args)
	if err != nil {
		return result, err
	}
	total := 0
	for _, arg := range args {
		total += len(arg)
	}
	if total > 32768 {
		return result, errors.New("compatibility command exceeds the supervision byte bound")
	}
	ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
	defer cancel()
	if err := compatibilityProtectedReview(p.manager.Path, p.review); err != nil {
		return result, err
	}
	if err := compatibilityFilesUnchanged(p.review); err != nil {
		return result, err
	}
	if err := compatibilityControlCurrent(ctx, p.review); err != nil {
		return result, err
	}
	identity, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil {
		return result, err
	}
	id, err := compatibilityNonce()
	if err != nil {
		return result, err
	}
	session := compatibilitySession{Schema: compatibilityRecordSchema, Active: phase}
	if phase == "dry-run" {
		session.ID, err = compatibilityNonce()
		if err != nil {
			return result, err
		}
	} else {
		// Only this provider's acknowledged dry-run can authorize its next
		// phase. Reopening a completed state never resumes a pending command.
		if prior == nil || prior.Active != "dry-run" || !compatibilityInvocationSucceeded(*prior.DryRun) || !compatibilityReviewsEqual(prior.DryRun.Command.Review, p.review) {
			return result, errors.New("Lua-init requires this provider's exact successful dry-run")
		}
		session.ID, session.DryRun = prior.ID, prior.DryRun
	}
	deadline, _ := ctx.Deadline()
	command := compatibilityCommand{ID: id, SessionID: session.ID, Phase: phase, BootID: identity.BootID, ParentStart: identity.Start, ParentPID: identity.PID, Deadline: deadline.UTC(), Args: append([]string(nil), args...), Review: p.review}
	invocation := &compatibilityInvocation{Command: command, CommandSHA256: compatibilityCommandDigest(command), Receipt: compatibilityReceipt{State: "intent"}}
	if phase == "dry-run" {
		session.DryRun = invocation
	} else {
		session.LuaInit = invocation
	}
	p.manager.mu.Lock()
	if !p.manager.nativeRunning {
		p.manager.mu.Unlock()
		return result, errors.New("compatibility provider requires Manager validation admission")
	}
	managed := managedInvocation(parent, p)
	var managedPhase *managedCompatibilityPhase
	if managed != nil {
		managedPhase, err = managed.preparePhaseLocked(session)
	}
	if err == nil {
		err = p.manager.beginCompatibilitySessionLocked(ctx, session)
	}
	p.manager.mu.Unlock()
	if err != nil {
		if managedPhase != nil {
			result.Quiescent = false
			return p.completeManagedPhase(managed, managedPhase, err)
		}
		return result, err
	}
	// After intent, failure is retained unknown unless this exact helper
	// publishes and the parent acknowledges an ECHILD terminal receipt.
	result.Quiescent = false
	helper, launchErr := compatibilityLaunchSupervisor(ctx, p.manager.Path, p.review, id, p.helperPrefix)
	if managedPhase != nil {
		return p.completeManagedPhase(managed, managedPhase, launchErr)
	}
	if launchErr != nil {
		err = launchErr
		return result, err
	}
	p.manager.mu.Lock()
	state, image, err := p.manager.readCompatibilityResultLocked(ctx, session)
	if err == nil {
		r := compatibilityActiveInvocation(state.CompatibilitySession).Receipt
		if r.PID != helper.PID || r.Group != helper.Group || r.Start != helper.Start || r.BootID != helper.BootID {
			err = ErrCompatibilityQuiescenceUnknown
		}
	}
	if err == nil {
		err = compatibilityControlCurrent(ctx, p.review)
	}
	if err == nil {
		err = p.manager.acknowledgeCompatibilityResultLocked(ctx, state, image)
	}
	if err != nil {
		p.manager.compatibilityUnknown = true
		p.manager.mu.Unlock()
		return result, err
	}
	completed := *state.CompatibilitySession
	active := compatibilityActiveInvocation(&completed)
	result = CompatibilityCompletion{Output: []byte(active.Output), Started: active.Receipt.Started, Quiescent: true}
	p.manager.mu.Unlock()
	p.mu.Lock()
	p.session = &completed
	p.mu.Unlock()
	if !compatibilityInvocationSucceeded(*active) {
		return result, fmt.Errorf("compatibility command rejected after ECHILD (exit %d, cancelled %t)", active.Receipt.ExitCode, active.Receipt.Cancelled)
	}
	return result, nil
}

func compatibilityControlCurrent(ctx context.Context, review compatibilityReview) error {
	control, present, err := operationgate.ReadSelfUpdateStop(ctx, review.ControlPath)
	if err != nil || !present {
		return errors.Join(operationgate.ErrSelfUpdateStopJournal, err)
	}
	if control.Stopped {
		return operationgate.ErrSelfUpdateStopped
	}
	if control.InstallationID != review.InstallationID || control.Sequence != review.Sequence {
		return operationgate.ErrSelfUpdateStopChanged
	}
	return nil
}

// Called only by Manager.Validate after its outer validator has returned a
// known result. Phase ACK never clears this marker: a timeout or crash before
// this point leaves durable unknown, even if ACK fsync eventually completes.
// This is only a precondition check. The guarded publisher retains the marker
// in memory until its exact candidate image has been confirmed on disk.
func (m *Manager) prepareCompatibilityPublicationLocked(ctx context.Context, validation Validation) error {
	if validation.QuiescenceUnknown || !m.state.CompatibilityFinalizing || ctx.Err() != nil || m.compatibilityRetainedUnknownLocked() || m.writeBlocked || !m.nativeRunning || m.state.CompatibilitySession == nil || compatibilitySessionUnknown(*m.state.CompatibilitySession) {
		return ErrCompatibilityQuiescenceUnknown
	}
	var provider *SupervisedCompatibilityProvider
	switch validator := m.Validator.(type) {
	case CompatibleValidator:
		provider, _ = validator.Provider.(*SupervisedCompatibilityProvider)
	case *CompatibleValidator:
		provider, _ = validator.Provider.(*SupervisedCompatibilityProvider)
	}
	if provider == nil || provider.manager != m {
		return ErrCompatibilityQuiescenceUnknown
	}
	if provider.managedControl != nil {
		if err := provider.managedMaterialCurrent(ctx); err != nil {
			return errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
	}
	provider.mu.Lock()
	verified := !provider.running && !provider.unknown && provider.session != nil && compatibilityJSONEqual(provider.session, m.state.CompatibilitySession)
	provider.mu.Unlock()
	if !verified || compatibilityControlCurrent(ctx, provider.review) != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	active := compatibilityActiveInvocation(m.state.CompatibilitySession)
	if !time.Now().Before(active.Command.Deadline) {
		return ErrCompatibilityQuiescenceUnknown
	}
	offset, end := 1+len(active.Command.Review.BaseArguments), len(active.Command.Args)
	if active.Command.Phase == "dry-run" {
		offset++
	} else {
		end--
	}
	if offset >= end || !slices.Equal(active.Command.Args[offset:end], validation.Arguments) {
		return ErrCompatibilityQuiescenceUnknown
	}
	passed := compatibilityInvocationSucceeded(*active)
	if passed {
		if active.Command.Phase != "lua-init" || !validation.OK || !validation.Native || !validation.LuaChecked || validation.Code != "COMPATIBLE" {
			return ErrCompatibilityQuiescenceUnknown
		}
	} else if validation.OK || validation.Native || validation.LuaChecked || validation.Code != "COMPATIBILITY_REJECTED" {
		return ErrCompatibilityQuiescenceUnknown
	}
	if ctx.Err() != nil {
		return ErrCompatibilityQuiescenceUnknown
	}
	return nil
}

func compatibilityNonce() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func compatibilityDiagnostic(output []byte) string {
	text := strings.ToValidUTF8(string(output), "?")
	if len(text) > compatibilityMaxOutputBytes {
		text = text[len(text)-compatibilityMaxOutputBytes:]
		for len(text) > 0 && !utf8.ValidString(text) {
			text = text[1:]
		}
	}
	return text
}
