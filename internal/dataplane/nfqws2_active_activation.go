package dataplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
)

type nfqws2ActiveActivationRegistrarKey struct{}

// No exported constructor or accessor: only SAME NFQ Activate issues this
// one-use seal from the actual untimed reader after SAME LAN Activate.
type nfqws2ActiveActivationSeal struct {
	self      *nfqws2ActiveActivationSeal
	mu        sync.Mutex
	execution *nfqws2ActiveExecution
	scope     *executionResourceScope
	selection *NFQWSScopedSelection
	command   nfqws2ActiveProcessCommand
	spec      NFQWSScopedSpec
	consumed  bool
}

func nfqws2OriginalActivationDeadline(ctx context.Context, now time.Time) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrNFQWSScopedOwner
	}
	deadline, finite := ctx.Deadline()
	if !finite || !now.Before(deadline) {
		return time.Time{}, ErrNFQWSScopedOwner
	}
	if ceiling := now.Add(15 * time.Second); deadline.After(ceiling) {
		deadline = ceiling
	}
	return deadline.UTC(), nil
}

// Every potentially expensive physical/source/COMMON read precedes the stamp.
// Closing reads and native Start still consume the original fixed 15s window.
func (e *nfqws2ActiveExecution) issueOriginalActivation(ctx context.Context) (*nfqws2ActiveActivationSeal, error) {
	if err := e.prepare(ctx); err != nil {
		return nil, err
	}
	s, ok := ctx.Value(nfqws2ActiveActivationRegistrarKey{}).(*executionResourceScope)
	if !ok || s == nil || s.manager != e.material.manager || s.adapterOwner != e.material.adapter || s.adapter != "nfqws2" || !nfqws2ActiveSamePlan(s.plan, e.plan) {
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	e.mu.Lock()
	if e.activationAttempted {
		e.mu.Unlock()
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	e.activationAttempted = true
	e.mu.Unlock()
	s.mu.Lock()
	err := s.check(ctx, nil, true)
	s.mu.Unlock()
	if err != nil {
		return nil, preflightRefusalError{err}
	}
	if err := e.verifyLAN(ctx, e.plan.LAN); err != nil {
		return nil, preflightRefusalError{err}
	}
	if err := e.preparedAbsence(ctx); err != nil {
		return nil, preflightRefusalError{err}
	}
	parent, err := components.ReadNFQWSSupervisionIdentity()
	if err != nil || parent != e.material.intent.Parent {
		return nil, preflightRefusalError{errors.Join(ErrNFQWSScopedOwner, err)}
	}
	if err := e.forward(ctx); err != nil {
		return nil, preflightRefusalError{err}
	}
	if _, err := os.Lstat(filepath.Join(e.material.intent.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
		return nil, preflightRefusalError{errors.Join(ErrNFQWSScopedOwner, err)}
	}
	r := e.material
	r.mu.Lock()
	if r.closed || !r.executionBound || r.command.ID != "" {
		r.mu.Unlock()
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	if err := r.currentLocked(ctx); err != nil {
		r.mu.Unlock()
		return nil, preflightRefusalError{err}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		r.mu.Unlock()
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	deadline, err := nfqws2OriginalActivationDeadline(ctx, time.Now())
	if err != nil {
		r.mu.Unlock()
		return nil, preflightRefusalError{err}
	}
	r.command = r.intent.command(hex.EncodeToString(nonce[:]), deadline)
	command, spec := r.command.clone(), r.spec()
	r.mu.Unlock()
	if nfqws2ActiveCommandMatchesSpec(command, spec) != nil {
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	selection, err := ReviewNFQWSScopedSelection(ctx, r.source, r.reference, e.plan, spec, e.spec.Matches)
	if err != nil {
		return nil, preflightRefusalError{err}
	}
	if err := e.forward(ctx); err != nil {
		_ = selection.Close()
		return nil, preflightRefusalError{err}
	}
	if !time.Now().Before(command.ActivationDeadline) {
		_ = selection.Close()
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	seal := &nfqws2ActiveActivationSeal{execution: e, scope: s, selection: selection, command: command, spec: selection.Spec()}
	seal.self = seal
	r.mu.Lock()
	if r.closed || r.issuedSelection != nil {
		r.mu.Unlock()
		_ = selection.Close()
		return nil, preflightRefusalError{ErrNFQWSScopedOwner}
	}
	r.issuedSelection = selection
	r.mu.Unlock()
	e.mu.Lock()
	prepared := e.selection
	e.selection, e.spec, e.activationSeal = selection, seal.spec.Clone(), seal
	e.mu.Unlock()
	// Closing the superseded comparison reader does not close the actual
	// selected source/component. App retains those through known retirement.
	_ = prepared.Close()
	return seal, nil
}

func (s *nfqws2ActiveActivationSeal) consume(ctx context.Context, e *nfqws2ActiveExecution) error {
	if s == nil || s.self != s || ctx == nil || e == nil || e.self != e || s.execution != e || e.activationSeal != s ||
		ctx.Value(nfqws2ActiveActivationRegistrarKey{}) != s.scope || e.selection != s.selection || !reflect.DeepEqual(e.spec, s.spec) || !reflect.DeepEqual(e.material.command, s.command) {
		return ErrNFQWSScopedOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed || ctx.Err() != nil || !time.Now().Before(s.command.ActivationDeadline) {
		return ErrNFQWSScopedOwner
	}
	s.consumed = true
	return nil
}

// Active lifetime checks retain the same immutable, consumed seal. Expiry is
// deliberately not renewed or reinterpreted as ongoing process permission.
func (s *nfqws2ActiveActivationSeal) current(e *nfqws2ActiveExecution) error {
	if s == nil || s.self != s || e == nil || e.self != e || s.execution != e || e.activationSeal != s || e.selection != s.selection ||
		!reflect.DeepEqual(e.spec, s.spec) || !reflect.DeepEqual(e.material.command, s.command) || !reflect.DeepEqual(nfqws2ActiveIntentFromCommand(s.command), e.material.intent) {
		return ErrNFQWSScopedOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.consumed {
		return ErrNFQWSScopedOwner
	}
	return nil
}

// Original absence before native issuance, without compiling placeholder
// commands or issuing a resource. The original whole graph separately proves
// OUTPUT-only stock queues; every project or LAN NFQ consumer still refuses.
func (e *nfqws2ActiveExecution) preparedAbsence(ctx context.Context) error {
	if err := e.checkOriginalQueueAbsent(ctx); err != nil {
		return err
	}
	if err := e.observeBackendAbsent(ctx, nil); err != nil {
		return err
	}
	return e.checkOriginalQueueAbsent(ctx)
}
