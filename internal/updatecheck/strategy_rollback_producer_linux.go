//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type strategyRollbackProducerKey struct{}
type strategyRollbackProducer struct {
	self          *strategyRollbackProducer
	adapter       *SelfUpdateFileAdapter
	original, ctx context.Context
	completion    *candidateAbsenceCompletion
	image         restorejournal.Image
	active        atomic.Bool
}

// Only cleanupAbsentCandidate calls this after its actual sole Wait, original
// PID removal and sealed completion. No public constructor accepts receipt data
// as the source. Durable retention never becomes a process owner after restart.
func (a *SelfUpdateFileAdapter) retainStoppedStrategyHistory(ctx context.Context, w *candidateStartWait) (result error) {
	if !productionOrdinaryRoleAdapter(a) {
		return ErrFileCommandUnsettled
	}
	return a.retainStoppedStrategyHistoryAt(ctx, w)
}

// Intrinsic source checks are exercised only by the private copied-controller
// native fixture. Production always passes the fixed-root wrapper above.
func (a *SelfUpdateFileAdapter) retainStoppedStrategyHistoryAt(ctx context.Context, w *candidateStartWait) (result error) {
	if ctx == nil || w == nil || w.owner == nil || ctx != w.owner.held {
		return ErrFileCommandUnsettled
	}
	if err := w.owner.current(ctx, a, w.owner.id); err != nil {
		return err
	}
	review := w.review
	if review.StrategyPair == nil {
		return nil
	}
	image, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil {
		return err
	}
	if image.Exists && schema == review.StrategyPair.StateSchema && digestBytes(image.Data) == review.StrategyPair.StateSHA256 {
		return nil
	}
	if !image.Exists || !retentionReaders(review.StrategyPair, schema) {
		return ErrStrategyStateAdmission
	}
	w.mu.Lock()
	completion := w.completion
	w.mu.Unlock()
	if completion == nil || completion.self != completion {
		return ErrFileCommandUnsettled
	}
	source := &strategyRollbackProducer{adapter: a, original: ctx, completion: completion, image: image}
	source.self = source
	scoped := context.WithValue(ctx, strategyRollbackProducerKey{}, source)
	source.ctx = scoped
	source.active.Store(true)
	defer source.active.Store(false)
	// A changed managed state must have the original store writer marker.
	// Taking only its existing lease prevents minting ownership for a copied edit.
	state, err := restorejournal.OpenExistingFileTarget(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	check := func(c context.Context) error { return source.current(c, state) }
	if err := check(scoped); err != nil {
		return err
	}
	_, recordReview, err := a.loadHeader(scoped, review.ID)
	if err != nil || !reflect.DeepEqual(recordReview, review) {
		return ErrStrategyStateAdmission
	}
	// Probe flags were observed before Stop. Under Stop we rehash those exact
	// immutable binaries and inventory, never launch new compatibility probes.
	adjusted := *review.StrategyPair
	adjusted.StateSchema, adjusted.StateSHA256 = schema, digestBytes(image.Data)
	if err := a.checkStrategyPairMode(scoped, review, image, schema, false, &adjusted); err != nil {
		return err
	}
	root, err := a.commandRoot(review.ID)
	if err != nil {
		return err
	}
	defer root.Close()
	originalSnapshot, err := root.ReadLimited("private-snapshot.json", 6<<20)
	if err != nil {
		return err
	}
	record, _, err := a.loadHeader(scoped, review.ID)
	if err != nil {
		return err
	}
	proof := strategyRollbackRetention{Schema: 1, ID: review.ID, ReviewSHA256: record.FileReviewSHA256, SnapshotSHA256: digestBytes(originalSnapshot), OriginalStateSHA256: review.StrategyPair.StateSHA256, StateSchema: schema, Current: image, Controllers: append([]strategyControllerProof(nil), review.StrategyPair.Controllers...), StopIntent: completion.intent, CandidateFinal: completion.final}
	data, err := strategyRetentionBytes(proof)
	if err != nil || len(data) > restorejournal.MaxImageBytes {
		return ErrStrategyStateAdmission
	}
	target, err := restorejournal.OpenFileTarget(filepath.Join(a.directory, review.ID, strategyRollbackRetentionName))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, target.Close()) }()
	before, err := target.Read(scoped)
	if err != nil {
		return err
	}
	if before.Exists {
		observed, observeErr := a.readPrivateFileImage(scoped, filepath.Join(a.directory, review.ID, strategyRollbackRetentionName))
		if observeErr != nil || !observed.Exists || !bytes.Equal(observed.Data, before.Data) || !bytes.Equal(before.Data, data) {
			return ErrStrategyStateAdmission
		}
		return check(scoped)
	}
	if err := check(scoped); err != nil {
		return err
	}
	err = target.CompareAndSwapWithRenameAdmission(scoped, before, restorejournal.Image{Exists: true, Data: data}, func(c context.Context, rename func() error) error {
		if err := check(c); err != nil {
			return err
		}
		return a.EffectAdmission(c, review.ID, "stop-owned", strategyRollbackSealEffect, rename)
	})
	observed, observeErr := a.readPrivateFileImage(scoped, filepath.Join(a.directory, review.ID, strategyRollbackRetentionName))
	if observeErr == nil && (!observed.Exists || !bytes.Equal(observed.Data, data)) {
		observeErr = ErrStrategyStateAdmission
	}
	return errors.Join(err, observeErr, check(scoped))
}

func (s *strategyRollbackProducer) current(ctx context.Context, state *restorejournal.FileTarget) error {
	if s == nil || s.self != s || !s.active.Load() || ctx != s.ctx || ctx.Value(strategyRollbackProducerKey{}) != s || s.original == nil || s.original.Err() != nil || ctx.Err() != nil {
		return ErrFileCommandUnsettled
	}
	a, c := s.adapter, s.completion
	w := c.wait
	if err := w.owner.current(ctx, a, w.owner.id); err != nil {
		return err
	}
	if !w.mu.TryLock() {
		return ErrFileCommandUnsettled
	}
	valid := w.self == w && !w.failed && w.consumed && w.completion == c && w.waitCompleted(c.final) == nil
	w.mu.Unlock()
	if !valid {
		return ErrFileCommandUnsettled
	}
	if exists, err := w.pid.observe(); err != nil || exists {
		return errors.Join(ErrFileCommandUnsettled, err)
	}
	if err := a.candidateStoppedCompletionFactsAt(ctx, c, true); err != nil {
		return err
	}
	image, err := state.Read(ctx)
	if err != nil || image.Exists != s.image.Exists || !bytes.Equal(image.Data, s.image.Data) {
		return ErrStrategyStateAdmission
	}
	actual, schema, err := a.inspectOrdinaryStrategyState(ctx)
	if err != nil || schema == 0 || actual.Exists != s.image.Exists || !bytes.Equal(actual.Data, s.image.Data) {
		return ErrStrategyStateAdmission
	}
	adjusted := *w.review.StrategyPair
	adjusted.StateSchema, adjusted.StateSHA256 = schema, digestBytes(actual.Data)
	return a.checkStrategyPairMode(ctx, w.review, actual, schema, false, &adjusted)
}
