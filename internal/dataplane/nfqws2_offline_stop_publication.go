package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// OfflineNFQWS2StopPublication is a metadata-only write-ahead comparison. It
// cannot carry a network step or resource. The offline coordinator durably
// retains it before CompleteNFQWS2EmptyStopPublication, which independently
// requires the same originally bound source and fresh absence every time.
type OfflineNFQWS2StopPublication struct {
	Before map[string]restorejournal.Image `json:"before"`
	After  map[string]restorejournal.Image `json:"after"`
}

func emptyStopNames(target Plan) []string {
	return []string{"latest-plan.json", "latest-committed-plan.json", filepath.Join("transactions", target.PlanID, "execution.json"), "latest-execution.json"}
}

func emptyStopImageEqual(a, b restorejournal.Image) bool {
	return a.Exists == b.Exists && bytes.Equal(a.Data, b.Data)
}

// ValidateNFQWS2EmptyStopPlan requires the exact normal-builder result. Empty
// adapters alone are insufficient: DNS, network policy, actions, retiring
// adapters and hidden resource claims cannot be smuggled into a continuation.
func ValidateNFQWS2EmptyStopPlan(target Plan) error {
	when, err := time.Parse(time.RFC3339, target.CreatedAt)
	if err != nil || !target.Noop || !target.Ready || target.State != "ready" || target.Revision == 0 {
		return ErrReviewChanged
	}
	expected, err := BuildAt(Input{Revision: target.Revision, SiteExclusions: target.SiteExclusions}, when)
	expectedRaw, _ := json.Marshal(expected)
	targetRaw, _ := json.Marshal(target)
	if err != nil || !bytes.Equal(expectedRaw, targetRaw) {
		return ErrReviewChanged
	}
	return nil
}

func readEmptyStopImage(root *ownedfs.Root, name string) (restorejournal.Image, error) {
	file, err := offlineStopOpenFile(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return restorejournal.Image{}, nil
	}
	if err != nil {
		return restorejournal.Image{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !offlineStopPrivateFile(info) {
		return restorejournal.Image{}, ErrReviewChanged
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return restorejournal.Image{}, ErrReviewChanged
	}
	return restorejournal.Image{Exists: true, Data: raw}, nil
}

func strictEmptyStopExecution(image restorejournal.Image, target Plan) (Execution, error) {
	var execution Execution
	d := json.NewDecoder(bytes.NewReader(image.Data))
	d.DisallowUnknownFields()
	if !image.Exists || d.Decode(&execution) != nil || d.Decode(new(any)) != io.EOF || execution.PlanID != target.PlanID || execution.Digest != target.Digest ||
		execution.ResourcePlanID != "" || len(execution.Resources) != 0 || execution.Steps == nil || len(execution.Steps) != 0 || execution.Error != "" || execution.RollbackVerified {
		return Execution{}, ErrExecutionJournal
	}
	canonical, err := json.MarshalIndent(execution, "", "  ")
	started, parseErr := time.Parse(time.RFC3339Nano, execution.StartedAt)
	created, _ := time.Parse(time.RFC3339, target.CreatedAt)
	if err != nil || !bytes.Equal(canonical, image.Data) || parseErr != nil || started.Before(created) {
		return Execution{}, ErrExecutionJournal
	}
	switch execution.State {
	case "applying", "committing":
		if execution.FinishedAt != "" {
			return Execution{}, ErrExecutionJournal
		}
	case "committed":
		finished, err := time.Parse(time.RFC3339Nano, execution.FinishedAt)
		if err != nil || finished.Before(started) {
			return Execution{}, ErrExecutionJournal
		}
	default:
		// Failed rollback/publication is not converted to success. Its original
		// evidence remains fenced for a separate explicit review.
		return Execution{}, ErrExecutionJournal
	}
	return execution, nil
}

func emptyStopAfter(prior, target Plan, original, observed map[string]restorejournal.Image, finished time.Time) (map[string]restorejournal.Image, error) {
	if !NFQWS2OfflineStopPlanScope(prior) || ValidateNFQWS2EmptyStopPlan(target) != nil || prior.PlanID == target.PlanID || finished.IsZero() || len(observed) != 4 {
		return nil, ErrReviewChanged
	}
	committed := target
	committed.State = "committed"
	planRaw, _ := json.MarshalIndent(committed, "", "  ")
	planImage := restorejournal.Image{Exists: true, Data: planRaw}
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json"} {
		before, ok := original[name]
		if !ok || !before.Exists {
			return nil, ErrReviewChanged
		}
		var p Plan
		priorRaw, _ := json.MarshalIndent(prior, "", "  ")
		if json.Unmarshal(before.Data, &p) != nil || !reflect.DeepEqual(p, prior) || !bytes.Equal(priorRaw, before.Data) {
			return nil, ErrReviewChanged
		}
		if !emptyStopImageEqual(observed[name], before) && !emptyStopImageEqual(observed[name], planImage) {
			return nil, ErrReviewChanged
		}
	}
	var selected *Execution
	for _, name := range []string{filepath.Join("transactions", target.PlanID, "execution.json"), "latest-execution.json"} {
		image, ok := observed[name]
		if !ok {
			return nil, ErrReviewChanged
		}
		if name == "latest-execution.json" && emptyStopImageEqual(image, original[name]) {
			continue
		}
		if name != "latest-execution.json" && !image.Exists && len(image.Data) == 0 {
			continue
		}
		execution, err := strictEmptyStopExecution(image, target)
		if err != nil || selected != nil && (selected.StartedAt != execution.StartedAt || selected.State == "committed" && execution.State == "committed" && !reflect.DeepEqual(*selected, execution)) {
			return nil, errors.Join(ErrExecutionJournal, err)
		}
		if selected == nil || execution.State == "committed" {
			selected = &execution
		}
	}
	if selected == nil {
		return nil, ErrExecutionJournal // No actual empty Manager.Apply was entered.
	}
	if selected.State != "committed" {
		selected.State, selected.FinishedAt = "committed", finished.UTC().Format(time.RFC3339Nano)
	}
	executionRaw, _ := json.MarshalIndent(selected, "", "  ")
	executionImage := restorejournal.Image{Exists: true, Data: executionRaw}
	if _, err := strictEmptyStopExecution(executionImage, target); err != nil {
		return nil, err
	}
	return map[string]restorejournal.Image{
		"latest-plan.json": planImage, "latest-committed-plan.json": planImage,
		filepath.Join("transactions", target.PlanID, "execution.json"): executionImage, "latest-execution.json": executionImage,
	}, nil
}

// ValidateNFQWS2EmptyStopPublication validates comparison data only. It never
// reads or writes files and cannot grant native absence or publication rights.
func ValidateNFQWS2EmptyStopPublication(prior, target Plan, original map[string]restorejournal.Image, publication OfflineNFQWS2StopPublication) error {
	if len(publication.Before) != 4 || len(publication.After) != 4 {
		return ErrExecutionJournal
	}
	final, err := strictEmptyStopExecution(publication.After["latest-execution.json"], target)
	if err != nil || final.State != "committed" {
		return ErrExecutionJournal
	}
	finished, _ := time.Parse(time.RFC3339Nano, final.FinishedAt)
	expected, err := emptyStopAfter(prior, target, original, publication.Before, finished)
	if err != nil || !reflect.DeepEqual(expected, publication.After) {
		return ErrReviewChanged
	}
	return nil
}

// ObserveNFQWS2EmptyStopPublication reads the four fixed metadata paths while
// the caller retains its original operation and journal admission. It is safe
// inside Manager.Apply's review guard and therefore takes no operation lock.
func (m *Manager) ObserveNFQWS2EmptyStopPublication(ctx context.Context, prior, target Plan, original map[string]restorejournal.Image, publication *OfflineNFQWS2StopPublication) error {
	if m == nil || !nfqws2InactiveFinite(ctx) || !NFQWS2OfflineStopPlanScope(prior) || ValidateNFQWS2EmptyStopPlan(target) != nil {
		return ErrReviewChanged
	}
	root, err := ownedfs.Open(m.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := checkEmptyStopTransaction(root, target); err != nil {
		return err
	}
	observed := map[string]restorejournal.Image{}
	unchanged := true
	for _, name := range emptyStopNames(target) {
		image, err := readEmptyStopImage(root, name)
		if err != nil {
			return err
		}
		observed[name] = image
		if publication != nil {
			if !emptyStopImageEqual(image, publication.Before[name]) && !emptyStopImageEqual(image, publication.After[name]) {
				return ErrReviewChanged
			}
		} else if name == filepath.Join("transactions", target.PlanID, "execution.json") {
			unchanged = unchanged && !image.Exists && len(image.Data) == 0
		} else {
			unchanged = unchanged && emptyStopImageEqual(image, original[name])
		}
	}
	if publication != nil {
		return ValidateNFQWS2EmptyStopPublication(prior, target, original, *publication)
	}
	if unchanged {
		return ctx.Err()
	}
	_, err = emptyStopAfter(prior, target, original, observed, time.Now())
	return err
}

func checkEmptyStopTransaction(root *ownedfs.Root, target Plan) error {
	name := filepath.Join("transactions", target.PlanID)
	file, err := offlineStopOpenFile(root, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ErrReviewChanged
	}
	if _, err := offlineStopDirectoryIdentity(info); err != nil {
		return ErrReviewChanged
	}
	entries, err := file.ReadDir(2)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 1 || len(entries) == 1 && (entries[0].Name() != "execution.json" || !entries[0].Type().IsRegular()) {
		return ErrReviewChanged
	}
	return nil
}

func (m *Manager) ReviewNFQWS2EmptyStopPublication(ctx context.Context, source *RuntimeInactivitySourceReview, prior, target Plan, original map[string]restorejournal.Image) (OfflineNFQWS2StopPublication, error) {
	if source == nil || source.manager != m {
		return OfflineNFQWS2StopPublication{}, ErrRuntimeInactivity
	}
	return m.reviewNFQWS2EmptyStopPublication(ctx, prior, target, original, source.VerifyNFQWS2Inactive)
}

func (m *Manager) reviewNFQWS2EmptyStopPublication(ctx context.Context, prior, target Plan, original map[string]restorejournal.Image, inactive func(context.Context) error) (OfflineNFQWS2StopPublication, error) {
	if !nfqws2InactiveFinite(ctx) || inactive == nil || ValidateNFQWS2EmptyStopPlan(target) != nil {
		return OfflineNFQWS2StopPublication{}, ErrReviewChanged
	}
	if err := m.beginOperation(ctx); err != nil {
		return OfflineNFQWS2StopPublication{}, err
	}
	defer m.endOperation()
	root, err := ownedfs.Open(m.StateRoot)
	if err != nil {
		return OfflineNFQWS2StopPublication{}, err
	}
	defer root.Close()
	if err := checkEmptyStopTransaction(root, target); err != nil {
		return OfflineNFQWS2StopPublication{}, err
	}
	observed := map[string]restorejournal.Image{}
	for _, name := range emptyStopNames(target) {
		image, err := readEmptyStopImage(root, name)
		if err != nil {
			return OfflineNFQWS2StopPublication{}, err
		}
		observed[name] = image
	}
	if err := inactive(ctx); err != nil {
		return OfflineNFQWS2StopPublication{}, err
	}
	after, err := emptyStopAfter(prior, target, original, observed, time.Now())
	if err != nil {
		return OfflineNFQWS2StopPublication{}, err
	}
	for _, name := range emptyStopNames(target) {
		current, err := readEmptyStopImage(root, name)
		if err != nil || !emptyStopImageEqual(current, observed[name]) {
			return OfflineNFQWS2StopPublication{}, ErrReviewChanged
		}
	}
	return OfflineNFQWS2StopPublication{Before: observed, After: after}, ctx.Err()
}

// CompleteNFQWS2EmptyStopPublication never calls an adapter, restores a prior
// plan or acknowledges a native effect. It only finishes this recorded empty
// transaction's four metadata files. The surrounding durable Stop intent is
// still required until the Store's exact stopped image is read back.
func (m *Manager) CompleteNFQWS2EmptyStopPublication(ctx context.Context, source *RuntimeInactivitySourceReview, prior, target Plan, original map[string]restorejournal.Image, publication OfflineNFQWS2StopPublication) error {
	if source == nil || source.manager != m {
		return ErrRuntimeInactivity
	}
	return m.completeNFQWS2EmptyStopPublication(ctx, prior, target, original, publication, source.VerifyNFQWS2Inactive)
}

func (m *Manager) completeNFQWS2EmptyStopPublication(ctx context.Context, prior, target Plan, original map[string]restorejournal.Image, publication OfflineNFQWS2StopPublication, inactive func(context.Context) error) error {
	if ctx == nil {
		return ErrReviewChanged
	}
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if !nfqws2InactiveFinite(ctx) || guard == nil || inactive == nil || len(publication.After) != 4 {
		return ErrReviewChanged
	}
	if err := ValidateNFQWS2EmptyStopPublication(prior, target, original, publication); err != nil {
		return err
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	root, err := ownedfs.Open(m.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	transaction, err := ownedfs.Open(filepath.Join(m.StateRoot, "transactions", target.PlanID))
	if err != nil {
		return err
	}
	defer transaction.Close()
	transactionInfo, err := transaction.RootInfo()
	if err != nil {
		return err
	}
	info, err := root.RootInfo()
	if err != nil {
		return err
	}
	check := func() error {
		if err := guard(ctx); err != nil {
			return err
		}
		current, err := os.Lstat(m.StateRoot)
		targetInfo, targetErr := root.Stat(filepath.Join("transactions", target.PlanID))
		if err != nil || targetErr != nil || !os.SameFile(info, current) || !os.SameFile(transactionInfo, targetInfo) || checkEmptyStopTransaction(root, target) != nil {
			return ErrReviewChanged
		}
		for _, name := range emptyStopNames(target) {
			actual, err := readEmptyStopImage(root, name)
			if err != nil || !emptyStopImageEqual(actual, publication.Before[name]) && !emptyStopImageEqual(actual, publication.After[name]) {
				return ErrReviewChanged
			}
		}
		return inactive(ctx)
	}
	if err := check(); err != nil {
		return err
	}
	for _, name := range emptyStopNames(target) {
		if err := check(); err != nil {
			return err
		}
		actual, err := readEmptyStopImage(root, name)
		if err != nil {
			return err
		}
		if emptyStopImageEqual(actual, publication.After[name]) {
			continue
		}
		parent, leaf := root, name
		if filepath.Dir(name) != "." {
			parent, leaf = transaction, filepath.Base(name)
		}
		if err := parent.WriteAtomic(leaf, publication.After[name].Data, 0600); err != nil {
			return executionJournalError(err)
		}
		if err := parent.Sync(); err != nil {
			return executionJournalError(err)
		}
	}
	// A previous rename may have become visible before its directory fsync
	// failed. Re-establish durability even for entries already equal to After.
	for _, name := range emptyStopNames(target) {
		parent, leaf := root, name
		if filepath.Dir(name) != "." {
			parent, leaf = transaction, filepath.Base(name)
		}
		file, err := offlineStopOpenFile(parent, leaf)
		if err != nil {
			return executionJournalError(err)
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return executionJournalError(err)
		}
	}
	if err := errors.Join(transaction.Sync(), root.Sync()); err != nil {
		return executionJournalError(err)
	}
	if err := check(); err != nil {
		return err
	}
	return m.checkExecutionRecovery()
}
