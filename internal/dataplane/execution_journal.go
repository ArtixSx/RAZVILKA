package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// CheckExecutionRecovery only observes retained transaction records. Recovery
// panels and installer authority may consult it before opening normal runtime.
// It never settles a publication, changes networking or writes a journal.
func (m *Manager) CheckExecutionRecovery(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil {
		return ErrExecutionJournal
	}
	if err := m.checkExecutionRecovery(); err != nil {
		return err
	}
	return ctx.Err()
}

// ErrExecutionJournal means that a transaction's durable outcome cannot be
// trusted. Callers must stop subsequent mutations even if live cleanup worked.
var ErrExecutionJournal = errors.New("dataplane transaction journal is unavailable")

func executionJournalError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrExecutionJournal, err)
}

// checkExecutionRecovery is read-only. Restart must not erase an unfinished
// rollback fence. The two independently published records must agree before
// the old committed runtime may be reconciled or a new candidate may start.
func (m *Manager) checkExecutionRecovery() error {
	var latest *Execution
	exists, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest)
	if err != nil {
		return executionJournalError(err)
	}
	if !exists {
		return nil
	} // Legacy state without transaction journals.
	if latest == nil || latest.PlanID == "" || !filepath.IsLocal(latest.PlanID) || filepath.Base(latest.PlanID) != latest.PlanID || strings.ContainsAny(latest.PlanID, "/\\:") || latest.Digest == "" || latest.FinishedAt == "" {
		return executionJournalError(errors.New("unfinished or invalid execution record"))
	}
	switch latest.State {
	case "committed", "rolled-back", "canary-failed", "network-stale", "temporary-complete":
	default:
		return executionJournalError(errors.New("previous execution requires recovery"))
	}
	if err := validateExecutionResources(*latest, true); err != nil {
		return executionJournalError(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, latest.FinishedAt); err != nil {
		return executionJournalError(errors.New("invalid execution finish time"))
	}
	for _, step := range latest.Steps {
		if (step.State != "passed" && step.State != "failed") || step.FinishedAt == "" || (latest.State == "committed" && step.State != "passed") {
			return executionJournalError(errors.New("unfinished execution step"))
		}
	}
	var transaction *Execution
	exists, err = readOptionalJournal(filepath.Join(m.StateRoot, "transactions", latest.PlanID, "execution.json"), &transaction)
	if err != nil {
		return executionJournalError(err)
	}
	if !exists || !reflect.DeepEqual(latest, transaction) {
		return executionJournalError(errors.New("execution records disagree; recovery is required"))
	}
	if err := m.checkRetainedNFQWSRecord(*latest); err != nil {
		return executionJournalError(err)
	}
	if err := m.checkRetainedXrayRecord(*latest); err != nil {
		return executionJournalError(err)
	}
	return nil
}

// settleCommittedPublication completes the one provable interruption of a
// commit. finishCommit writes "committing" to both execution records, then
// publishes the committed plan (latest and boot copies), then writes
// "committed" to the transaction record and to the latest record. If power is
// lost after the plan publication, every adapter step has passed and both plan
// files name this execution's plan as committed: only the final records are
// missing, so they are completed. Anything else (plan not published or only
// partly, a failed or unfinished step, records of different executions) stays
// fenced for review. It reports whether the records were completed.
func (m *Manager) settleCommittedPublication() (bool, error) {
	var latest, transaction *Execution
	exists, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest)
	if err != nil || !exists || latest == nil || latest.State != "committing" || !validExecutionPlanID(latest.PlanID) {
		return false, nil
	}
	exists, err = readOptionalJournal(filepath.Join(m.StateRoot, "transactions", latest.PlanID, "execution.json"), &transaction)
	if err != nil || !exists || transaction == nil || transaction.PlanID != latest.PlanID || transaction.Digest != latest.Digest || transaction.StartedAt != latest.StartedAt || latest.Digest == "" {
		return false, nil
	}
	if !reflect.DeepEqual(transaction.Steps, latest.Steps) || !reflect.DeepEqual(transaction.Resources, latest.Resources) || transaction.ResourcePlanID != latest.ResourcePlanID || len(latest.Steps) == 0 {
		return false, nil
	}
	if validateExecutionResources(*latest, true) != nil || validateExecutionResources(*transaction, true) != nil {
		return false, nil
	}
	// A documentary ACTIVE row cannot reconstruct the original live owner.
	if m.checkRetainedNFQWSRecord(*latest) != nil || m.checkRetainedXrayRecord(*latest) != nil {
		return false, nil
	}
	for _, step := range latest.Steps {
		if step.State != "passed" || step.FinishedAt == "" {
			return false, nil
		}
	}
	settled := *latest
	switch transaction.State {
	case "committing":
		settled.State, settled.FinishedAt = "committed", time.Now().UTC().Format(time.RFC3339Nano)
	case "committed":
		if _, err := time.Parse(time.RFC3339Nano, transaction.FinishedAt); err != nil {
			return false, nil
		}
		settled = *transaction
	default:
		return false, nil
	}
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json"} {
		plan, found, err := readPlanJournal(filepath.Join(m.StateRoot, name))
		if err != nil || !found || plan.State != "committed" || plan.PlanID != latest.PlanID || plan.Digest != latest.Digest {
			return false, nil
		}
	}
	if err := m.writeExecution(filepath.Join(m.StateRoot, "transactions", latest.PlanID), settled); err != nil {
		return false, err
	}
	return true, nil
}

func validExecutionPlanID(id string) bool {
	return id != "" && filepath.IsLocal(id) && filepath.Base(id) == id && !strings.ContainsAny(id, "/\\:")
}

func (m *Manager) writeExecution(root string, execution Execution) error {
	return m.writeExecutionOwned(root, execution, nil)
}

// scope is the actual original issuer passed by the serialized Manager
// operation or scope.persist. A decoded resource never locates this receiver.
func (m *Manager) writeExecutionOwned(root string, execution Execution, scope *executionResourceScope) error {
	if scope != nil && (scope.manager != m || scope.root != root || scope.managerRoot != m.StateRoot || scope.execution == nil || scope.execution.PlanID != execution.PlanID || scope.execution.Digest != execution.Digest) {
		return executionJournalError(ErrExecutionJournal)
	}
	terminal := execution.State == "committed" || execution.State == "committing" || execution.State == "rolled-back" || execution.State == "canary-failed" || execution.State == "network-stale" || execution.State == "temporary-complete"
	if err := validateExecutionResources(execution, terminal); err != nil {
		return executionJournalError(err)
	}
	// Typed network identities have a canonical compact wire form. Indenting
	// their embedded object would produce a journal their decoder must refuse.
	var data []byte
	var err error
	if executionHasNetworkIdentity(execution) {
		data, err = json.Marshal(execution)
	} else {
		data, err = json.MarshalIndent(execution, "", "  ")
	}
	if err != nil {
		return executionJournalError(err)
	}
	m.retainedXrayMu.Lock()
	pair := m.replacementXray
	m.retainedXrayMu.Unlock()
	if pair != nil && pair.self == pair && pair.prior != nil && !pair.closed.Load() && scope != nil && (scope == pair.scope || scope == pair.prior.scope) {
		return executionJournalError(pair.publish(scope, data))
	}
	if scope != nil && len(scope.xraySelectedTCP) != 0 {
		if len(scope.xraySelectedTCP) != 1 {
			return executionJournalError(ErrExecutionJournal)
		}
		for _, resource := range scope.xraySelectedTCP {
			if resource == nil || resource.records == nil {
				return executionJournalError(ErrExecutionJournal)
			}
			if err := resource.records.beforePublication(); err != nil {
				return executionJournalError(err)
			}
		}
		publish := func(index int, path string) error {
			file, err := writeDataplaneJournalRetained(path, data)
			if err != nil {
				return err
			}
			info, err := file.Stat()
			if err == nil {
				err = scope.captureOriginalXrayExecutionRecord(index, file, info, data)
			}
			if err != nil {
				return errors.Join(err, file.Close())
			}
			return nil // Original sink accepted ownership of this writer's FD.
		}
		transactionErr := publish(0, filepath.Join(root, "execution.json"))
		latestErr := publish(1, filepath.Join(m.StateRoot, "latest-execution.json"))
		return executionJournalError(errors.Join(transactionErr, latestErr))
	}
	if scope != nil && scope.wgOwner != nil {
		if scope.wgRecords == nil || scope.wgRecords.scope != scope {
			return executionJournalError(ErrExecutionJournal)
		}
		if err := scope.wgRecords.beforePublication(); err != nil {
			return executionJournalError(err)
		}
		return executionJournalError(errors.Join(scope.wgRecords.publishOriginal(0, data), scope.wgRecords.publishOriginal(1, data)))
	}
	// Attempt both records, including during cleanup. A successful UI record
	// cannot compensate for a missing transaction record (or vice versa).
	transactionErr := writeDataplaneJournal(filepath.Join(root, "execution.json"), data)
	latestErr := writeDataplaneJournal(filepath.Join(m.StateRoot, "latest-execution.json"), data)
	return executionJournalError(errors.Join(transactionErr, latestErr))
}

func executionHasNetworkIdentity(execution Execution) bool {
	for _, resource := range execution.Resources {
		if resource.XraySelectedTCP != nil {
			return true
		}
		if resource.NFQWS != nil && (resource.NFQWS.NetworkIdentity != nil || resource.NFQWS.Spec.NetworkIdentity != nil) {
			return true
		}
	}
	return false
}

// preserveCommittedJournal keeps the previous boot recovery source before
// latest-plan can be replaced. This also promotes the pre-v0.15 journal format.
// The returned restoration is used only after an attempted commit publication;
// writes may have reached rename before reporting an error.
func (m *Manager) preserveCommittedJournal() (func() error, error) {
	m.journalMu.Lock()
	defer m.journalMu.Unlock()
	path := filepath.Join(m.StateRoot, "latest-committed-plan.json")
	data, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, executionJournalError(err)
	}
	if exists {
		if plan, _, err := readPlanJournal(path); err != nil || plan.State != "committed" {
			return nil, executionJournalError(errors.Join(err, errors.New("invalid committed recovery source")))
		}
	} else {
		plan, found, err := readPlanJournal(filepath.Join(m.StateRoot, "latest-plan.json"))
		if err != nil {
			return nil, executionJournalError(err)
		}
		if found && plan.State == "committed" {
			data, err = json.MarshalIndent(plan, "", "  ")
			if err == nil {
				err = writeDataplaneJournal(path, data)
			}
			if err != nil {
				return nil, executionJournalError(err)
			}
			exists = true
		}
	}
	return func() error {
		m.journalMu.Lock()
		defer m.journalMu.Unlock()
		if exists {
			return executionJournalError(writeDataplaneJournal(path, data))
		}
		root, err := openJournalDirectory(filepath.Dir(path))
		if err != nil {
			return executionJournalError(err)
		}
		defer root.Close()
		if err := root.Remove(filepath.Base(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return executionJournalError(err)
		}
		return executionJournalError(syncDataplaneJournalDirectory(root))
	}, nil
}

func openJournalDirectory(path string) (*ownedfs.Root, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return ownedfs.Open(absolute)
}

func writeDataplaneJournal(path string, data []byte) error {
	root, err := openJournalDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.WriteAtomic(filepath.Base(path), data, 0o600); err != nil {
		return err
	}
	// A renamed file without a synced directory is not a durable commit on
	// the router. Failure here is uncertain publication and requires rollback.
	return syncDataplaneJournalDirectory(root)
}

func writeDataplaneJournalRetained(path string, data []byte) (*os.File, error) {
	root, err := openJournalDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.WriteAtomicRetained(filepath.Base(path), data, 0600)
	if err != nil {
		return nil, err
	}
	if err := syncDataplaneJournalDirectory(root); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (m *Manager) prepareExecutionRoot(transactionRoot string) error {
	if err := os.MkdirAll(transactionRoot, 0o700); err != nil {
		return executionJournalError(err)
	}
	// Flush newly created transaction and state entries from child to parent
	// before any adapter may mutate the network.
	for _, path := range []string{transactionRoot, filepath.Dir(transactionRoot), m.StateRoot, filepath.Dir(m.StateRoot)} {
		root, err := openJournalDirectory(path)
		if err != nil {
			return executionJournalError(err)
		}
		err = syncDataplaneJournalDirectory(root)
		_ = root.Close()
		if err != nil {
			return executionJournalError(err)
		}
	}
	return nil
}

// retireSettledAttempt moves out what a settled, failed earlier attempt of the
// same plan left in its transaction root. Plan IDs follow the plan content, so
// an identical retry (the autopilot's next round) reuses the root, and adapters
// refuse to stage over the earlier attempt's receipts. Only attempts that ended
// with every effect undone or never started are moved, to a sibling .retired
// directory nothing reads; execution.json stays until the new attempt replaces
// it, so the latest journal keeps a readable record.
func (m *Manager) retireSettledAttempt(transactionRoot string) error {
	var previous *Execution
	exists, err := readOptionalJournal(filepath.Join(transactionRoot, "execution.json"), &previous)
	if err != nil || !exists || previous == nil {
		return nil // Unknown content stays for the adapters' own refusal.
	}
	switch previous.State {
	case "rolled-back", "canary-failed", "network-stale", "rejected", "cancelled":
	default:
		return nil
	}
	entries, err := os.ReadDir(transactionRoot)
	if err != nil {
		return executionJournalError(err)
	}
	retired := filepath.Join(filepath.Dir(transactionRoot), ".retired", fmt.Sprintf("%s-%d", filepath.Base(transactionRoot), time.Now().UnixNano()))
	moved := false
	for _, entry := range entries {
		if entry.Name() == "execution.json" {
			continue
		}
		if !moved {
			if err := os.MkdirAll(retired, 0o700); err != nil {
				return executionJournalError(err)
			}
			moved = true
		}
		if err := os.Rename(filepath.Join(transactionRoot, entry.Name()), filepath.Join(retired, entry.Name())); err != nil {
			return executionJournalError(err)
		}
	}
	if !moved {
		return nil
	}
	for _, path := range []string{transactionRoot, retired, filepath.Dir(retired)} {
		root, err := openJournalDirectory(path)
		if err != nil {
			return executionJournalError(err)
		}
		err = syncDataplaneJournalDirectory(root)
		_ = root.Close()
		if err != nil {
			return executionJournalError(err)
		}
	}
	return nil
}
