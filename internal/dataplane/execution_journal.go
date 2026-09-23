package dataplane

import (
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
	case "committed", "rolled-back", "canary-failed", "network-stale":
	default:
		return executionJournalError(errors.New("previous execution requires recovery"))
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
	return nil
}

func (m *Manager) writeExecution(root string, execution Execution) error {
	data, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		return executionJournalError(err)
	}
	// Attempt both records, including during cleanup. A successful UI record
	// cannot compensate for a missing transaction record (or vice versa).
	transactionErr := writeDataplaneJournal(filepath.Join(root, "execution.json"), data)
	latestErr := writeDataplaneJournal(filepath.Join(m.StateRoot, "latest-execution.json"), data)
	return executionJournalError(errors.Join(transactionErr, latestErr))
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
