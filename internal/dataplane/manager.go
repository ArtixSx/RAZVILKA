package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Manager struct {
	operationMu sync.Mutex
	journalMu   sync.RWMutex
	registryMu  sync.RWMutex
	StateRoot   string
	Adapters    map[string]Adapter
}

type Adapter interface {
	ID() string
	Snapshot(context.Context, Plan, string) error
	Stage(context.Context, Plan, string) error
	Validate(context.Context, Plan, string) error
	Activate(context.Context, Plan, string) error
	Health(context.Context, Plan, string) error
	Commit(context.Context, Plan, string) error
	Rollback(context.Context, Plan, string) error
}

type RuntimeReconciler interface {
	Reconcile(context.Context, Plan) error
}

type PolicyRefresher interface {
	RefreshPolicy(context.Context, Plan) (bool, error)
}

type RuntimeDeactivator interface {
	Deactivate(context.Context) error
}

type DeactivationStep struct {
	Adapter string `json:"adapter"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
}

type Deactivation struct {
	State      string             `json:"state"`
	StartedAt  string             `json:"started_at"`
	FinishedAt string             `json:"finished_at"`
	Steps      []DeactivationStep `json:"steps"`
}

type RecoveryStep struct {
	Adapter string `json:"adapter"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
}

type Recovery struct {
	PlanID     string         `json:"plan_id,omitempty"`
	State      string         `json:"state"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	Steps      []RecoveryStep `json:"steps"`
}

type ExecutionStep struct {
	Adapter    string `json:"adapter"`
	Phase      string `json:"phase"`
	State      string `json:"state"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type Execution struct {
	PlanID     string          `json:"plan_id"`
	Digest     string          `json:"digest"`
	State      string          `json:"state"`
	StartedAt  string          `json:"started_at"`
	FinishedAt string          `json:"finished_at,omitempty"`
	Steps      []ExecutionStep `json:"steps"`
	Error      string          `json:"error,omitempty"`
}

type PolicyRefresh struct {
	PlanID    string          `json:"plan_id,omitempty"`
	CheckedAt string          `json:"checked_at,omitempty"`
	Changed   map[string]bool `json:"changed,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// RuntimeStatus is a non-blocking view of the atomic dataplane journals. It
// deliberately reads immutable snapshots instead of waiting for a long Apply
// transaction, so the UI remains useful while health checks are running.
type RuntimeStatus struct {
	Exists        bool           `json:"exists"`
	Plan          *Plan          `json:"plan,omitempty"`
	Execution     *Execution     `json:"execution,omitempty"`
	Recovery      *Recovery      `json:"recovery,omitempty"`
	PolicyRefresh *PolicyRefresh `json:"policy_refresh,omitempty"`
	Deactivation  *Deactivation  `json:"deactivation,omitempty"`
}

func New(stateRoot string) *Manager {
	return &Manager{StateRoot: stateRoot, Adapters: map[string]Adapter{}}
}

func (m *Manager) Register(adapter Adapter) error {
	if m == nil || adapter == nil || adapter.ID() == "" {
		return errors.New("dataplane adapter id is required")
	}
	m.registryMu.Lock()
	defer m.registryMu.Unlock()
	if m.Adapters == nil {
		m.Adapters = map[string]Adapter{}
	}
	if _, exists := m.Adapters[adapter.ID()]; exists {
		return fmt.Errorf("dataplane adapter %q is already registered", adapter.ID())
	}
	m.Adapters[adapter.ID()] = adapter
	return nil
}

func (m *Manager) Capable(id string) bool {
	if m == nil {
		return false
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	_, ok := m.Adapters[id]
	return ok
}

func (m *Manager) adapter(id string) (Adapter, bool) {
	if m == nil {
		return nil, false
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	adapter, ok := m.Adapters[id]
	return adapter, ok
}

func (m *Manager) Record(plan Plan) error {
	if m == nil || m.StateRoot == "" {
		return errors.New("dataplane state root is not configured")
	}
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	return m.recordLocked(plan)
}

func (m *Manager) recordLocked(plan Plan) error {
	m.journalMu.Lock()
	defer m.journalMu.Unlock()
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("encode dataplane plan: %w", err)
	}
	if err := os.MkdirAll(m.StateRoot, 0o700); err != nil {
		return fmt.Errorf("create dataplane state: %w", err)
	}
	return writeAtomic(filepath.Join(m.StateRoot, "latest-plan.json"), data, 0o600)
}

func (m *Manager) Latest() (Plan, bool, error) {
	if m == nil || m.StateRoot == "" {
		return Plan{}, false, nil
	}
	return m.latestLocked()
}

func (m *Manager) Status() (RuntimeStatus, error) {
	if m == nil || m.StateRoot == "" {
		return RuntimeStatus{}, nil
	}
	status := RuntimeStatus{}
	plan, exists, err := m.Latest()
	if err != nil {
		return status, err
	}
	status.Exists = exists
	if exists {
		status.Plan = &plan
	}
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &status.Execution); err != nil {
		return status, err
	} else if !found {
		status.Execution = nil
	}
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-recovery.json"), &status.Recovery); err != nil {
		return status, err
	} else if !found {
		status.Recovery = nil
	}
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-policy-refresh.json"), &status.PolicyRefresh); err != nil {
		return status, err
	} else if !found {
		status.PolicyRefresh = nil
	}
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-deactivation.json"), &status.Deactivation); err != nil {
		return status, err
	} else if !found {
		status.Deactivation = nil
	}
	return status, nil
}

func readOptionalJournal[T any](path string, target **T) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read dataplane journal %s: %w", filepath.Base(path), err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return false, fmt.Errorf("decode dataplane journal %s: %w", filepath.Base(path), err)
	}
	*target = &value
	return true, nil
}

func (m *Manager) latestLocked() (Plan, bool, error) {
	m.journalMu.RLock()
	defer m.journalMu.RUnlock()
	data, err := os.ReadFile(filepath.Join(m.StateRoot, "latest-plan.json"))
	if errors.Is(err, os.ErrNotExist) {
		return Plan{}, false, nil
	}
	if err != nil {
		return Plan{}, false, fmt.Errorf("read dataplane plan: %w", err)
	}
	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return Plan{}, false, fmt.Errorf("decode dataplane plan: %w", err)
	}
	if plan.SchemaVersion != SchemaVersion || plan.PlanID == "" || plan.Digest == "" {
		return Plan{}, false, errors.New("invalid dataplane plan journal")
	}
	return plan, true, nil
}

// Recover restores only a previously committed RAZVILKA-owned dataplane after
// reboot. It never builds a new plan and never acts on reviewed, blocked or
// rolled-back journals.
func (m *Manager) Recover(ctx context.Context) (Recovery, error) {
	if m == nil || m.StateRoot == "" {
		return Recovery{}, errors.New("dataplane state root is not configured")
	}
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	recovery := Recovery{State: "skipped", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []RecoveryStep{}}
	plan, exists, err := m.latestLocked()
	if err != nil {
		return recovery, err
	}
	if !exists || plan.State != "committed" || plan.SafeMode || plan.Noop {
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = m.writeRecoveryLocked(recovery)
		return recovery, nil
	}
	recovery.PlanID = plan.PlanID
	recovery.State = "recovering"
	var firstErr error
	for _, id := range plan.Adapters {
		step := RecoveryStep{Adapter: id, State: "failed"}
		adapter, ok := m.adapter(id)
		if !ok {
			step.Detail = "adapter is not registered"
		} else if reconciler, ok := adapter.(RuntimeReconciler); !ok {
			step.Detail = "adapter does not support boot recovery"
		} else if err := reconciler.Reconcile(ctx, plan); err != nil {
			step.Detail = err.Error()
		} else {
			step.State = "recovered"
		}
		if step.State == "failed" && firstErr == nil {
			firstErr = fmt.Errorf("recover %s: %s", id, step.Detail)
		}
		recovery.Steps = append(recovery.Steps, step)
	}
	recovery.State = "recovered"
	if firstErr != nil {
		recovery.State = "degraded"
	}
	recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.writeRecoveryLocked(recovery); err != nil && firstErr == nil {
		firstErr = err
	}
	return recovery, firstErr
}

func (m *Manager) writeRecoveryLocked(recovery Recovery) error {
	if err := os.MkdirAll(m.StateRoot, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(recovery, "", "  ")
	return writeAtomic(filepath.Join(m.StateRoot, "latest-recovery.json"), data, 0o600)
}

func (m *Manager) RefreshCommitted(ctx context.Context) (map[string]bool, error) {
	if m == nil || m.StateRoot == "" {
		return nil, errors.New("dataplane state root is not configured")
	}
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	plan, exists, err := m.latestLocked()
	if err != nil {
		return nil, err
	}
	if !exists || plan.State != "committed" || plan.SafeMode || plan.Noop {
		return map[string]bool{}, nil
	}
	changed := map[string]bool{}
	var firstErr error
	for _, id := range plan.Adapters {
		adapter, ok := m.adapter(id)
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("refresh %s policy: adapter is not registered", id)
			}
			continue
		}
		refresher, ok := adapter.(PolicyRefresher)
		if !ok {
			continue
		}
		updated, err := refresher.RefreshPolicy(ctx, plan)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("refresh %s policy: %w", id, err)
			}
			continue
		}
		changed[id] = updated
	}
	report := map[string]any{"plan_id": plan.PlanID, "checked_at": time.Now().UTC().Format(time.RFC3339Nano), "changed": changed}
	if firstErr != nil {
		report["error"] = firstErr.Error()
	}
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := writeAtomic(filepath.Join(m.StateRoot, "latest-policy-refresh.json"), data, 0o600); err != nil && firstErr == nil {
		firstErr = err
	}
	return changed, firstErr
}

// Deactivate removes only runtime objects explicitly owned by registered
// adapters. It is used by uninstall/rollback and leaves desired configuration
// available for a later reinstall.
func (m *Manager) Deactivate(ctx context.Context) (Deactivation, error) {
	if m == nil || m.StateRoot == "" {
		return Deactivation{}, errors.New("dataplane state root is not configured")
	}
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	report := Deactivation{State: "deactivated", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []DeactivationStep{}}
	m.registryMu.RLock()
	ids := make([]string, 0, len(m.Adapters))
	for id := range m.Adapters {
		ids = append(ids, id)
	}
	m.registryMu.RUnlock()
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	var firstErr error
	for _, id := range ids {
		adapter, _ := m.adapter(id)
		step := DeactivationStep{Adapter: id, State: "skipped", Detail: "adapter has no owned-runtime deactivator"}
		if deactivator, ok := adapter.(RuntimeDeactivator); ok {
			step.State, step.Detail = "deactivated", ""
			if err := deactivator.Deactivate(ctx); err != nil {
				step.State, step.Detail = "failed", err.Error()
				if firstErr == nil {
					firstErr = fmt.Errorf("deactivate %s: %w", id, err)
				}
			}
		}
		report.Steps = append(report.Steps, step)
	}
	if firstErr != nil {
		report.State = "degraded"
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.MkdirAll(m.StateRoot, 0o700); err == nil {
		data, _ := json.MarshalIndent(report, "", "  ")
		if writeErr := writeAtomic(filepath.Join(m.StateRoot, "latest-deactivation.json"), data, 0o600); writeErr != nil && firstErr == nil {
			firstErr = writeErr
		}
	} else if firstErr == nil {
		firstErr = err
	}
	return report, firstErr
}

// Apply runs every adapter under a single transaction lock. The configuration
// commit callback executes only after all live health checks pass. Any failure,
// including a failed config commit, rolls prepared adapters back in reverse
// order before returning.
func (m *Manager) Apply(ctx context.Context, plan Plan, commit func() (func() error, error)) (Execution, error) {
	if m == nil || m.StateRoot == "" {
		return Execution{}, errors.New("dataplane state root is not configured")
	}
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []ExecutionStep{}}
	if plan.SchemaVersion != SchemaVersion || plan.PlanID == "" || plan.Digest == "" {
		return execution, errors.New("invalid dataplane plan")
	}
	if plan.SafeMode {
		return execution, errors.New("Safe Mode blocks dataplane execution")
	}
	if !plan.Ready {
		return execution, errors.New("dataplane plan is blocked")
	}
	if err := os.MkdirAll(m.StateRoot, 0o700); err != nil {
		return execution, err
	}
	transactionRoot := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
	if err := os.MkdirAll(transactionRoot, 0o700); err != nil {
		return execution, fmt.Errorf("create dataplane transaction: %w", err)
	}
	writeExecution := func() {
		data, _ := json.MarshalIndent(execution, "", "  ")
		_ = writeAtomic(filepath.Join(transactionRoot, "execution.json"), data, 0o600)
		_ = writeAtomic(filepath.Join(m.StateRoot, "latest-execution.json"), data, 0o600)
	}
	writeExecution()

	prepared := make([]Adapter, 0, len(plan.Adapters))
	var undoCommit func() error
	run := func(adapter Adapter, phase string, action func(context.Context, Plan, string) error) error {
		step := ExecutionStep{Adapter: adapter.ID(), Phase: phase, State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		execution.Steps = append(execution.Steps, step)
		index := len(execution.Steps) - 1
		writeExecution()
		adapterRoot := filepath.Join(transactionRoot, adapter.ID())
		if err := os.MkdirAll(adapterRoot, 0o700); err != nil {
			execution.Steps[index].State = "failed"
			execution.Steps[index].Detail = err.Error()
			execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			writeExecution()
			return err
		}
		err := action(ctx, plan, adapterRoot)
		execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err != nil {
			execution.Steps[index].State = "failed"
			execution.Steps[index].Detail = err.Error()
		} else {
			execution.Steps[index].State = "passed"
		}
		writeExecution()
		return err
	}
	rollback := func(cause error) error {
		execution.Error = cause.Error()
		execution.State = "rolling-back"
		writeExecution()
		var rollbackErr error
		for i := len(prepared) - 1; i >= 0; i-- {
			adapter := prepared[i]
			if err := run(adapter, "rollback", adapter.Rollback); err != nil && rollbackErr == nil {
				rollbackErr = err
			}
		}
		if undoCommit != nil {
			if err := undoCommit(); err != nil && rollbackErr == nil {
				rollbackErr = fmt.Errorf("restore desired state: %w", err)
			}
		}
		plan.Ready = false
		plan.State = "rolled-back"
		execution.State = "rolled-back"
		if rollbackErr != nil {
			plan.State = "rollback-failed"
			execution.State = "rollback-failed"
			execution.Error += "; rollback: " + rollbackErr.Error()
		}
		plan.Note = execution.Error
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = m.recordLocked(plan)
		writeExecution()
		if rollbackErr != nil {
			return fmt.Errorf("%w; rollback failed: %v", cause, rollbackErr)
		}
		return cause
	}

	if plan.Noop {
		if commit != nil {
			var err error
			undoCommit, err = commit()
			if err != nil {
				return execution, rollback(err)
			}
		}
		plan.State = "committed"
		execution.State = "committed"
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := m.recordLocked(plan); err != nil {
			return execution, err
		}
		writeExecution()
		return execution, nil
	}

	adapters := make([]Adapter, 0, len(plan.Adapters))
	for _, id := range plan.Adapters {
		adapter, ok := m.adapter(id)
		if !ok {
			return execution, rollback(fmt.Errorf("adapter %s is not registered", id))
		}
		adapters = append(adapters, adapter)
	}
	for _, adapter := range adapters {
		if err := run(adapter, "snapshot", adapter.Snapshot); err != nil {
			return execution, rollback(err)
		}
		prepared = append(prepared, adapter)
	}
	for _, phase := range []struct {
		name string
		call func(Adapter) func(context.Context, Plan, string) error
	}{
		{name: "stage", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Stage }},
		{name: "validate", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Validate }},
		{name: "activate", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Activate }},
		{name: "health", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Health }},
		{name: "commit-adapter", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Commit }},
	} {
		for _, adapter := range adapters {
			if err := run(adapter, phase.name, phase.call(adapter)); err != nil {
				return execution, rollback(err)
			}
		}
	}
	if commit != nil {
		var err error
		undoCommit, err = commit()
		if err != nil {
			return execution, rollback(fmt.Errorf("commit desired state: %w", err))
		}
	}
	plan.State = "committed"
	plan.Note = "Dataplane adapters activated, health-checked and committed."
	execution.State = "committed"
	execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.recordLocked(plan); err != nil {
		return execution, rollback(fmt.Errorf("commit dataplane journal: %w", err))
	}
	writeExecution()
	return execution, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".latest-plan.tmp-*")
	if err != nil {
		return fmt.Errorf("create dataplane transaction: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("protect dataplane transaction: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write dataplane transaction: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync dataplane transaction: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close dataplane transaction: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit dataplane transaction: %w", err)
	}
	return nil
}
