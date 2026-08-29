package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

type Manager struct {
	operationOnce   sync.Once
	operationGate   chan struct{}
	journalMu       sync.RWMutex
	registryMu      sync.RWMutex
	StateRoot       string
	Adapters        map[string]Adapter
	RollbackTimeout time.Duration
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

// CanaryAdapter can validate a staged candidate through an isolated path
// before Activate replaces a working process, interface, list or policy.
// Implementations receive a RoutePlan scoped to their own adapter only.
type CanaryAdapter interface {
	Canary(context.Context, RoutePlan, string) error
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
	PlanID       string         `json:"plan_id,omitempty"`
	State        string         `json:"state"`
	FailureCount int            `json:"failure_count,omitempty"`
	Guarded      bool           `json:"boot_loop_guard,omitempty"`
	StartedAt    string         `json:"started_at"`
	FinishedAt   string         `json:"finished_at"`
	Steps        []RecoveryStep `json:"steps"`
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
	CommittedPlan *Plan          `json:"committed_plan,omitempty"`
	Execution     *Execution     `json:"execution,omitempty"`
	Recovery      *Recovery      `json:"recovery,omitempty"`
	PolicyRefresh *PolicyRefresh `json:"policy_refresh,omitempty"`
	Deactivation  *Deactivation  `json:"deactivation,omitempty"`
}

func New(stateRoot string) *Manager {
	return &Manager{StateRoot: stateRoot, Adapters: map[string]Adapter{}, operationGate: make(chan struct{}, 1), RollbackTimeout: 45 * time.Second}
}

func (m *Manager) beginOperation(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.operationOnce.Do(func() {
		if m.operationGate == nil {
			m.operationGate = make(chan struct{}, 1)
		}
	})
	select {
	case m.operationGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for conflicting dataplane operation: %w", ctx.Err())
	}
}

func (m *Manager) endOperation() {
	if m != nil && m.operationGate != nil {
		<-m.operationGate
	}
}

func (m *Manager) rollbackTimeout() time.Duration {
	if m != nil && m.RollbackTimeout > 0 {
		return m.RollbackTimeout
	}
	return 45 * time.Second
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

func (m *Manager) CanaryCapable(id string) bool {
	adapter, ok := m.adapter(id)
	if !ok {
		return false
	}
	_, ok = adapter.(CanaryAdapter)
	return ok
}

// ProbeCandidate runs the non-live half of a transaction for one adapter:
// snapshot, stage, validate and isolated canary. It never calls Activate,
// Commit or Rollback because the CanaryAdapter contract must leave live state
// untouched and clean only its temporary resources.
func (m *Manager) ProbeCandidate(ctx context.Context, plan Plan, adapterID string) error {
	if m == nil || m.StateRoot == "" {
		return errors.New("dataplane state root is not configured")
	}
	adapter, ok := m.adapter(adapterID)
	if !ok {
		return fmt.Errorf("dataplane adapter %q is unavailable", adapterID)
	}
	canary, ok := adapter.(CanaryAdapter)
	if !ok {
		return fmt.Errorf("dataplane adapter %q has no isolated canary", adapterID)
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	base := filepath.Join(m.StateRoot, "candidate-probes")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	root, err := os.MkdirTemp(base, adapterID+"-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	for _, phase := range []struct {
		name string
		call func(context.Context, Plan, string) error
	}{
		{name: "snapshot", call: adapter.Snapshot},
		{name: "stage", call: adapter.Stage},
		{name: "validate", call: adapter.Validate},
	} {
		if err := phase.call(ctx, plan, root); err != nil {
			return fmt.Errorf("%s candidate %s: %w", adapterID, phase.name, err)
		}
	}
	if err := canary.Canary(ctx, plan.RoutePlanFor(adapterID), root); err != nil {
		return fmt.Errorf("%s isolated canary: %w", adapterID, err)
	}
	return nil
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
	if err := m.beginOperation(context.Background()); err != nil {
		return err
	}
	defer m.endOperation()
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
	if err := writeAtomic(filepath.Join(m.StateRoot, "latest-plan.json"), data, 0o600); err != nil {
		return err
	}
	if plan.State == "committed" {
		if err := writeAtomic(filepath.Join(m.StateRoot, "latest-committed-plan.json"), data, 0o600); err != nil {
			return fmt.Errorf("record committed dataplane plan: %w", err)
		}
	}
	return nil
}

func (m *Manager) Latest() (Plan, bool, error) {
	if m == nil || m.StateRoot == "" {
		return Plan{}, false, nil
	}
	return m.latestLocked()
}

// Committed returns the last plan that actually reached commit. Reviewed,
// blocked and rolled-back drafts remain visible through Latest but cannot
// replace the boot recovery source or the applied AUTO-route evidence.
func (m *Manager) Committed() (Plan, bool, error) {
	if m == nil || m.StateRoot == "" {
		return Plan{}, false, nil
	}
	return m.committedLocked()
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
	committed, committedExists, err := m.Committed()
	if err != nil {
		return status, err
	}
	if committedExists {
		status.CommittedPlan = &committed
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
	return readPlanJournal(filepath.Join(m.StateRoot, "latest-plan.json"))
}

func (m *Manager) committedLocked() (Plan, bool, error) {
	m.journalMu.RLock()
	defer m.journalMu.RUnlock()
	plan, exists, err := readPlanJournal(filepath.Join(m.StateRoot, "latest-committed-plan.json"))
	if err != nil || exists {
		return plan, exists, err
	}
	// Backward compatibility: before v0.15 the committed plan lived only in
	// latest-plan.json. Promote it lazily only when its state is unambiguous.
	plan, exists, err = readPlanJournal(filepath.Join(m.StateRoot, "latest-plan.json"))
	if err != nil || !exists || plan.State != "committed" {
		return Plan{}, false, err
	}
	return plan, true, nil
}

func readPlanJournal(path string) (Plan, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Plan{}, false, nil
	}
	if err != nil {
		return Plan{}, false, fmt.Errorf("read dataplane plan %s: %w", filepath.Base(path), err)
	}
	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return Plan{}, false, fmt.Errorf("decode dataplane plan %s: %w", filepath.Base(path), err)
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
	if err := m.beginOperation(ctx); err != nil {
		return Recovery{State: "cancelled", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}, err
	}
	defer m.endOperation()
	recovery := Recovery{State: "skipped", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []RecoveryStep{}}
	plan, exists, err := m.committedLocked()
	if err != nil {
		return recovery, err
	}
	if !exists || plan.State != "committed" || plan.SafeMode || plan.Noop {
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = m.writeRecoveryLocked(recovery)
		return recovery, nil
	}
	recovery.PlanID = plan.PlanID
	var previous *Recovery
	if _, readErr := readOptionalJournal(filepath.Join(m.StateRoot, "latest-recovery.json"), &previous); readErr != nil {
		return recovery, readErr
	}
	if previous != nil && previous.PlanID == plan.PlanID && (previous.State == "degraded" || previous.State == "safe-mode") {
		recovery.State = "safe-mode"
		recovery.Guarded = true
		recovery.FailureCount = previous.FailureCount + 1
		if recovery.FailureCount < 2 {
			recovery.FailureCount = 2
		}
		recovery.Steps = append(recovery.Steps, m.deactivateForRecovery(ctx, plan)...)
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		guardErr := errors.New("boot-loop guard blocked repeated dataplane recovery; Recovery Safe Mode is required")
		if err := m.writeRecoveryLocked(recovery); err != nil {
			return recovery, fmt.Errorf("%w; write recovery guard: %v", guardErr, err)
		}
		return recovery, guardErr
	}
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
		recovery.FailureCount = 1
		recovery.Steps = append(recovery.Steps, m.deactivateForRecovery(ctx, plan)...)
	}
	recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.writeRecoveryLocked(recovery); err != nil && firstErr == nil {
		firstErr = err
	}
	return recovery, firstErr
}

func (m *Manager) deactivateForRecovery(parent context.Context, plan Plan) []RecoveryStep {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), m.rollbackTimeout())
	defer cancel()
	steps := []RecoveryStep{}
	for i := len(plan.Adapters) - 1; i >= 0; i-- {
		id := plan.Adapters[i]
		step := RecoveryStep{Adapter: id, State: "safe-mode-skipped", Detail: "adapter has no owned-runtime deactivator"}
		adapter, ok := m.adapter(id)
		if !ok {
			step.State = "safe-mode-failed"
			step.Detail = "adapter is not registered"
		} else if deactivator, ok := adapter.(RuntimeDeactivator); ok {
			step.State, step.Detail = "safe-mode-deactivated", ""
			if err := deactivator.Deactivate(ctx); err != nil {
				step.State, step.Detail = "safe-mode-failed", err.Error()
			}
		}
		steps = append(steps, step)
	}
	return steps
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
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	plan, exists, err := m.committedLocked()
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
	if err := m.beginOperation(ctx); err != nil {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		return Deactivation{State: "cancelled", StartedAt: now, FinishedAt: now}, err
	}
	defer m.endOperation()
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
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []ExecutionStep{}}
	if err := m.beginOperation(ctx); err != nil {
		execution.State = "cancelled"
		execution.Error = err.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, err
	}
	defer m.endOperation()
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

	prepared := make([]Adapter, 0, len(plan.Adapters)+len(plan.RetiringAdapters))
	var undoCommit func() error
	run := func(runCtx context.Context, adapter Adapter, phase string, action func(context.Context, Plan, string) error) error {
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
		err := action(runCtx, plan, adapterRoot)
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
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), m.rollbackTimeout())
		defer cancelRollback()
		execution.Error = cause.Error()
		execution.State = "rolling-back"
		writeExecution()
		var rollbackErr error
		for i := len(prepared) - 1; i >= 0; i-- {
			adapter := prepared[i]
			if err := run(rollbackCtx, adapter, "rollback", adapter.Rollback); err != nil && rollbackErr == nil {
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
	rejectCanary := func(cause error) error {
		plan.Ready = false
		plan.State = "canary-failed"
		plan.Note = cause.Error()
		execution.Error = cause.Error()
		execution.State = "canary-failed"
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = m.recordLocked(plan)
		writeExecution()
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

	retiringAdapters := make([]Adapter, 0, len(plan.RetiringAdapters))
	for _, id := range plan.RetiringAdapters {
		adapter, ok := m.adapter(id)
		if !ok {
			return execution, rollback(fmt.Errorf("retiring adapter %s is not registered", id))
		}
		if _, ok := adapter.(RuntimeDeactivator); !ok {
			return execution, rollback(fmt.Errorf("retiring adapter %s cannot be safely deactivated", id))
		}
		retiringAdapters = append(retiringAdapters, adapter)
	}
	adapters := make([]Adapter, 0, len(plan.Adapters))
	for _, id := range plan.Adapters {
		adapter, ok := m.adapter(id)
		if !ok {
			return execution, rollback(fmt.Errorf("adapter %s is not registered", id))
		}
		adapters = append(adapters, adapter)
	}
	for _, adapter := range append(append([]Adapter(nil), retiringAdapters...), adapters...) {
		if err := run(ctx, adapter, "snapshot", adapter.Snapshot); err != nil {
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
	} {
		for _, adapter := range adapters {
			if err := run(ctx, adapter, phase.name, phase.call(adapter)); err != nil {
				return execution, rollback(err)
			}
		}
	}
	for _, adapter := range adapters {
		canary, ok := adapter.(CanaryAdapter)
		if !ok {
			continue
		}
		routePlan := plan.RoutePlanFor(adapter.ID())
		if err := run(ctx, adapter, "canary", func(runCtx context.Context, _ Plan, root string) error {
			return canary.Canary(runCtx, routePlan, root)
		}); err != nil {
			// CanaryAdapter owns and removes only its isolated candidate. Calling
			// the live Rollback method here could unnecessarily interrupt the
			// still-working process even though Activate has not started.
			return execution, rejectCanary(err)
		}
	}
	for _, adapter := range retiringAdapters {
		deactivator := adapter.(RuntimeDeactivator)
		if err := run(ctx, adapter, "deactivate", func(runCtx context.Context, _ Plan, _ string) error {
			return deactivator.Deactivate(runCtx)
		}); err != nil {
			return execution, rollback(err)
		}
	}
	for _, phase := range []struct {
		name string
		call func(Adapter) func(context.Context, Plan, string) error
	}{
		{name: "activate", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Activate }},
		{name: "health", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Health }},
		{name: "commit-adapter", call: func(a Adapter) func(context.Context, Plan, string) error { return a.Commit }},
	} {
		for _, adapter := range adapters {
			if err := run(ctx, adapter, phase.name, phase.call(adapter)); err != nil {
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
	plan.ObservedEvidence = plan.RequiredEvidence
	directPending := false
	routeInputs := map[string]Route{}
	for _, route := range plan.Routes {
		routeInputs[route.ServiceID+"|"+route.Resolved] = route
	}
	for index := range plan.RouteEvidence {
		proof := &plan.RouteEvidence[index]
		route := routeInputs[proof.ServiceID+"|"+proof.Route]
		switch {
		case AdapterID(proof.Route) == "direct":
			directPending = true
			proof.Note = "DIRECT не повышается из успеха другого обхода; требуется отдельный изолированный контроль."
		case strings.TrimSpace(route.ProbeURL) == "":
			proof.Note = "У сервиса нет контрольного URL; успешный запуск адаптера не подтверждает доступ к самому сервису."
		case len(route.Sources) > 0:
			proof.Note = "Маршрут ограничен устройствами; общий health-check не доказывает путь конкретного клиента."
		default:
			proof.Observed = proof.Required
			proof.Source = "adapter-health"
			proof.Note = "Обязательный health-check сервиса через активированный адаптер завершился успешно."
		}
		plan.ObservedEvidence = evidence.Weaker(plan.ObservedEvidence, proof.Observed)
	}
	if len(plan.RouteEvidence) != len(plan.Routes) {
		plan.ObservedEvidence = evidence.None
	}
	if !plan.ObservedEvidence.AtLeast(plan.RequiredEvidence) {
		if directPending {
			plan.EvidenceNote = "Обходы прошли health-check, но DIRECT-сервисы требуют отдельного изолированного контроля; общий уровень не повышен."
		} else {
			plan.EvidenceNote = "Адаптеры активированы, но не для каждого сервиса выполнена изолированная проверка; смотрите доказательность по маршрутам."
		}
	} else {
		plan.EvidenceNote = "Все адаптеры активированы, а обязательные health-check сервисов через назначенные маршруты завершились успешно."
	}
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
