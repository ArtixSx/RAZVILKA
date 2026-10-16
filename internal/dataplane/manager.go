package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrNetworkChanged = errors.New("network epoch changed or is unavailable; repeat exact node checks")

var ErrReviewChanged = errors.New("reviewed node plan is no longer current")

type reviewGuardKey struct{}
type reviewCommitAdapterKey struct{}

// WithReviewGuard attaches request-owned review authority to an existing
// transaction. The guard is never consulted during rollback.
func WithReviewGuard(ctx context.Context, guard func(context.Context) error) context.Context {
	return context.WithValue(ctx, reviewGuardKey{}, guard)
}

// ReviewCommittedAdapter identifies only the successful adapter commit whose
// postcondition is currently being checked. A review may then permit that
// adapter to have consumed its own staged files. It grants no rollback waiver.
func ReviewCommittedAdapter(ctx context.Context) string {
	id, _ := ctx.Value(reviewCommitAdapterKey{}).(string)
	return id
}

// preflightRefusalError is returned only after read-only checks, before the
// adapter touches live runtime. It grants no exemption once any adapter in the
// transaction has mutated runtime; that transaction must still roll back.
type preflightRefusalError struct{ error }

func (err preflightRefusalError) Unwrap() error { return err.error }

type Manager struct {
	operationOnce      sync.Once
	operationGate      chan struct{}
	journalMu          sync.RWMutex
	registryMu         sync.RWMutex
	registryGeneration uint64
	StateRoot          string
	Adapters           map[string]Adapter
	RollbackTimeout    time.Duration
	FreshProfile       func(context.Context) (string, error)
	retainedNFQMu      sync.Mutex
	retainedNFQ        *retainedNFQWSExecution
	pendingNFQ         *pendingNFQWSExecution
	wgPreEffectChecks  *NetworkPolicyChecks // Frozen trusted startup association; registryMu.
	retainedXrayMu     sync.Mutex
	retainedXray       *retainedXrayExecution
	replacementXray    *xraySelectedTCPReplacement
	retainedWGMu       sync.Mutex
	retainedWG         *retainedWGExecution
	retainedSingMu     sync.Mutex
	retainedSing       *RetainedSingReview // Read-only preparation, never a delta/skip grant.
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

// CheckComponentLive observes the exact committed runtime and probes its live
// path. It never runs Stage/Canary/Activate/Reconcile. Component recovery must
// supply current authority through WithReviewGuard and retain app admission.
func (m *Manager) CheckComponentLive(ctx context.Context, expected Plan, component string) error {
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	verify := func() error {
		if err := m.checkExecutionRecovery(); err != nil {
			return err
		}
		current, exists, err := m.Committed()
		if err != nil || !exists || current.State != "committed" || current.SafeMode || current.Noop || !reflect.DeepEqual(current, expected) {
			return ErrReviewChanged
		}
		return m.checkPlanNetwork(ctx, expected)
	}
	if err := verify(); err != nil {
		return err
	}
	matched := false
	for _, id := range expected.Adapters {
		uses := id == component || component == "sing-box" && (id == "xray" || id == "usque") || (component == "wireguard" || component == "warp-wg") && (id == "wireguard" || id == "warp-wg")
		if !uses {
			continue
		}
		matched = true
		if err := verify(); err != nil {
			return err
		}
		registered, exists := m.adapter(id)
		if !exists {
			return errors.New("live component adapter unavailable")
		}
		observer, ok := registered.(RuntimeObserver)
		if !ok {
			return errors.New("live component ownership observation unavailable")
		}
		if err := observer.ObserveOwnedRuntime(ctx); err != nil {
			return err
		}
		// All accepted routes must have a real health target. Source-scoped proxy
		// health without an exact-node probe currently skips service traffic.
		probe := false
		for _, route := range expected.Routes {
			if adapterID(route.Resolved) != id {
				continue
			}
			if route.ProbeURL == "" {
				return errors.New("live service health target unavailable")
			}
			if _, ok := registered.(*ProxyTunnelAdapter); ok && len(route.Sources) > 0 && !(RoutePlan{Routes: []Route{route}}).RequiresNetworkProof() {
				return errors.New("source-scoped live service probe unavailable")
			}
			probe = true
		}
		if !probe {
			return errors.New("live service proof unavailable")
		}
		switch a := registered.(type) {
		case *ProxyTunnelAdapter:
			state, exists, err := a.loadPolicy()
			if err != nil || !exists {
				return errors.New("live proxy policy unavailable")
			}
			check := func() error {
				if component == a.ID() {
					if err := verifyInstalledManagedProcess(a.engineProcess()); err != nil {
						return err
					}
				}
				if component == "sing-box" {
					return verifyInstalledManagedProcess(a.sidecarProcess())
				}
				return nil
			}
			if err := check(); err != nil {
				return err
			}
			if err := m.withExecutionResourcesLocked(ctx, expected, id, func(c context.Context) error {
				return a.healthState(c, expected, state)
			}); err != nil {
				return err
			}
			if err := check(); err != nil {
				return err
			}
		case *WARPWireGuardAdapter:
			state, exists, err := a.loadPolicyState()
			if err != nil || !exists {
				return errors.New("live WireGuard policy unavailable")
			}
			if err := a.healthState(ctx, expected, state, ""); err != nil {
				return err
			}
		case *NFQWS2Adapter:
			if err := a.Health(ctx, expected, ""); err != nil {
				return err
			}
		default:
			return errors.New("adapter has no component live acceptance implementation")
		}
		if err := observer.ObserveOwnedRuntime(ctx); err != nil {
			return err
		}
	}
	if !matched {
		return errors.New("component has no committed live runtime; isolated checks cannot accept it")
	}
	return verify()
}

func verifyInstalledManagedProcess(spec ProcessSpec) error {
	pid, err := readManagedPID(spec)
	if err != nil || !processMatches(pid, spec) {
		return errors.New("live managed component process unavailable")
	}
	installed, err := os.Stat(spec.Binary)
	if err != nil {
		return err
	}
	active, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || !os.SameFile(installed, active) {
		return errors.New("live managed process has not adopted the installed executable")
	}
	// Receipt is launch evidence, not an identity reconstructed from a candidate.
	data, err := os.ReadFile(spec.PIDPath + routeidentity.ReceiptSuffix)
	var receipt routeidentity.Receipt
	if err != nil || json.Unmarshal(data, &receipt) != nil || receipt.Version != 1 || receipt.PID != pid {
		return errors.New("live managed process launch receipt unavailable")
	}
	config, e1 := os.ReadFile(spec.MatchArg)
	cmd, e2 := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	stat, e3 := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	boot, e4 := os.ReadFile("/proc/sys/kernel/random/boot_id")
	executable, e5 := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	end := strings.LastIndex(string(stat), ")")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || end < 0 {
		return errors.New("live managed process identity unavailable")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[19] != receipt.StartTicks || strings.TrimSpace(string(boot)) != receipt.BootID || executable != receipt.Executable || routeidentity.Hash(cmd) != receipt.ArgsHash || routeidentity.Hash(config) != receipt.ConfigHash {
		return errors.New("live managed process changed since launch")
	}
	return nil
}

type PolicyRefresher interface {
	RefreshPolicy(context.Context, Plan) (bool, error)
}

type RuntimeDeactivator interface {
	Deactivate(context.Context) error
}

// RetirementCommitter finalizes settings only after the whole replacement
// plan passed health. Its original snapshot remains available for rollback.
type RetirementCommitter interface {
	CommitRetirement(context.Context, Plan, string) error
}

// RollbackVerifier reads back the restored local runtime after ALL adapters
// and configuration have been rolled back. true certifies the exact recorded
// resources, not service availability or a LAN-client request. Unsupported
// legacy states return false, nil and cannot authorize trying another candidate.
type RollbackVerifier interface {
	VerifyRollback(context.Context, Plan, string) (bool, error)
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
	ResourcePlanID   string              `json:"resource_plan_id,omitempty"`
	Resources        []ExecutionResource `json:"resources,omitempty"`
	PlanID           string              `json:"plan_id"`
	Digest           string              `json:"digest"`
	State            string              `json:"state"`
	StartedAt        string              `json:"started_at"`
	FinishedAt       string              `json:"finished_at,omitempty"`
	Steps            []ExecutionStep     `json:"steps"`
	Error            string              `json:"error,omitempty"`
	RollbackVerified bool                `json:"rollback_verified,omitempty"`
}

type PolicyRefresh struct {
	State     string          `json:"state,omitempty"`
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
	return &Manager{StateRoot: stateRoot, Adapters: map[string]Adapter{}, operationGate: make(chan struct{}, 1), RollbackTimeout: defaultRollbackTimeout, FreshProfile: observeNetworkProfile}
}

// ConfigureSingBoxNodeRoutes attaches the private registry only after both
// stores completed boot recovery. It does not materialize or mutate a route.
func (m *Manager) ConfigureSingBoxNodeRoutes(materializer NodeRouteMaterializer, profile func(context.Context) (string, error)) error {
	if m == nil || materializer == nil || profile == nil {
		return errors.New("Sing-box node route materializer is unavailable")
	}
	m.registryMu.Lock()
	defer m.registryMu.Unlock()
	adapter, ok := m.Adapters["sing-box"].(*ProxyTunnelAdapter)
	if !ok || adapter == nil {
		return errors.New("Sing-box dataplane adapter is unavailable")
	}
	adapter.NodeRoutes = materializer
	adapter.FreshProfile = profile
	m.FreshProfile = profile
	return nil
}

func observeNetworkProfile(ctx context.Context) (string, error) {
	profile, err := systemprobe.FreshWANProfile(ctx)
	return profile.ID, err
}

func verifyNetworkProfile(ctx context.Context, expected string, observe func(context.Context) (string, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !systemprobe.ValidWANProfileID(expected) {
		return ErrNetworkChanged
	}
	if observe == nil {
		observe = observeNetworkProfile
	}
	current, err := observe(ctx)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if err != nil || !systemprobe.ValidWANProfileID(current) || current != expected {
		return ErrNetworkChanged
	}
	return nil
}

// adapterNeedsNetworkProof reports whether an adapter serves node routes or
// the scoped DNS of the plan, whose proof is bound to a network epoch.
func adapterNeedsNetworkProof(plan Plan, id string) bool {
	if plan.LAN != nil {
		return true
	}
	if plan.DNS != nil && id == scopedDNSAdapterID {
		return true
	}
	for _, route := range plan.Routes {
		if adapterID(route.Resolved) == id && routesRequireNetworkProof([]Route{route}) {
			return true
		}
	}
	return false
}

// reconcileNetworkIndependent restores the adapters of a network-stale plan
// that do not need network proof. Failures are recorded; the plan stays
// network-stale until node recovery proves and applies it again.
func (m *Manager) reconcileNetworkIndependent(ctx context.Context, plan Plan) []RecoveryStep {
	var steps []RecoveryStep
	for _, id := range plan.Adapters {
		if adapterNeedsNetworkProof(plan, id) || ctx.Err() != nil {
			continue
		}
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
		steps = append(steps, step)
	}
	return steps
}

func (m *Manager) checkPlanNetwork(ctx context.Context, plan Plan) error {
	if plan.RequiresNetworkProof() {
		if err := verifyNetworkProfile(ctx, plan.NetworkProfileID, m.FreshProfile); err != nil {
			return err
		}
	}
	if guard, ok := ctx.Value(reviewGuardKey{}).(func(context.Context) error); ok && guard != nil {
		return guard(ctx)
	}
	return nil
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

// A rollback that runs out of time fences every later change, so its budget
// covers a full policy on a slow router: the Keenetic USB drive needs about
// half a second per fsync and a sing-box policy records about 60 selectors.
const defaultRollbackTimeout = 3 * time.Minute

// liveMutationBudget bounds one live phase that no longer follows its
// caller's cancellation.
const liveMutationBudget = 3 * time.Minute

// shieldLiveMutation lets a started live phase finish its kernel steps. A
// cancellation in the middle of a step (an operator click interrupting the
// autopilot, a page load, a service stop) left its receipt between intent and
// acknowledgement; such a step is unknown by design, its rollback refuses and
// the router stays fenced. Cancellation still stops the transaction before
// this phase, and after it the next phase fails and rolls back normally.
func shieldLiveMutation(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), liveMutationBudget)
}

func (m *Manager) rollbackTimeout() time.Duration {
	if m != nil && m.RollbackTimeout > 0 {
		return m.RollbackTimeout
	}
	return defaultRollbackTimeout
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
	if nfqws2, ok := adapter.(*NFQWS2Adapter); ok {
		if err := nfqws2.bindStateRoot(m.StateRoot); err != nil {
			return err
		}
	}
	if gate, ok := adapter.(*NetworkPolicyAdapter); ok {
		if err := gate.bindStateRoot(m.StateRoot); err != nil {
			return err
		}
	}
	m.Adapters[adapter.ID()] = adapter
	m.registryGeneration++
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

// XrayNodeRouteCapable distinguishes the scoped registry backend from a
// generic Xray draft adapter. A service proof alone does not grant LAN proof.
func (m *Manager) XrayNodeRouteCapable() bool {
	if m == nil {
		return false
	}
	m.registryMu.RLock()
	defer m.registryMu.RUnlock()
	a, ok := m.Adapters["xray"].(*ProxyTunnelAdapter)
	return ok && a != nil && a.scopedXray && a.NodeRoutes != nil && a.FreshProfile != nil && a.NodeTUNProbe != nil
}

// ProbeCandidate runs the non-live half of a transaction for one adapter:
// snapshot, stage, validate and isolated canary. It never calls Activate,
// Commit or Rollback because the CanaryAdapter contract must leave live state
// untouched and clean only its temporary resources.
func (m *Manager) ProbeCandidate(ctx context.Context, plan Plan, adapterID string) (retErr error) {
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
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		return err
	}
	if err := os.MkdirAll(m.StateRoot, 0o700); err != nil {
		return err
	}
	owned, err := ownedfs.Open(m.StateRoot)
	if err != nil {
		return err
	}
	defer owned.Close()
	if err := owned.MkdirAll("candidate-probes", 0o700); err != nil {
		return err
	}
	relative, err := owned.MkdirTemp("candidate-probes", adapterID+"-")
	if err != nil {
		return err
	}
	root := filepath.Join(m.StateRoot, relative)
	defer func() {
		if err := owned.RemoveAll(relative); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("clean owned candidate files: %w", err))
		}
	}()
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
		if err := m.checkPlanNetwork(ctx, plan); err != nil {
			return err
		}
	}
	check := func(c context.Context) error { return canary.Canary(c, plan.RoutePlanFor(adapterID), root) }
	guard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
	if guard != nil && validPlanID(plan.PlanID) && validPlanDigest(plan.Digest) {
		call := check
		check = func(c context.Context) error { return m.withExecutionResourcesLocked(c, plan, adapterID, call) }
	}
	if err := check(ctx); err != nil {
		return fmt.Errorf("%s isolated canary: %w", adapterID, err)
	}
	return m.checkPlanNetwork(ctx, plan)
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
	m.revokeRetainedSingReview()
	m.journalMu.Lock()
	defer m.journalMu.Unlock()
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("encode dataplane plan: %w", err)
	}
	if err := os.MkdirAll(m.StateRoot, 0o700); err != nil {
		return fmt.Errorf("create dataplane state: %w", err)
	}
	if err := writeDataplaneJournal(filepath.Join(m.StateRoot, "latest-plan.json"), data); err != nil {
		return err
	}
	if plan.State == "committed" {
		if err := writeDataplaneJournal(filepath.Join(m.StateRoot, "latest-committed-plan.json"), data); err != nil {
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

// CommittedPolicyRefresh returns the latest address refresh only when it
// belongs to the committed plan. Unlike Status it decodes just the plan
// identity, so a frequent reader does not parse every route list.
func (m *Manager) CommittedPolicyRefresh() (*PolicyRefresh, error) {
	if m == nil || m.StateRoot == "" {
		return nil, nil
	}
	var refresh *PolicyRefresh
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-policy-refresh.json"), &refresh); err != nil || !found {
		return nil, err
	}
	m.journalMu.RLock()
	defer m.journalMu.RUnlock()
	committed, found, err := readPlanIdentity(filepath.Join(m.StateRoot, "latest-committed-plan.json"))
	if err == nil && !found {
		// Same pre-v0.15 fallback as committedLocked.
		committed, found, err = readPlanIdentity(filepath.Join(m.StateRoot, "latest-plan.json"))
		found = found && committed.State == "committed"
	}
	if err != nil || !found || refresh.PlanID != committed.PlanID {
		return nil, err
	}
	return refresh, nil
}

type planIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	PlanID        string `json:"plan_id"`
	Digest        string `json:"digest"`
	State         string `json:"state"`
}

// readPlanIdentity applies readPlanJournal's validity rule without
// materializing routes, actions or evidence.
func readPlanIdentity(path string) (planIdentity, bool, error) {
	var identity *planIdentity
	found, err := readOptionalJournal(path, &identity)
	if err != nil || !found {
		return planIdentity{}, false, err
	}
	if identity.SchemaVersion != SchemaVersion || identity.PlanID == "" || identity.Digest == "" {
		return planIdentity{}, false, errors.New("invalid dataplane plan journal")
	}
	return *identity, true, nil
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
	m.revokeRetainedSingReview()
	recovery := Recovery{State: "skipped", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []RecoveryStep{}}
	if settled, err := m.settleCommittedPublication(); err != nil {
		recovery.Steps = append(recovery.Steps, RecoveryStep{Adapter: "journal", State: "failed", Detail: "The interrupted commit could not be completed in the journal."})
	} else if settled {
		recovery.Steps = append(recovery.Steps, RecoveryStep{Adapter: "journal", State: "settled", Detail: "An interrupted commit was completed: its plan had been published and every step had passed."})
	}
	if err := m.checkExecutionRecovery(); err != nil {
		recovery.State, recovery.Guarded = "journal-recovery-required", true
		steps, cleanupErr := m.revokeUnverifiedDNS(ctx)
		recovery.Steps = append(recovery.Steps, steps...)
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return recovery, errors.Join(err, cleanupErr, executionJournalError(m.writeRecoveryLocked(recovery)))
	}
	plan, exists, err := m.committedLocked()
	if err != nil {
		recovery.State, recovery.Guarded = "journal-recovery-required", true
		steps, cleanupErr := m.revokeUnverifiedDNS(ctx)
		recovery.Steps = append(recovery.Steps, steps...)
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return recovery, errors.Join(executionJournalError(err), cleanupErr, executionJournalError(m.writeRecoveryLocked(recovery)))
	}
	if !exists || plan.State != "committed" || plan.SafeMode || plan.Noop {
		steps, cleanupErr := m.revokeUnverifiedDNS(ctx)
		recovery.Steps = append(recovery.Steps, steps...)
		if cleanupErr != nil {
			recovery.State, recovery.Guarded = "safe-mode", true
		}
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return recovery, errors.Join(cleanupErr, executionJournalError(m.writeRecoveryLocked(recovery)))
	}
	if plan.DNS == nil {
		steps, cleanupErr := m.revokeUnverifiedDNS(ctx)
		recovery.Steps = append(recovery.Steps, steps...)
		if cleanupErr != nil {
			recovery.State, recovery.Guarded = "safe-mode", true
			recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			return recovery, errors.Join(cleanupErr, executionJournalError(m.writeRecoveryLocked(recovery)))
		}
	}
	recovery.PlanID = plan.PlanID
	networkStale := func(cause error) (Recovery, error) {
		recovery.State, recovery.Guarded, recovery.FailureCount = "network-stale", false, 0
		recovery.Steps = append(recovery.Steps, RecoveryStep{Adapter: "network", State: "network-stale", Detail: cause.Error()})
		if errors.Is(cause, ErrNetworkChanged) {
			steps, cleanupErr := m.revokeUnverifiedDNS(ctx)
			recovery.Steps = append(recovery.Steps, steps...)
			if cleanupErr != nil {
				recovery.State, recovery.Guarded, recovery.FailureCount = "safe-mode", true, 1
				cause = errors.Join(cause, cleanupErr)
			}
		}
		recovery.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := m.writeRecoveryLocked(recovery); err != nil {
			return recovery, errors.Join(cause, err)
		}
		return recovery, cause
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		// Every new process observes a new network epoch, so a plan with node
		// routes waits for fresh node checks after any restart. Adapters without
		// such routes (NFQWS2) do not depend on that proof: restore them now.
		// Otherwise their services stay without the lists the installer removes
		// while it replaces the program, and a later node transaction snapshots
		// and "restores" that incomplete state.
		recovery.Steps = append(recovery.Steps, m.reconcileNetworkIndependent(ctx, plan)...)
		return networkStale(err)
	}
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
	gateFailed := false
	for _, id := range networkPolicyGateFirstIDs(plan.Adapters) {
		if gateFailed && id != NetworkPolicyAdapterID {
			recovery.Steps = append(recovery.Steps, RecoveryStep{Adapter: id, State: "failed", Detail: "LAN admission recovery failed; consumer was not started"})
			continue
		}
		if err := m.checkPlanNetwork(ctx, plan); err != nil {
			return networkStale(err)
		}
		step := RecoveryStep{Adapter: id, State: "failed"}
		adapter, ok := m.adapter(id)
		if !ok {
			step.Detail = "adapter is not registered"
		} else if reconciler, ok := adapter.(RuntimeReconciler); !ok {
			step.Detail = "adapter does not support boot recovery"
		} else if err := reconciler.Reconcile(ctx, plan); err != nil {
			if errors.Is(err, ErrNetworkChanged) {
				return networkStale(err)
			}
			step.Detail = err.Error()
		} else {
			step.State = "recovered"
		}
		if step.State == "failed" && firstErr == nil {
			firstErr = fmt.Errorf("recover %s: %s", id, step.Detail)
		}
		if id == NetworkPolicyAdapterID && step.State == "failed" {
			gateFailed = true
		}
		recovery.Steps = append(recovery.Steps, step)
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		return networkStale(err)
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
	ids := slices.Clone(plan.Adapters)
	slices.Reverse(ids)
	ids = networkPolicyGateLastIDs(ids)
	consumerFailed := false
	for _, id := range ids {
		step := RecoveryStep{Adapter: id, State: "safe-mode-skipped", Detail: "adapter has no owned-runtime deactivator"}
		adapter, ok := m.adapter(id)
		if id == NetworkPolicyAdapterID && consumerFailed {
			step.State, step.Detail = "safe-mode-failed", ErrNetworkPolicyConsumers.Error()
			steps = append(steps, step)
			continue
		}
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
		if id != NetworkPolicyAdapterID && step.State != "safe-mode-deactivated" {
			consumerFailed = true
		}
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
	m.revokeRetainedSingReview()
	plan, exists, err := m.committedLocked()
	if err != nil {
		return nil, err
	}
	if !exists || plan.State != "committed" || plan.SafeMode || plan.Noop {
		return map[string]bool{}, nil
	}
	changed := map[string]bool{}
	var firstErr error
	writeRefresh := func() error {
		state := "checked"
		if firstErr != nil {
			state = "failed"
		}
		for _, updated := range changed {
			if updated && firstErr != nil {
				state = "partial"
			}
		}
		if errors.Is(firstErr, ErrNetworkChanged) {
			state = "network-stale"
		}
		if errors.Is(firstErr, context.Canceled) {
			state = "canceled"
		}
		if errors.Is(firstErr, context.DeadlineExceeded) {
			state = "timed-out"
		}
		report := PolicyRefresh{PlanID: plan.PlanID, State: state, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Changed: changed}
		if firstErr != nil {
			report.Error = "Address refresh did not complete; inspect the owned runtime and retry. Existing configuration was not declared healthy."
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		return writeAtomic(filepath.Join(m.StateRoot, "latest-policy-refresh.json"), data, 0o600)
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		firstErr = err
		return changed, errors.Join(err, writeRefresh())
	}
	for _, id := range plan.Adapters {
		if err := m.checkPlanNetwork(ctx, plan); err != nil {
			firstErr = err
			break
		}
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
		callerGuard, _ := ctx.Value(reviewGuardKey{}).(func(context.Context) error)
		updated, err := refresher.RefreshPolicy(WithReviewGuard(ctx, func(c context.Context) error {
			if c.Err() != nil {
				return c.Err()
			}
			// Keep the child cancellation and the original caller authority.
			return m.checkPlanNetwork(WithReviewGuard(c, callerGuard), plan)
		}), plan)
		if err != nil {
			if errors.Is(err, ErrNetworkChanged) {
				firstErr = err
				break
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("refresh %s policy: %w", id, err)
			}
			continue
		}
		changed[id] = updated
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		firstErr = err
	}
	if err := writeRefresh(); err != nil && firstErr == nil {
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
	m.revokeRetainedSingReview()
	report := Deactivation{State: "deactivated", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []DeactivationStep{}}
	m.registryMu.RLock()
	ids := make([]string, 0, len(m.Adapters))
	for id := range m.Adapters {
		ids = append(ids, id)
	}
	m.registryMu.RUnlock()
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	ids = networkPolicyGateLastIDs(ids)
	var firstErr error
	for _, id := range ids {
		adapter, _ := m.adapter(id)
		step := DeactivationStep{Adapter: id, State: "skipped", Detail: "adapter has no owned-runtime deactivator"}
		if id == NetworkPolicyAdapterID && firstErr != nil {
			step.State, step.Detail = "failed", ErrNetworkPolicyConsumers.Error()
			report.Steps = append(report.Steps, step)
			continue
		}
		if deactivator, ok := adapter.(RuntimeDeactivator); ok {
			step.State, step.Detail = "deactivated", ""
			if err := deactivator.Deactivate(ctx); err != nil {
				step.State, step.Detail = "failed", err.Error()
				if firstErr == nil {
					firstErr = fmt.Errorf("deactivate %s: %w", id, err)
				}
			}
		} else if slices.Contains(ids, NetworkPolicyAdapterID) {
			step.State, step.Detail = "failed", ErrNetworkPolicyConsumers.Error()
			firstErr = errors.Join(firstErr, ErrNetworkPolicyConsumers)
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
func (m *Manager) Apply(ctx context.Context, plan Plan, commit func() (func() error, error)) (result Execution, resultErr error) {
	if m == nil || m.StateRoot == "" {
		return Execution{}, errors.New("dataplane state root is not configured")
	}
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "applying", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Steps: []ExecutionStep{}}
	if err := m.beginOperation(ctx); err != nil {
		execution.State = "cancelled"
		if m.pendingUnenteredXrayReplacement(ctx, plan) {
			execution.State = "replacement-pending"
		}
		execution.Error = err.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, err
	}
	defer m.endOperation()
	m.revokeRetainedSingReview()
	pair, pairErr := m.xrayReplacementFor(ctx, plan)
	if pairErr != nil {
		if m.pendingUnenteredXrayReplacement(ctx, plan) {
			execution.State = "replacement-pending"
		}
		return execution, pairErr
	}
	pairInResourceDefer := false
	defer func() {
		if pair != nil && !pairInResourceDefer {
			pair.settleApply(ctx, &result, &resultErr)
		}
	}()
	if err := validateDomainTransportForExecution(plan); err != nil {
		return execution, err
	}
	if m.retainedNFQOwner() != nil || m.HasPendingManagedNFQWS() || m.retainedXrayOwner() != nil && pair == nil || m.retainedWGOwner() != nil {
		return execution, ErrNetworkPolicyReplacement // Join the original owner with explicit Stop first.
	}
	if err := m.checkManagedNFQWSApply(ctx, plan); err != nil {
		return execution, err
	}
	if err := validateNetworkPolicyParticipation(plan); err != nil {
		return execution, err
	}
	if plan.SchemaVersion != SchemaVersion || plan.PlanID == "" || plan.Digest == "" {
		return execution, errors.New("invalid dataplane plan")
	}
	if plan.SafeMode {
		return execution, errors.New("Safe Mode blocks dataplane execution")
	}
	if !plan.Ready {
		return execution, errors.New("dataplane plan is blocked")
	}
	if err := m.checkScopedDNSContinuation(plan); err != nil {
		execution.State, execution.Error = "rejected", err.Error()
		if errors.Is(err, ErrExecutionJournal) {
			execution.State = "journal-failed"
		}
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, err
	}
	if err := m.checkExecutionRecovery(); err != nil {
		execution.State, execution.Error = "journal-failed", err.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, err
	}
	previousPolicy, previousExists, previousErr := m.committedLocked()
	if previousErr != nil {
		return execution, executionJournalError(previousErr)
	}
	if previousExists && previousPolicy.LAN != nil && plan.LAN == nil {
		if err := m.verifyRuntimeInactiveLocked(ctx); err != nil {
			return execution, errors.Join(ErrNetworkPolicyReplacement, err)
		}
	}
	// Resolve a stopped DNS snapshot before publishing this transaction's
	// unfinished journal. SuspendedDNS deliberately refuses unfinished work.
	var discardedDNSPrior *Plan
	if plan.DiscardDNS {
		previous, exists, err := m.committedLocked()
		if err != nil || !exists {
			return execution, errors.Join(err, ErrReviewChanged)
		}
		saved, err := m.suspendedDNSState(previous)
		if err != nil {
			return execution, err
		}
		previous.DNS, previous.Routes, previous.NetworkProfileID = saved.DNS, saved.Routes, saved.Network
		discardedDNSPrior = &previous
	}
	transactionRoot := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
	if err := m.retireSettledAttempt(transactionRoot); err != nil {
		execution.State, execution.Error = "journal-failed", err.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, err
	}
	if err := m.prepareExecutionRoot(transactionRoot); err != nil {
		execution.State, execution.Error = "journal-failed", err.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, err
	}
	var activeNFQScope, activeXrayScope, activeWGScope *executionResourceScope
	var xrayPreResource *xraySelectedTCPPreResource
	if pair != nil {
		var attachErr error
		activeXrayScope, attachErr = m.newExecutionResourceScope(ctx, plan, "xray", &execution, transactionRoot)
		if attachErr == nil {
			attachErr = pair.attachScope(activeXrayScope)
		}
		if attachErr != nil {
			return execution, attachErr
		}
	}
	writeExecution := func() error {
		count := 0
		for _, candidate := range []*executionResourceScope{activeNFQScope, activeXrayScope, activeWGScope} {
			if candidate != nil {
				count++
			}
		}
		if count > 1 {
			return executionJournalError(ErrNetworkPolicyAuthority)
		}
		scope := activeNFQScope
		if activeXrayScope != nil {
			scope = activeXrayScope
		}
		if activeWGScope != nil {
			scope = activeWGScope
		}
		return m.writeExecutionOwned(transactionRoot, execution, scope)
	}
	restoreCommitted, journalErr := m.preserveCommittedJournal()
	if journalErr == nil {
		journalErr = writeExecution()
	}
	if journalErr != nil {
		execution.State, execution.Error = "journal-failed", journalErr.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return execution, journalErr
	}

	prepared := make([]Adapter, 0, len(plan.Adapters)+len(plan.RetiringAdapters))
	var undoCommit func() error
	commitPublicationAttempted := false
	liveMutation := false
	var retryNFQRollback func(context.Context) error
	var retryXrayRollback func(context.Context) error
	var retryWGRollback func(context.Context) error
	pairInResourceDefer = true
	defer func() {
		if pair != nil {
			pair.retry = retryXrayRollback
			if result.State == "rollback-failed" && activeXrayScope != nil && pair.candidate.resource != nil && !activeXrayScope.retained && retryXrayRollback != nil {
				resultErr = errors.Join(resultErr, m.retainPendingXray(ctx, activeXrayScope, retryXrayRollback))
			}
			pair.settleApply(ctx, &result, &resultErr)
			if pair.pending.Load() {
				return // Both actual issuers/compensation roots remain open.
			}
		}
		if activeWGScope != nil && !activeWGScope.retained {
			if result.State == "rollback-failed" && retryWGRollback != nil {
				if err := m.retainOriginalWG(ctx, activeWGScope, retryWGRollback); err == nil {
					result.Resources = cloneExecutionResources(result.Resources)
					result.Steps = slices.Clone(result.Steps)
					return
				} else {
					resultErr = errors.Join(resultErr, err)
				}
			}
			resultErr = errors.Join(resultErr, activeWGScope.close())
		}
		if activeXrayScope != nil && !activeXrayScope.retained {
			if result.State == "rollback-failed" && retryXrayRollback != nil {
				if err := m.retainPendingXray(ctx, activeXrayScope, retryXrayRollback); err == nil {
					result.Resources = cloneExecutionResources(result.Resources)
					result.Steps = slices.Clone(result.Steps)
					return
				} else {
					resultErr = errors.Join(resultErr, err)
				}
			}
			if err := activeXrayScope.close(); err != nil {
				resultErr = errors.Join(resultErr, executionJournalError(err))
				result.RollbackVerified = false
			}
		}
		if (activeNFQScope == nil || !activeNFQScope.retained) && result.State == "rollback-failed" && retryNFQRollback != nil {
			if err := m.retainPendingNFQWS(ctx, activeNFQScope, retryNFQRollback); err == nil {
				// Returned data never aliases the private retained original owner.
				result.Resources = cloneExecutionResources(result.Resources)
				result.Steps = slices.Clone(result.Steps)
				return
			}
		}
		if activeNFQScope != nil && !activeNFQScope.retained {
			if err := activeNFQScope.close(); err != nil {
				resultErr = errors.Join(resultErr, executionJournalError(err))
				result.RollbackVerified = false
			}
		}
	}()
	// Issue one original WG command owner before Snapshot/Stage/Canary. The
	// SAME scope also supplies the shared LAN participant's consumer context.
	for _, id := range plan.Adapters {
		adapter, _ := m.adapter(id)
		if a, ok := adapter.(*WARPWireGuardAdapter); ok && a != nil && a.wgCommandTools != nil {
			if activeWGScope != nil || plan.LAN == nil {
				return execution, ErrWGOperationOwner
			}
			material, _ := ctx.Value(wgOperationMaterialKey{}).(*WGOperationMaterial)
			if material == nil || material.source == nil || material.source.Current(ctx) != nil {
				return execution, ErrWGOperationOwner
			}
			var err error
			activeWGScope, err = m.newExecutionResourceScope(ctx, plan, id, &execution, transactionRoot)
			if err != nil {
				return execution, err
			}
		}
	}
	run := func(runCtx context.Context, adapter Adapter, phase string, action func(context.Context, Plan, string) error) error {
		restoring := phase == "rollback" || phase == "verify-rollback"
		if !restoring {
			if err := runCtx.Err(); err != nil {
				return err
			}
		}
		if xrayPreResource == nil && activeXrayScope == nil && !restoring && adapter.ID() == NetworkPolicyAdapterID &&
			validPlanID(plan.PlanID) && ctx.Value(xraySelectedTCPExecutionKey{}) != nil {
			var err error
			activeXrayScope, xrayPreResource, err = m.originalXrayPreResourceScope(ctx, plan, &execution, transactionRoot)
			if err != nil {
				return err
			}
		}
		if xrayPreResource != nil && (adapter.ID() == NetworkPolicyAdapterID || adapter == xrayPreResource.owner.material.adapter) {
			var err error
			runCtx, err = xrayPreResource.context(runCtx, restoring)
			if err != nil {
				return err
			}
			runCtx = networkPolicyConsumerContext(runCtx, activeXrayScope.plan)
		}
		if activeWGScope != nil {
			if restoring {
				var err error
				runCtx, err = activeWGScope.wgOwner.cleanupContext(runCtx)
				if err != nil {
					return err
				}
			} else {
				runCtx = activeWGScope.contextWith(runCtx)
			}
			runCtx = networkPolicyConsumerContext(runCtx, activeWGScope.plan)
		}
		if !restoring {
			if err := m.checkPlanNetwork(runCtx, plan); err != nil {
				return err
			}
		}
		step := ExecutionStep{Adapter: adapter.ID(), Phase: phase, State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		execution.Steps = append(execution.Steps, step)
		index := len(execution.Steps) - 1
		journalErr := writeExecution()
		if journalErr != nil && !restoring {
			execution.Steps[index].State, execution.Steps[index].Detail = "failed", journalErr.Error()
			execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			return journalErr
		}
		adapterRoot := filepath.Join(transactionRoot, adapter.ID())
		if err := os.MkdirAll(adapterRoot, 0o700); err != nil && !restoring {
			execution.Steps[index].State = "failed"
			execution.Steps[index].Detail = err.Error()
			execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			return errors.Join(err, writeExecution())
		}
		previouslyMutated := liveMutation
		if phase == "activate" || phase == "deactivate" || phase == "commit-adapter" {
			if !restoring {
				// Journal publication can outlast a cancellation. Admit the phase
				// using the original context before detaching its kernel work.
				if err := runCtx.Err(); err != nil {
					execution.Steps[index].State, execution.Steps[index].Detail = "failed", err.Error()
					execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
					return errors.Join(err, writeExecution())
				}
				var release context.CancelFunc
				runCtx, release = shieldLiveMutation(runCtx)
				defer release()
			}
			liveMutation = true
		}
		var err error
		_, actualNFQ := adapter.(*NFQWS2Adapter)
		actualXray, isXray := adapter.(*ProxyTunnelAdapter)
		_, selectedXray, xrayErr := xraySelectedTCPExecutionFor(runCtx, actualXray, plan, adapterRoot)
		if activeWGScope != nil {
			err = action(runCtx, plan, adapterRoot)
		} else if isXray && selectedXray {
			if xrayErr != nil {
				err = xrayErr
			} else {
				if activeXrayScope == nil && !restoring {
					activeXrayScope, err = m.newExecutionResourceScope(ctx, plan, adapter.ID(), &execution, transactionRoot)
				}
				if err == nil && activeXrayScope != nil {
					err = action(activeXrayScope.contextWith(runCtx), cloneExecutionResourcePlan(activeXrayScope.plan), adapterRoot)
				} else if restoring {
					err = action(runCtx, plan, adapterRoot)
				}
			}
		} else if actualNFQ && plan.LAN != nil && (phase == "activate" || phase == "health" || phase == "commit-adapter" || restoring) {
			if activeNFQScope == nil && !restoring {
				activeNFQScope, err = m.newExecutionResourceScope(ctx, plan, adapter.ID(), &execution, transactionRoot)
			}
			if err == nil && activeNFQScope != nil {
				err = action(activeNFQScope.contextWith(runCtx), cloneExecutionResourcePlan(activeNFQScope.plan), adapterRoot)
			} else if restoring {
				err = action(runCtx, plan, adapterRoot)
			}
		} else if (phase == "health" || phase == "canary") && validPlanID(plan.PlanID) && validPlanDigest(plan.Digest) {
			var scope *executionResourceScope
			scope, err = m.newExecutionResourceScope(runCtx, plan, adapter.ID(), &execution, transactionRoot)
			if err == nil {
				defer scope.close() // Unexpected callback exits cannot retain authority.
				err = action(scope.context(), plan, adapterRoot)
				err = errors.Join(err, scope.close())
			}
		} else {
			err = action(runCtx, plan, adapterRoot)
		}
		if validateExecutionResources(execution, true) != nil {
			// A temporary rule may have entered the common writer even when the
			// adapter phase is nominally isolated. Unknown resources require the
			// same rollback fence and retained LAN boundary as live mutations.
			liveMutation = true
		}
		wgMutation := activeWGScope != nil && activeWGScope.wgOwner.mutationAttempted.Load()
		if wgMutation {
			liveMutation = true
		}
		var preflight preflightRefusalError
		if !previouslyMutated && !wgMutation && errors.As(err, &preflight) && validateExecutionResources(execution, true) == nil {
			liveMutation = false
		}
		if err == nil && !restoring {
			checkCtx := runCtx
			if phase == "commit-adapter" {
				checkCtx = context.WithValue(checkCtx, reviewCommitAdapterKey{}, adapter.ID())
			}
			err = m.checkPlanNetwork(checkCtx, plan)
		}
		execution.Steps[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err != nil {
			execution.Steps[index].State = "failed"
			execution.Steps[index].Detail = err.Error()
		} else {
			execution.Steps[index].State = "passed"
		}
		return errors.Join(err, journalErr, writeExecution())
	}
	rollbackParent := ctx
	// Private completion of this SAME original never-effect participant.
	// It is reset per compensation cycle and is never a mutation receipt.
	var noEffectNFQCompletion *nfqwsPreEffectLANReview
	var noEffectWGCompletion *wgPreEffectSnapshot
	rollback := func(cause error) error {
		noEffectNFQCompletion = nil
		noEffectWGCompletion = nil
		if activeWGScope != nil {
			activeWGScope.mu.Lock()
			activeWGScope.wgCleanupJoined = false
			activeWGScope.mu.Unlock()
		}
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(rollbackParent), m.rollbackTimeout())
		defer cancelRollback()
		execution.Error = cause.Error()
		plan.ObservedEvidence = evidence.None
		for index := range plan.RouteEvidence {
			plan.RouteEvidence[index].Observed = evidence.None
		}
		execution.State = "rolling-back"
		rollbackErr := writeExecution()
		var gate Adapter
		for i := len(prepared) - 1; i >= 0; i-- {
			adapter := prepared[i]
			if adapter.ID() == NetworkPolicyAdapterID {
				gate = adapter
				continue
			}
			if err := run(rollbackCtx, adapter, "rollback", adapter.Rollback); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
		if undoCommit != nil {
			if err := undoCommit(); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore desired state: %w", err))
			}
		}
		if commitPublicationAttempted {
			rollbackErr = errors.Join(rollbackErr, restoreCommitted())
		}
		verified := liveMutation && len(prepared) > 0 && rollbackErr == nil
		consumersVerified := rollbackErr == nil
		wgConsumerVerified := false
		// Readback must follow the complete reverse restoration, including
		// desired-state undo. Never reuse the failed candidate's review guard.
		for _, adapter := range prepared {
			if adapter.ID() == NetworkPolicyAdapterID {
				continue
			}
			verifier, ok := adapter.(RollbackVerifier)
			wg, wgOriginal := adapter.(*WARPWireGuardAdapter)
			wgOriginal = wgOriginal && activeWGScope != nil && activeWGScope.adapterOwner == wg
			if !ok && !wgOriginal {
				verified = false
				consumersVerified = false
				continue
			}
			var confirmed bool
			err := run(rollbackCtx, adapter, "verify-rollback", func(c context.Context, p Plan, root string) error {
				var err error
				if ok {
					confirmed, err = verifier.VerifyRollback(c, p, root)
				} else {
					confirmed, err = m.verifyOriginalWGPreEffect(c, p, wg, activeWGScope)
				}
				return errors.Join(err, c.Err())
			})
			if err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
			verified = verified && confirmed && err == nil
			consumersVerified = consumersVerified && confirmed && err == nil
			if wgOriginal {
				wgConsumerVerified = confirmed && err == nil
			}
		}
		// Original resource owners must first get their bounded rollback and
		// independent readback opportunity. Pending metadata cannot itself
		// prevent exact cleanup; it still prevents removing the LAN boundary.
		resourceErr := validateExecutionResources(execution, true)
		rollbackErr = errors.Join(rollbackErr, resourceErr)
		verified = verified && resourceErr == nil
		consumersVerified = consumersVerified && resourceErr == nil
		gateVerified := false
		if gate != nil {
			if liveMutation && !consumersVerified {
				// A successful rollback call alone cannot authorize removing the
				// physical negative boundary beneath an unknown consumer.
				rollbackErr = errors.Join(rollbackErr, run(rollbackCtx, gate, "rollback", func(context.Context, Plan, string) error { return ErrNetworkPolicyConsumers }))
				verified = false
			} else {
				rollbackErr = errors.Join(rollbackErr, run(rollbackCtx, gate, "rollback", gate.Rollback))
				verifier, ok := gate.(RollbackVerifier)
				if !ok {
					rollbackErr = errors.Join(rollbackErr, ErrNetworkPolicyConsumers)
					verified = false
				} else {
					var confirmed bool
					err := run(rollbackCtx, gate, "verify-rollback", func(c context.Context, p Plan, root string) error {
						var err error
						confirmed, err = verifier.VerifyRollback(c, p, root)
						return errors.Join(err, c.Err())
					})
					rollbackErr = errors.Join(rollbackErr, err)
					gateVerified = confirmed && err == nil
					verified = verified && confirmed && err == nil && rollbackErr == nil
				}
			}
		}
		if !liveMutation && consumersVerified && gateVerified && rollbackErr == nil {
			if original, ok := gate.(*NetworkPolicyAdapter); ok {
				var completionErr error
				noEffectNFQCompletion, completionErr = original.preEffectNFQCompletion(rollbackCtx, plan, filepath.Join(transactionRoot, NetworkPolicyAdapterID))
				rollbackErr = errors.Join(rollbackErr, completionErr)
			}
		}
		execution.RollbackVerified = verified
		if activeWGScope != nil && wgConsumerVerified && consumersVerified && gateVerified && rollbackErr == nil {
			if !liveMutation && gateVerified {
				var completionErr error
				noEffectWGCompletion, completionErr = m.preEffectWGCompletion(rollbackCtx, plan, activeWGScope)
				rollbackErr = errors.Join(rollbackErr, completionErr)
			}
			activeWGScope.mu.Lock()
			activeWGScope.wgCleanupJoined = rollbackErr == nil
			activeWGScope.mu.Unlock()
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
		finalErr := errors.Join(executionJournalError(m.recordLocked(plan)), writeExecution())
		if finalErr != nil {
			noEffectNFQCompletion = nil
			noEffectWGCompletion = nil
			if activeWGScope != nil {
				activeWGScope.mu.Lock()
				activeWGScope.wgCleanupJoined = false
				activeWGScope.mu.Unlock()
			}
			execution.RollbackVerified = false
			rollbackErr = errors.Join(rollbackErr, finalErr)
			execution.State, plan.State = "rollback-failed", "rollback-failed"
			execution.Error += "; persist rollback: " + finalErr.Error()
			plan.Note = execution.Error
			// Best effort to correct whichever record remains writable. The
			// first failure still prevents a success result or another Apply.
			rollbackErr = errors.Join(rollbackErr, executionJournalError(m.recordLocked(plan)), writeExecution())
		}
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		return cause
	}
	retryNFQRollback = func(parent context.Context) error {
		rollbackParent = parent
		_ = rollback(ErrNFQWSScopedOwner)
		if execution.State != "rolled-back" || !execution.RollbackVerified && noEffectNFQCompletion == nil {
			return executionJournalError(ErrNFQWSScopedOwner)
		}
		return nil
	}
	retryXrayRollback = func(parent context.Context) error {
		rollbackParent = parent
		_ = rollback(ErrXrayOperationOwner)
		if execution.State != "rolled-back" || !execution.RollbackVerified {
			return executionJournalError(ErrXrayOperationOwner)
		}
		return nil
	}
	retryWGRollback = func(parent context.Context) error {
		rollbackParent = parent
		_ = rollback(ErrWGOperationOwner)
		if execution.State != "rolled-back" || !execution.RollbackVerified && noEffectWGCompletion == nil {
			return executionJournalError(ErrWGOperationOwner)
		}
		return nil
	}
	rejectCanary := func(cause error) error {
		plan.Ready = false
		plan.State = "canary-failed"
		plan.ObservedEvidence = evidence.None
		for index := range plan.RouteEvidence {
			plan.RouteEvidence[index].Observed = evidence.None
		}
		plan.Note = cause.Error()
		execution.Error = cause.Error()
		execution.State = "canary-failed"
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return errors.Join(cause, executionJournalError(m.recordLocked(plan)), writeExecution())
	}
	rejectNetwork := func(cause error) error {
		plan.Ready, plan.State = false, "network-stale"
		plan.ObservedEvidence = evidence.None
		for index := range plan.RouteEvidence {
			plan.RouteEvidence[index].Observed = evidence.None
		}
		plan.Note = cause.Error()
		execution.State, execution.Error = "network-stale", cause.Error()
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return errors.Join(cause, executionJournalError(m.recordLocked(plan)), writeExecution())
	}
	fail := func(cause error) error {
		if !liveMutation {
			if errors.Is(cause, ErrNetworkChanged) {
				return rejectNetwork(cause)
			}
			if errors.Is(cause, ErrReviewChanged) {
				return rejectCanary(cause)
			}
			var preflight preflightRefusalError
			if errors.As(cause, &preflight) {
				return rejectCanary(cause)
			}
			if plan.RequiresNetworkProof() && (errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded)) {
				return rejectCanary(cause)
			}
		}
		return rollback(cause)
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		return execution, fail(err)
	}
	finishCommit := func() error {
		execution.State = "committing"
		if activeXrayScope != nil {
			if err := activeXrayScope.prepareActiveXray(ctx); err != nil {
				return rollback(err)
			}
		}
		if activeNFQScope != nil {
			if err := activeNFQScope.prepareActiveNFQWS(ctx); err != nil {
				return rollback(err)
			}
		}
		if err := writeExecution(); err != nil {
			return rollback(err)
		}
		commitPublicationAttempted = true
		if err := m.recordLocked(plan); err != nil {
			return rollback(executionJournalError(err))
		}
		execution.State = "committed"
		execution.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := writeExecution(); err != nil {
			return rollback(err)
		}
		if activeNFQScope != nil {
			if err := m.retainActiveNFQWS(ctx, activeNFQScope); err != nil {
				return rollback(err)
			}
		}
		if activeXrayScope != nil {
			if err := m.retainActiveXray(ctx, activeXrayScope); err != nil {
				return rollback(err)
			}
		}
		if activeWGScope != nil {
			if err := m.retainOriginalWG(activeWGScope.contextWith(ctx), activeWGScope, nil); err != nil {
				return rollback(err)
			}
		}
		m.finishRetainedSingRequest(ctx, plan, execution)
		return nil
	}

	if plan.Noop {
		if commit != nil {
			var err error
			liveMutation = true
			undoCommit, err = commit()
			if err != nil {
				return execution, rollback(err)
			}
		}
		if err := m.checkPlanNetwork(ctx, plan); err != nil {
			return execution, fail(err)
		}
		plan.State = "committed"
		err := finishCommit()
		return execution, err
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
	adapters = networkPolicyGateFirst(adapters)
	retiringAdapters = networkPolicyGateLast(retiringAdapters)
	allPrepared := append(append([]Adapter(nil), retiringAdapters...), adapters...)
	allPrepared = networkPolicyGateFirst(allPrepared)
	for _, adapter := range allPrepared {
		snapshot := adapter.Snapshot
		if owner, ok := adapter.(interface {
			snapshotRetiring(context.Context, Plan, Plan, string) error
		}); ok && slices.Contains(plan.RetiringAdapters, adapter.ID()) {
			previous, exists, err := m.committedLocked()
			if err != nil || !exists {
				return execution, fail(errors.Join(err, ErrReviewChanged))
			}
			if previous.SuspendDNS && plan.DiscardDNS {
				if discardedDNSPrior == nil {
					return execution, fail(ErrReviewChanged)
				}
				previous = *discardedDNSPrior
			}
			snapshot = func(c context.Context, p Plan, root string) error {
				return owner.snapshotRetiring(c, p, previous, root)
			}
		}
		if err := run(ctx, adapter, "snapshot", snapshot); err != nil {
			return execution, fail(err)
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
				return execution, fail(err)
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
			if validateExecutionResources(execution, true) != nil {
				return execution, rollback(err)
			}
			// CanaryAdapter owns and removes only its isolated candidate. Calling
			// the live Rollback method here could unnecessarily interrupt the
			// still-working process even though Activate has not started.
			if errors.Is(err, ErrNetworkChanged) {
				return execution, rejectNetwork(err)
			}
			return execution, rejectCanary(err)
		}
	}
	for _, adapter := range adapters {
		if adapter.ID() == NetworkPolicyAdapterID {
			if err := run(ctx, adapter, "activate", adapter.Activate); err != nil {
				return execution, fail(err)
			}
		}
	}
	for _, adapter := range retiringAdapters {
		deactivator := adapter.(RuntimeDeactivator)
		if err := run(ctx, adapter, "deactivate", func(runCtx context.Context, _ Plan, _ string) error {
			return deactivator.Deactivate(runCtx)
		}); err != nil {
			return execution, fail(err)
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
			if phase.name == "activate" && adapter.ID() == NetworkPolicyAdapterID {
				continue
			}
			if err := run(ctx, adapter, phase.name, phase.call(adapter)); err != nil {
				return execution, fail(err)
			}
		}
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		return execution, fail(err)
	}
	for _, adapter := range retiringAdapters {
		if committer, ok := adapter.(RetirementCommitter); ok {
			if err := run(ctx, adapter, "commit-adapter", committer.CommitRetirement); err != nil {
				return execution, fail(err)
			}
		}
	}
	if activeNFQScope != nil {
		if commit == nil {
			return execution, fail(ErrNFQWSScopedOwner)
		}
		if err := activeNFQScope.beginNFQWSTransfer(ctx); err != nil {
			return execution, fail(err)
		}
	}
	if commit != nil {
		var err error
		liveMutation = true
		undoCommit, err = commit()
		if err != nil {
			return execution, rollback(fmt.Errorf("commit desired state: %w", err))
		}
	}
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		return execution, fail(err)
	}
	if activeNFQScope != nil {
		if err := activeNFQScope.commitNFQWSTransfer(ctx); err != nil {
			return execution, fail(err)
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
	if err := m.checkPlanNetwork(ctx, plan); err != nil {
		return execution, fail(err)
	}
	err := finishCommit()
	return execution, err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	owned, err := ownedfs.Open(parent)
	if err != nil {
		return fmt.Errorf("open dataplane transaction directory: %w", err)
	}
	defer owned.Close()
	return owned.WriteAtomic(filepath.Base(path), data, mode)
}
