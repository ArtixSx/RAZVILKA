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
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrRetainedSingReview = errors.New("original committed Sing-box read-only review unavailable")

const retainedSingBudget = 8 * time.Second

// RetainedSingAvailability is separate from the full Apply result. A committed
// execution with Code=unavailable has still committed: callers must not retry
// Apply to obtain a review. This reader grants no delta, skip, health or cleanup.
type RetainedSingAvailability struct {
	Code   string
	Stage  string // Fixed internal coordinate, never arbitrary cause text.
	Review *RetainedSingReview
}

type retainedSingCaptureFailure struct {
	stage string
	cause error
}

func (e *retainedSingCaptureFailure) Error() string {
	return "retained Sing-box snapshot refused at " + e.stage
}
func (e *retainedSingCaptureFailure) Unwrap() error { return e.cause }

type retainedSingRequestKey struct{}
type retainedSingRequest struct {
	manager *Manager
	plan    Plan
	proof   retainedSingProof
	result  RetainedSingAvailability
	used    bool
}

// Only private package models can replace these observations. The public
// wrapper always uses the existing actual launch-receipt verifier and actual
// process namespaces. No observer/callback is accepted from an App or request.
type retainedSingProof struct {
	process   func(ProcessSpec) (retainedSingProcess, error)
	namespace func(ProcessSpec) (string, error)
}

type retainedSingProcess struct {
	identity   routeidentity.Receipt
	executable os.FileInfo
}

// ApplyWithRetainedSingReview is an explicit preparation primitive: it runs
// the SAME complete Apply, including all adapters, service checks and rollback.
// Only this opt-in pays for a post-commit runtime snapshot. No App uses it yet.
// The ordinary Apply path only revokes an older reader and performs no reads.
func (m *Manager) ApplyWithRetainedSingReview(ctx context.Context, plan Plan, commit func() (func() error, error)) (Execution, RetainedSingAvailability, error) {
	return m.applyWithRetainedSingReview(ctx, plan, commit, retainedSingProof{retainedSingProcessIdentity, retainedSingNamespace})
}

func (m *Manager) applyWithRetainedSingReview(ctx context.Context, plan Plan, commit func() (func() error, error), proof retainedSingProof) (Execution, RetainedSingAvailability, error) {
	unavailable := RetainedSingAvailability{Code: "unavailable", Stage: "request"}
	if ctx == nil || ctx.Err() != nil || m == nil || !retainedSingPlanShape(plan) || proof.process == nil || proof.namespace == nil {
		return Execution{}, unavailable, ErrRetainedSingReview
	}
	r := &retainedSingRequest{manager: m, plan: cloneExecutionResourcePlan(plan), proof: proof, result: unavailable}
	execution, err := m.Apply(context.WithValue(ctx, retainedSingRequestKey{}, r), cloneExecutionResourcePlan(plan), commit)
	if err != nil || execution.State != "committed" {
		if r.result.Review != nil {
			_ = r.result.Review.Close()
		}
		return execution, unavailable, err
	}
	return execution, r.result, nil
}

func retainedSingPlanShape(p Plan) bool {
	if p.SchemaVersion != SchemaVersion || !validPlanID(p.PlanID) || !validPlanDigest(p.Digest) || !p.Ready || p.SafeMode || p.Noop || !systemprobe.ValidWANProfileID(p.NetworkProfileID) ||
		p.LAN != nil || p.DNS != nil || p.DomainPolicy != nil || p.SyntheticDNS != nil || p.SuspendDNS || p.DiscardDNS || len(p.EngineDrafts) != 0 || len(p.RetiringAdapters) != 0 || len(p.ResourceConflicts) != 0 || len(p.Blockers) != 0 || len(p.Routes) == 0 || len(p.Routes) > 32 {
		return false
	}
	seen, sing := map[string]bool{}, false
	for _, id := range p.Adapters {
		if seen[id] || id != "sing-box" && id != "nfqws2" {
			return false
		}
		seen[id], sing = true, sing || id == "sing-box"
	}
	if !sing || len(p.Adapters) > 2 {
		return false
	}
	sing = false
	for _, r := range p.Routes {
		id := adapterID(r.Resolved)
		if r.ServiceID == "" || !seen[id] || r.NetworkPolicyGeneration != "" || r.NetworkPolicyRole != "" {
			return false
		}
		sing = sing || id == "sing-box"
	}
	return sing
}

// Called only after the original full Apply has independently published both
// committed records. Snapshot failure affects availability, never the already
// successful Apply outcome and never invokes another phase or rollback.
func (m *Manager) finishRetainedSingRequest(ctx context.Context, p Plan, e Execution) {
	r, _ := ctx.Value(retainedSingRequestKey{}).(*retainedSingRequest)
	if r == nil || r.manager != m || r.used || r.plan.PlanID != p.PlanID || r.plan.Digest != p.Digest || !slices.Equal(r.plan.Adapters, p.Adapters) || !reflect.DeepEqual(r.plan.Routes, p.Routes) {
		return
	}
	r.used = true
	if e.State != "committed" || p.State != "committed" || !retainedSingPlanShape(p) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, retainedSingBudget)
	defer cancel()
	review, err := m.captureRetainedSing(ctx, p, e, r.proof)
	if err != nil {
		var failure *retainedSingCaptureFailure
		if errors.As(err, &failure) {
			r.result.Stage = failure.stage
		}
		return
	}
	m.retainedSingMu.Lock()
	m.retainedSing = review
	m.retainedSingMu.Unlock()
	r.result = RetainedSingAvailability{Code: "available", Review: review}
}

func (m *Manager) revokeRetainedSingReview() {
	m.retainedSingMu.Lock()
	r := m.retainedSing
	m.retainedSing = nil
	m.retainedSingMu.Unlock()
	if r != nil {
		_ = r.Close()
	}
}

type retainedSingFile struct {
	info os.FileInfo
	hash string
}
type retainedSingRoot struct {
	path string
	root *ownedfs.Root
	info os.FileInfo
}

// RetainedSingReview is process-local, bound to the original full successful
// Manager/Proxy commit. It has no mutation/health methods and no serializable
// capability. The App/Store/catalog layer and delta execution do not exist yet.
type RetainedSingReview struct {
	self       *RetainedSingReview
	mu         sync.Mutex
	closed     bool
	manager    *Manager
	managerDir string
	adapter    *ProxyTunnelAdapter
	frozen     ProxyTunnelAdapter
	registry   uint64
	plan       Plan
	execution  Execution
	policy     PolicyState
	binding    proxyPolicyBinding
	boot       string
	engine     ProcessSpec
	sidecar    ProcessSpec
	namespace  string
	proof      retainedSingProof
	profile    func(context.Context) (string, error)
	roots      []retainedSingRoot
	files      map[string]retainedSingFile
	processes  map[string]retainedSingProcess
}

func (*RetainedSingReview) String() string   { return "[original Sing-box read-only review]" }
func (*RetainedSingReview) GoString() string { return "[original Sing-box read-only review]" }

func (m *Manager) captureRetainedSing(ctx context.Context, p Plan, e Execution, proof retainedSingProof) (_ *RetainedSingReview, resultErr error) {
	stage := "adapter"
	defer func() {
		if resultErr != nil {
			resultErr = &retainedSingCaptureFailure{stage, resultErr}
		}
	}()
	m.registryMu.RLock()
	a, ok := m.Adapters["sing-box"].(*ProxyTunnelAdapter)
	registry := m.registryGeneration
	m.registryMu.RUnlock()
	if !ok || a == nil || a.ID() != "sing-box" || a.StateRoot != filepath.Join(m.StateRoot, "sing-box") || a.scopedXray || a.xrayPlanDispatch || a.xrayOperation || a.valid() != nil {
		return nil, ErrRetainedSingReview
	}
	r := &RetainedSingReview{manager: m, managerDir: m.StateRoot, adapter: a, frozen: *a, registry: registry,
		proof: proof, profile: m.FreshProfile, files: map[string]retainedSingFile{}, processes: map[string]retainedSingProcess{}}
	planBytes, err := json.Marshal(p)
	if err != nil || json.Unmarshal(planBytes, &r.plan) != nil {
		return nil, ErrRetainedSingReview
	}
	executionBytes, err := json.Marshal(e)
	if err != nil || json.Unmarshal(executionBytes, &r.execution) != nil {
		return nil, ErrRetainedSingReview
	}
	r.self = r
	defer func() {
		if resultErr != nil {
			_ = r.Close()
		}
	}()
	stage = "boot"
	r.boot, err = a.currentBootIdentity()
	if err != nil || !kernelBootIDPattern.MatchString(r.boot) {
		return nil, ErrRetainedSingReview
	}
	stage = "policy"
	policyRoot, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return nil, ErrRetainedSingReview
	}
	_, policyData, err := retainedSingReadOwned(policyRoot, filepath.Base(a.policyPath()), 8<<20)
	var journal proxyPolicyJournal
	if err != nil || json.Unmarshal(policyData, &journal) != nil || journal.AdditionReceiptVersion != 1 {
		_ = policyRoot.Close()
		return nil, ErrRetainedSingReview
	}
	r.policy = journal.PolicyState
	if validPolicyLayout(r.policy) != nil || r.policy.Interface != a.Interface || r.policy.Table != a.Table || r.policy.PriorityBase != a.Priority || r.policy.RuleLayout != 2 || r.policy.NetworkPolicyGeneration != "" || r.policy.Forwarding == nil || len(effectivePolicyRules(r.policy)) == 0 || len(effectivePolicyRules(r.policy)) > 4 {
		_ = policyRoot.Close()
		return nil, ErrRetainedSingReview
	}
	stage = "policy-binding"
	_, bindingData, err := retainedSingReadOwned(policyRoot, filepath.Base(a.policyBindingPath()), 4096)
	closeErr := policyRoot.Close()
	decoder := json.NewDecoder(bytes.NewReader(bindingData))
	decoder.DisallowUnknownFields()
	if err != nil || closeErr != nil || decoder.Decode(&r.binding) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrRetainedSingReview
	}
	canonicalBinding, _ := json.Marshal(r.binding)
	if !bytes.Equal(bindingData, canonicalBinding) || r.binding.Schema != 1 || r.binding.Engine != a.ID() || r.binding.Digest != proxyPolicyDigest(r.policy) || r.binding.Phase != "active" || r.binding.ReceiptID != r.binding.Generation {
		return nil, ErrRetainedSingReview
	}
	generation, err := a.policyGenerationRoot(r.binding.Generation)
	if err != nil {
		return nil, ErrRetainedSingReview
	}
	transaction := filepath.Join(m.StateRoot, "transactions", p.PlanID)
	stage = "roots"
	for _, path := range []string{m.StateRoot, a.StateRoot, a.runtimeRoot(), transaction, generation} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return nil, ErrRetainedSingReview
		}
		root, err := ownedfs.Open(path)
		if err != nil {
			return nil, ErrRetainedSingReview
		}
		r.roots = append(r.roots, retainedSingRoot{path, root, info})
	}
	stage = "process-intent"
	r.engine, r.sidecar = a.engineProcess(), a.sidecarProcess()
	for _, spec := range []ProcessSpec{r.engine, r.sidecar} {
		if validateProcessSpec(spec) != nil || spec.Dir != a.runtimeRoot() || !filepath.IsAbs(spec.Binary) {
			return nil, ErrRetainedSingReview
		}
	}
	if !r.engine.RouteProof {
		return nil, ErrRetainedSingReview
	}
	paths := []string{filepath.Join(m.StateRoot, "latest-plan.json"), filepath.Join(m.StateRoot, "latest-committed-plan.json"), filepath.Join(m.StateRoot, "latest-execution.json"), filepath.Join(transaction, "execution.json"),
		a.policyPath(), a.policyBindingPath(), a.forwardingPath(), a.engineConfigPath(), a.sidecarConfigPath(), r.engine.PIDPath, r.sidecar.PIDPath, r.engine.PIDPath + routeidentity.ReceiptSuffix,
		filepath.Join(generation, policyAdditionFile), filepath.Join(generation, policyAdditionLock)}
	if r.sidecar.RouteProof {
		paths = append(paths, r.sidecar.PIDPath+routeidentity.ReceiptSuffix)
	}
	stage = "files"
	for _, path := range paths {
		image, err := r.file(path)
		if err != nil {
			return nil, ErrRetainedSingReview
		}
		r.files[path] = image
	}
	stage = "runtime"
	if err := r.observe(ctx, false); err != nil {
		return nil, err
	}
	return r, nil
}

// Current proves preservation of the bound runtime, not that any service works.
// A failed observation permanently revokes this reader. Restoring old bytes,
// reopening journals or reusing a copied handle cannot revive it.
func (r *RetainedSingReview) Current(ctx context.Context, expected Plan) error {
	if r == nil || r.self != r || ctx == nil {
		return ErrRetainedSingReview
	}
	ctx, cancel := context.WithTimeout(ctx, retainedSingBudget)
	defer cancel()
	if err := r.manager.beginOperation(ctx); err != nil {
		return errors.Join(ErrRetainedSingReview, err)
	}
	defer r.manager.endOperation()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !reflect.DeepEqual(expected, r.plan) {
		return ErrRetainedSingReview
	}
	if err := r.observe(ctx, true); err != nil {
		r.closeLocked()
		return errors.Join(ErrRetainedSingReview, err, ctx.Err())
	}
	return nil
}

func (r *RetainedSingReview) observe(ctx context.Context, registered bool) error {
	if ctx.Err() != nil || r.closed || !r.coordinates(registered) {
		return errors.Join(ErrRetainedSingReview, ctx.Err())
	}
	verify := func() error {
		// All four complete original publication images must agree. Use only
		// bounded held-root reads, never legacy unbounded journal openers or
		// a "latest" fallback capable of inventing a committed baseline.
		var latest, committed Plan
		var execution, transaction Execution
		if r.decode(filepath.Join(r.managerDir, "latest-plan.json"), &latest) != nil ||
			r.decode(filepath.Join(r.managerDir, "latest-committed-plan.json"), &committed) != nil ||
			r.decode(filepath.Join(r.managerDir, "latest-execution.json"), &execution) != nil ||
			r.decode(filepath.Join(r.managerDir, "transactions", r.plan.PlanID, "execution.json"), &transaction) != nil ||
			!reflect.DeepEqual(latest, r.plan) || !reflect.DeepEqual(committed, r.plan) || !reflect.DeepEqual(execution, r.execution) || !reflect.DeepEqual(transaction, r.execution) || !r.coordinates(registered) {
			return ErrRetainedSingReview
		}
		if err := verifyNetworkProfile(ctx, r.plan.NetworkProfileID, r.profile); err != nil {
			return err
		}
		boot, err := r.frozen.currentBootIdentity()
		if err != nil || boot != r.boot {
			return ErrRetainedSingReview
		}
		for _, root := range r.roots {
			if root.path != r.managerDir {
				relative, err := filepath.Rel(r.managerDir, root.path)
				if err != nil || r.roots[0].root.Check(relative) != nil {
					return ErrRetainedSingReview
				}
			}
			current, err := os.Lstat(root.path)
			held, heldErr := root.root.RootInfo()
			if err != nil || heldErr != nil || !os.SameFile(current, root.info) || !os.SameFile(held, root.info) || current.Mode() != root.info.Mode() {
				return ErrRetainedSingReview
			}
		}
		for path, before := range r.files {
			after, err := r.file(path)
			if err != nil || !os.SameFile(before.info, after.info) || before.info.Mode() != after.info.Mode() || before.hash != after.hash {
				return ErrRetainedSingReview
			}
		}
		for _, spec := range []ProcessSpec{r.engine, r.sidecar} {
			process, err := r.proof.process(spec)
			if err != nil || process.identity.BootID != r.boot || process.executable == nil {
				return ErrRetainedSingReview
			}
			if original, exists := r.processes[spec.ID]; exists {
				if process.identity != original.identity || !os.SameFile(process.executable, original.executable) {
					return ErrRetainedSingReview
				}
			} else if registered {
				return ErrRetainedSingReview
			} else {
				r.processes[spec.ID] = process
			}
			namespace, err := r.proof.namespace(spec)
			if err != nil || namespace == "" || r.namespace != "" && namespace != r.namespace {
				return ErrRetainedSingReview
			}
			r.namespace = namespace
		}
		return ctx.Err()
	}
	if err := verify(); err != nil {
		return err
	}
	if err := r.checkPolicyReceipt(ctx); err != nil {
		return err
	}
	_, leaseData, err := r.read(r.adapter.forwardingPath())
	var lease proxyForwardingLease
	if err != nil || len(leaseData) > 128<<10 || json.Unmarshal(leaseData, &lease) != nil || lease.Version != 1 || len(lease.Created) > 4 || r.frozen.validateForwarding(lease.Policy, lease.Policy.Forwarding) != nil {
		return ErrRetainedSingReview
	}
	if err := r.frozen.verifyForwardingLease(ctx, r.policy, lease); err != nil {
		return err
	}
	if err := verifyPolicyEvidence(ctx, r.frozen.Runner, r.frozen.ip(), r.policy); err != nil {
		return err
	}
	return verify()
}

func (r *RetainedSingReview) coordinates(registered bool) bool {
	m, a, original := r.manager, r.adapter, &r.frozen
	if r.self != r || m == nil || a == nil || m.StateRoot != r.managerDir || a.StateRoot != original.StateRoot || a.ID() != "sing-box" || a.Configs != original.Configs ||
		!sameNetworkPolicyDependency(a.Runner, original.Runner) || !sameNetworkPolicyDependency(a.Processes, original.Processes) || !reflect.DeepEqual(a.engineProcess(), r.engine) || !reflect.DeepEqual(a.sidecarProcess(), r.sidecar) ||
		a.Interface != original.Interface || a.Table != original.Table || a.Priority != original.Priority || a.SOCKSPort != original.SOCKSPort || a.TunnelCIDR != original.TunnelCIDR || a.IP != original.IP || a.IPTables != original.IPTables || a.IP6Tables != original.IP6Tables || a.SidecarKind != original.SidecarKind || a.scopedXray || a.xrayPlanDispatch || a.xrayOperation {
		return false
	}
	m.registryMu.RLock()
	ok := m.registryGeneration == r.registry && m.Adapters["sing-box"] == a
	m.registryMu.RUnlock()
	if registered {
		m.retainedSingMu.Lock()
		ok = ok && m.retainedSing == r
		m.retainedSingMu.Unlock()
	}
	return ok
}

func (r *RetainedSingReview) file(path string) (retainedSingFile, error) {
	image, _, err := r.read(path)
	return image, err
}

func (r *RetainedSingReview) decode(path string, into any) error {
	_, data, err := r.read(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func (r *RetainedSingReview) read(path string) (retainedSingFile, []byte, error) {
	for _, root := range r.roots {
		if filepath.Dir(path) != root.path {
			continue
		}
		name := filepath.Base(path)
		return retainedSingReadOwned(root.root, name, 8<<20)
	}
	return retainedSingFile{}, nil, ErrRetainedSingReview
}

// Nonblocking open precedes fstat so replacing even a previously regular file
// with a FIFO cannot hang the Manager gate. No file/marker is created here.
func retainedSingReadOwned(root *ownedfs.Root, name string, limit int64) (retainedSingFile, []byte, error) {
	f, err := root.OpenFile(name, retainedSingOpenFlags(false), 0)
	if err != nil {
		return retainedSingFile{}, nil, err
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > limit {
		_ = f.Close()
		return retainedSingFile{}, nil, ErrRetainedSingReview
	}
	data, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return retainedSingFile{}, nil, ErrRetainedSingReview
	}
	return retainedSingFile{info, routeidentity.Hash(data)}, data, nil
}

// The general receipt opener may initialize a missing permanent lock. This
// reader instead opens ONLY an existing marker and uses the pure decoder; a
// missing/changed lock is refusal, never a write or a legacy fallback.
func (r *RetainedSingReview) checkPolicyReceipt(ctx context.Context) error {
	root := r.roots[len(r.roots)-1]
	f, err := root.root.OpenFile(policyAdditionLock, retainedSingOpenFlags(true), 0)
	if err != nil {
		return ErrRetainedSingReview
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, r.files[filepath.Join(root.path, policyAdditionLock)].info) || lockCloudflareScanFile(f) != nil {
		return ErrRetainedSingReview
	}
	defer unlockCloudflareScanFile(f)
	marker, err := io.ReadAll(io.LimitReader(f, int64(len(policyAdditionMarker)+1)))
	if err != nil || string(marker) != policyAdditionMarker {
		return ErrRetainedSingReview
	}
	s := &policyAdditionSession{root: root.root, path: root.path, state: r.policy, options: r.frozen.additionOptions()}
	_, document, err := retainedSingReadOwned(root.root, policyAdditionFile, policyAdditionMaxBytes)
	if err != nil || s.decodeDocument(ctx, document) != nil || s.validatePolicyDocument(ctx) != nil {
		return ErrRetainedSingReview
	}
	status := s.status()
	if !status.Complete || status.Unknown || status.ID != r.binding.ReceiptID {
		return ErrRetainedSingReview
	}
	return nil
}

func (r *RetainedSingReview) Close() error {
	if r == nil {
		return nil
	}
	if r.self != r {
		return ErrRetainedSingReview
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked()
	return nil
}

func (r *RetainedSingReview) closeLocked() {
	if r.closed {
		return
	}
	r.closed = true
	for _, root := range r.roots {
		_ = root.root.Close()
	}
}

func retainedSingNamespace(spec ProcessSpec) (string, error) {
	if runtime.GOOS != "linux" {
		return "", ErrRetainedSingReview
	}
	pid, err := retainedSingPID(spec)
	if err != nil {
		return "", err
	}
	process, processErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "ns/net"))
	self, selfErr := os.Readlink("/proc/self/ns/net")
	if errors.Is(processErr, os.ErrNotExist) && errors.Is(selfErr, os.ErrNotExist) {
		return "no-netns", nil // Same exact older-kernel fallback as routeidentity.
	}
	if processErr != nil || selfErr != nil || process == "" || process != self {
		return "", ErrRetainedSingReview
	}
	return process, nil
}
