package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

type mihomoSameBootIntent struct {
	Schema                       int `json:"schema"`
	Before, After, Configuration []byte
	Plans                        map[string][]byte
	RuntimeBefore                mihomoColdRuntimeArchive
	Candidate                    map[string][]byte `json:"candidate,omitempty"`
}
type mihomoSameBootRetirementCursor struct {
	self                                    *mihomoSameBootRetirementCursor
	manager                                 *Manager
	ctx                                     context.Context
	owner                                   *mihomoSameBootCleanup
	archive                                 *mihomoSameBootArchive
	history                                 *updatecheck.ExecutionHistoryAdmission
	plans                                   []*mihomoColdRecord
	intent                                  mihomoSameBootIntent
	effectProxy                             *ProxyTunnelAdapter
	sidecarDone, policyDone, forwardingDone bool
	runtimeAfter                            *mihomoColdRuntimeArchive
	finalTree                               *mihomoSameBootStatic
	home                                    *mihomoColdHomeArchive
	terminal                                Execution
	closed                                  bool
	closeErr, unknown                       error
	retryArchive                            string
	retryTerminal                           int // Slot+1, only SAME retained authored writer ACK.
	terminalPending                         [2]bool
	terminalCloseErr                        error
	terminalFault                           func(int) error // Refusal-only AFTER original publication ACK.
}

// RetireMihomoLiveSameBoot is explicit offline maintenance under the five
// original private callbacks, actual startup source, fresh cleanup Gate and
// trusted caller's configured control root. It never constructs a warm owner.
// The original active execution remains an updater recovery fence through
// every native effect and archive freeze; effects are irrevocably disabled
// before the first terminal publication. Any close/unknown result clears the
// returned terminal acknowledgment.
func (m *Manager) RetireMihomoLiveSameBoot(ctx context.Context, id, digest string, set *privaterestore.OfflineServiceControlSet, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, controlRoot string, history *updatecheck.ExecutionHistoryAdmission) (result Execution, resultErr error) {
	resultErr = m.WithMihomoSameBootRetirement(ctx, id, digest, set, control, cleanup, controlRoot, history, func(original context.Context, h *MihomoSameBootRetirement) error {
		var err error
		result, err = h.Run(original)
		return err
	})
	if resultErr != nil {
		result = Execution{}
	}
	return result, resultErr
}

// This synchronous original cursor owns Manager.operation through Close. It
// is never rebuilt from serialized data and cannot outlive the five private
// callback lifetimes. The public CLI connection waits for native acceptance.
func (m *Manager) prepareMihomoSameBootRetirement(ctx context.Context, id, digest string, set *privaterestore.OfflineServiceControlSet, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, controlRoot string, history *updatecheck.ExecutionHistoryAdmission) (_ *mihomoSameBootRetirementCursor, resultErr error) {
	stage := "prepare-context"
	defer func() { resultErr = mihomoSameBootStageError(stage, resultErr) }()
	if err := xraySelectedTCPFinite(ctx); err != nil {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	if m == nil || control == nil || cleanup == nil || history == nil || !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot || !control.MatchesControlRoot(controlRoot) {
		return nil, ErrMihomoLiveRetirement
	}
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	c := &mihomoSameBootRetirementCursor{manager: m, ctx: ctx, history: history}
	c.self = c
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	if m.retainedNFQOwner() != nil || m.retainedXrayOwner() != nil || m.retainedWGOwner() != nil || m.HasPendingManagedNFQWS() || m.HasPendingMihomoLive() || m.originalMihomoLive() != nil {
		return nil, ErrMihomoLiveRetirement
	}
	stage = "prepare-inputs"
	i, err := holdMihomoSameBootInputs(ctx, set, m.StateRoot, id, digest)
	if err != nil {
		return nil, err
	}
	c.owner = &mihomoSameBootCleanup{inputs: i, control: control, cleanup: cleanup, controlRoot: controlRoot}
	c.owner.self = c.owner
	stage = "prepare-proxy"
	a, _, err := m.mihomoColdProxy(ctx)
	if err != nil {
		return nil, err
	}
	read, ok := a.Runner.(*mihomoColdReadRunner)
	if !ok {
		return nil, ErrMihomoLiveRetirement
	}
	c.owner.read = read
	if err := c.beforeSidecar(); err != nil {
		return nil, err
	}
	stage = "prepare-runtime"
	before, err := readMihomoColdRuntime(i.roots[0], "mihomo", a)
	if err != nil || !before.Present {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	if err := validateMihomoColdRuntime(a, i.definition, before); err != nil {
		return nil, err
	}
	stage = "prepare-static"
	c.owner.static, err = holdMihomoSameBootStatic(ctx, i, a, before)
	if err != nil {
		return nil, err
	}
	if err := c.beforeSidecar(); err != nil {
		return nil, err
	}
	stage = "prepare-runtime-closing"
	closing, err := readMihomoColdRuntime(i.roots[0], "mihomo", a)
	if err != nil {
		return nil, err
	}
	first, _ := json.Marshal(before)
	second, _ := json.Marshal(closing)
	if !bytes.Equal(first, second) {
		return nil, ErrMihomoLiveRetirement
	}
	c.intent = mihomoSameBootIntent{Schema: 1, Before: bytes.Clone(i.records[0].data), Configuration: bytes.Clone(i.records[2].data), RuntimeBefore: before, Plans: map[string][]byte{}}
	stage = "prepare-policy"
	if i.candidate {
		if _, err := holdMihomoSameBootCandidatePolicy(ctx, c.owner); err != nil {
			return nil, err
		}
		c.intent.Candidate = map[string][]byte{}
		for _, r := range append([]*mihomoColdRecord{c.owner.policy.marker, c.owner.policy.record}, c.owner.policy.candidatePins...) {
			c.intent.Candidate[r.name] = bytes.Clone(r.data)
		}
	} else {
		binding, present, err := a.readPolicyBinding(i.definition.Policy)
		if err != nil || !present || binding.Phase != "active" {
			return nil, errors.Join(ErrPolicyAdditionUnknown, err)
		}
		if _, err := holdMihomoSameBootPolicy(ctx, c.owner, binding.Generation, before); err != nil {
			return nil, err
		}
	}
	stage = "prepare-plans"
	for _, name := range mihomoStoppedPlanNames {
		r, err := openMihomoColdRecord(i.roots[0], name, nil)
		if errors.Is(err, os.ErrNotExist) && name == "latest-committed-plan.json" {
			continue
		}
		if err != nil {
			return nil, err
		}
		c.plans = append(c.plans, r)
		c.intent.Plans[name] = bytes.Clone(r.data)
	}
	if err := validateMihomoColdPlans(i.definition.Plan, c.intent.Plans); err != nil {
		return nil, err
	}
	stage = "prepare-terminal"
	c.terminal, err = mihomoLiveRetirementTerminal(i.before, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	c.intent.After, err = json.Marshal(c.terminal)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(c.intent)
	if err != nil || len(encoded) > bootRetirementLimit {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	if err := history.CheckWrite(ctx, 8); err != nil {
		return nil, err
	}
	stage = "prepare-archive"
	c.archive, err = newMihomoSameBootArchive(i)
	if err != nil {
		return nil, err
	}
	stage = "prepare-effect-proxy"
	c.effectProxy, err = NewProxyTunnelAdapter("mihomo", nil, m.StateRoot)
	if err != nil {
		return nil, err
	}
	p := c.effectProxy
	p.Runner, p.IP, p.IPTables, p.IP6Tables = c.owner, a.IP, a.IPTables, a.IP6Tables
	p.EngineBin, p.SidecarKind, p.SidecarBin = a.EngineBin, a.SidecarKind, a.SidecarBin
	p.Interface, p.Table, p.Priority, p.SOCKSPort = a.Interface, a.Table, a.Priority, a.SOCKSPort
	if err := c.beforeSidecar(); err != nil {
		return nil, err
	}
	if err := installMihomoSameBootNativeACKCut(ctx, c); err != nil {
		return nil, err
	}
	keep = true
	return c, nil
}

// Parent-gone plus exact same network identity precede even a pidfd signal.
// No controller or interface absence is inferred from serialized metadata.
func (c *mihomoSameBootRetirementCursor) beforeSidecar() error {
	if c != nil && c.unknown != nil {
		return errors.Join(ErrMihomoLiveRetirement, c.unknown)
	}
	return c.originalInputsCurrent()
}

func (c *mihomoSameBootRetirementCursor) originalInputsCurrent() error {
	if c == nil || c.self != c || c.closed || c.owner == nil || c.owner.read == nil {
		return errors.Join(ErrMihomoLiveRetirement, sameBootRetirementError(c))
	}
	if c.terminalCloseErr != nil {
		return errors.Join(ErrMihomoLiveRetirement, c.terminalCloseErr)
	}
	o := c.owner
	if o.inputs.configPath != o.read.original.settings || o.inputs.statePath != o.read.original.root {
		return ErrMihomoLiveRetirement
	}
	if err := errors.Join(o.inputs.current(o.inputs.ctx), o.read.current(c.ctx), o.control.CurrentForCleanupOperation(c.ctx, o.cleanup)); err != nil {
		return err
	}
	if o.static != nil && !o.effectsClosed {
		if err := o.static.current(); err != nil {
			return err
		}
	}
	if o.policy != nil && !o.effectsClosed {
		if err := o.policy.currentRoot(); err != nil {
			return err
		}
	}
	for _, r := range c.plans {
		if err := r.current(); err != nil {
			return err
		}
	}
	return o.read.tools.Provider.WithCurrent(c.ctx, func(held context.Context, identity netidentity.Identity) error {
		if identity != o.inputs.definition.NetworkIdentity {
			return ErrMihomoLiveRetirement
		}
		if err := components.ObserveMihomoProbeParentGone(held, o.inputs.definition.Source.ParentOrigin); err != nil {
			return err
		}
		return errors.Join(o.inputs.current(o.inputs.ctx), o.control.CurrentForCleanupOperation(held, o.cleanup))
	})
}
func sameBootRetirementError(c *mihomoSameBootRetirementCursor) error {
	if c != nil {
		return errors.Join(c.unknown, c.closeErr)
	}
	return nil
}

func (c *mihomoSameBootRetirementCursor) run() (Execution, error) {
	if err := c.beforeSidecar(); err != nil {
		return Execution{}, err
	}
	if err := c.history.CheckWrite(c.ctx, 8); err != nil {
		return Execution{}, err
	}
	if err := c.publishArchive("retirement.json", c.intent, c.beforeSidecar); err != nil {
		return Execution{}, err
	}
	if err := mihomoSameBootNativeStage(c.ctx, c, "intent", c.beforeSidecar); err != nil {
		return Execution{}, err
	}
	o := c.owner
	if !c.sidecarDone {
		if err := stopMihomoSameBootSidecar(c.ctx, o); err != nil {
			c.unknown = c.sidecarFailureAfterAttempt(err)
			return Execution{}, c.unknown
		}
		c.sidecarDone = true
	}
	if err := o.current(c.ctx); err != nil {
		return Execution{}, err
	}
	current := func() error { return o.current(c.ctx) }
	if err := mihomoSameBootNativeStage(c.ctx, c, "sidecar", current); err != nil {
		return Execution{}, err
	}
	if !c.policyDone {
		if o.policy == nil {
			return Execution{}, ErrPolicyAdditionUnknown
		}
		policyCtx := context.WithValue(c.ctx, mihomoSameBootPolicyKey{}, o.policy)
		if err := removePolicyAddition(policyCtx, o, c.effectProxy.ip(), o.inputs.definition.Policy, o.policy.path, c.effectProxy.additionOptions()); err != nil {
			return Execution{}, err
		}
		status, err := c.effectProxy.additionStatus(policyCtx, o.inputs.definition.Policy, o.policy.path)
		if err != nil || !status.Removed || status.Unknown {
			return Execution{}, errors.Join(ErrPolicyAdditionUnknown, err)
		}
		c.policyDone = true
	}
	if err := mihomoSameBootNativeStage(c.ctx, c, "policy", current); err != nil {
		return Execution{}, err
	}
	if !c.forwardingDone {
		lease, present, err := c.effectProxy.readForwardingLease()
		if err != nil || !present || !reflect.DeepEqual(lease.Policy, o.inputs.definition.Policy) {
			return Execution{}, errors.Join(ErrProxyPolicyUnknown, err)
		}
		if err := removeMihomoSameBootForwarding(c.ctx, o, c.effectProxy, lease); err != nil {
			return Execution{}, err
		}
		c.forwardingDone = true
	}
	kernelAbsent := func() error { _, err := o.absent(c.ctx); return err }
	if err := mihomoSameBootNativeStage(c.ctx, c, "forwarding", kernelAbsent); err != nil {
		return Execution{}, err
	}
	if _, err := o.absent(c.ctx); err != nil {
		return Execution{}, err
	}
	if c.home == nil {
		home, err := observeMihomoSameBootHome(c.ctx, o)
		if err != nil {
			return Execution{}, err
		}
		c.home = &home
	}
	if c.runtimeAfter == nil {
		after, err := readMihomoColdRuntime(o.inputs.roots[0], "mihomo", o.read.proxy)
		if err != nil {
			return Execution{}, err
		}
		if err := validateMihomoColdRuntime(o.read.proxy, o.inputs.definition, after); err != nil {
			return Execution{}, err
		}
		c.runtimeAfter = &after
	}
	absent := func() error {
		if err := c.beforeSidecar(); err != nil {
			return err
		}
		if _, err := o.absent(c.ctx); err != nil {
			return err
		}
		return c.homeCurrent()
	}
	if err := c.publishArchive("runtime-history", struct {
		Schema  int
		Runtime mihomoColdRuntimeArchive
		Home    *mihomoColdHomeArchive
	}{1, *c.runtimeAfter, c.home}, absent); err != nil {
		return Execution{}, err
	}
	if !o.effectsClosed {
		// This is irreversible revocation, not a process or cleanup ACK. All
		// native cleanup and complete absence already succeeded above.
		o.effectsClosed = true
		// Original read descriptors stay held through the no-replace move and
		// terminal ACKs. Closing them now would allow inode reuse to imitate a
		// member of the archived tree. Close joins every ACK before releasing
		// the Manager operation or the outer five private lifetimes.
	}
	if c.finalTree == nil {
		var err error
		c.finalTree, err = holdMihomoSameBootTree(c.ctx, o.inputs, o.read.proxy, *c.runtimeAfter, true)
		if err != nil {
			return Execution{}, err
		}
	}
	if err := moveMihomoColdRuntime(o.inputs.roots[0], c.archive.root, o.read.proxy, *c.runtimeAfter, absent, nil); err != nil {
		return Execution{}, err
	}
	if err := c.finalTree.currentAt(c.archive.root, "runtime"); err != nil {
		return Execution{}, err
	}
	terminalCurrent := func() error {
		return errors.Join(absent(), c.finalTree.currentAt(c.archive.root, "runtime"), checkMihomoColdRuntimePair(o.inputs.roots[0], c.archive.root, o.read.proxy, *c.runtimeAfter))
	}
	if err := mihomoSameBootNativeStage(c.ctx, c, "archive", terminalCurrent); err != nil {
		return Execution{}, err
	}
	for n := range 2 {
		if bytes.Equal(o.inputs.records[n].data, c.intent.After) && !c.terminalPending[n] {
			continue
		}
		if err := terminalCurrent(); err != nil {
			return Execution{}, err
		}
		if err := c.history.CheckWrite(c.ctx, 8); err != nil {
			return Execution{}, err
		}
		if err := c.publishTerminal(n, terminalCurrent); err != nil {
			return Execution{}, err
		}
		stage := "terminal-transaction"
		if n == 1 {
			stage = "terminal-global"
		}
		if err := mihomoSameBootNativeStage(c.ctx, c, stage, terminalCurrent); err != nil {
			return Execution{}, err
		}
	}
	if err := c.publishArchive("completed.json", struct {
		Schema                    int
		BeforeSHA256, AfterSHA256 string
	}{1, nodeDefaultSourceMaterialHash(c.intent.Before), nodeDefaultSourceMaterialHash(c.intent.After)}, terminalCurrent); err != nil {
		return Execution{}, err
	}
	if err := terminalCurrent(); err != nil {
		return Execution{}, err
	}
	return c.terminal, nil
}

func (c *mihomoSameBootRetirementCursor) homeCurrent() error {
	if c.home == nil {
		return ErrMihomoLiveRetirement
	}
	observed, err := observeMihomoSameBootHome(c.ctx, c.owner)
	if err != nil {
		return err
	}
	before, e1 := json.Marshal(c.home)
	after, e2 := json.Marshal(observed)
	if e1 != nil || e2 != nil || !bytes.Equal(before, after) {
		return errors.Join(ErrMihomoLiveRetirement, e1, e2)
	}
	return nil
}
func (c *mihomoSameBootRetirementCursor) close() error {
	if c == nil || c.self != c {
		return ErrMihomoLiveRetirement
	}
	if !c.closed {
		c.closed = true
		if c.owner != nil {
			if c.owner.sidecar != nil {
				c.closeErr = errors.Join(c.closeErr, c.owner.sidecar.close())
			}
			if c.owner.policy != nil {
				c.closeErr = errors.Join(c.closeErr, c.owner.policy.close())
			}
			if c.owner.static != nil {
				c.closeErr = errors.Join(c.closeErr, c.owner.static.close())
			}
		}
		if c.finalTree != nil {
			c.closeErr = errors.Join(c.closeErr, c.finalTree.close())
		}
		if c.archive != nil {
			c.closeErr = errors.Join(c.closeErr, c.archive.close())
		}
		for _, r := range c.plans {
			c.closeErr = errors.Join(c.closeErr, r.file.Close())
		}
		if c.owner != nil && c.owner.inputs != nil {
			c.closeErr = errors.Join(c.closeErr, c.owner.inputs.close())
		}
		c.manager.endOperation()
	}
	return errors.Join(c.closeErr, c.terminalCloseErr)
}
