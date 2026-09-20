package dataplane

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// A scoped proxy inspection reads the forwarding lease, firewall attachments
// and every admitted source/destination route. On routers this can exceed two
// seconds even with healthy processes; retain a bound without truncating that
// proof or replacing it with a PID/journal-only check.
const runtimePresenceTimeout = 8 * time.Second

// ObserveCommittedRuntime proves present owned runtime, not service reachability.
// Bounded read-only inspection never probes services, switches an endpoint,
// starts a process, repairs state or changes kernel rules.
func (m *Manager) ObserveCommittedRuntime(ctx context.Context, expected Plan) (retErr error) {
	if m == nil || expected.State != "committed" || len(expected.Routes) == 0 {
		return ErrReviewChanged
	}
	ctx, cancel := context.WithTimeout(ctx, runtimePresenceTimeout)
	defer cancel()
	defer func() {
		// Command runners can return only an exit status (or a higher-level
		// ownership error) after cancellation. Preserve the actual observation
		// timeout so consumers do not misreport it as absent/broken runtime.
		if err := ctx.Err(); err != nil {
			retErr = err
		}
	}()
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	verify := func() error {
		current, exists, err := m.Committed()
		if err != nil || !exists || !reflect.DeepEqual(current, expected) {
			return ErrReviewChanged
		}
		return m.checkPlanNetwork(ctx, expected)
	}
	if err := verify(); err != nil {
		return err
	}
	for _, id := range expected.Adapters {
		registered, exists := m.adapter(id)
		if !exists {
			return errors.New("owned runtime adapter unavailable")
		}
		observer, ok := registered.(interface{ observeOwnedRuntime(context.Context) error })
		if !ok {
			return errors.New("owned runtime observation unavailable")
		}
		if err := observer.observeOwnedRuntime(ctx); err != nil {
			return err
		}
	}
	return verify()
}

func (a *ProxyTunnelAdapter) observeOwnedRuntime(ctx context.Context) error {
	if err := a.checkSidecarIdentity(); err != nil {
		return err
	}
	state, exists, err := a.loadPolicy()
	if err != nil || !exists || state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || len(state.Prefixes) == 0 || a.Processes == nil {
		return errors.New("owned proxy policy unavailable")
	}
	if !regularFile(a.engineConfigPath()) || !regularFile(a.sidecarConfigPath()) || !a.Processes.Running(a.engineProcess()) || !a.Processes.Running(a.sidecarProcess()) {
		return errors.New("owned proxy process unavailable")
	}
	if err := a.verifyForwarding(ctx, state); err != nil {
		return err
	}
	return verifyPolicyEvidence(ctx, a.Runner, a.ip(), state)
}

func (a *WARPWireGuardAdapter) observeOwnedRuntime(ctx context.Context) error {
	state, exists, err := a.deactivationOwnership(ctx)
	if err != nil || !exists {
		return errors.New("owned WireGuard policy unavailable")
	}
	active, err := a.deactivationInterfaceActive(ctx)
	if err != nil || !active {
		return errors.New("owned WireGuard interface unavailable")
	}
	return verifyPolicyEvidence(ctx, a.Runner, a.ip(), state)
}

func (a *NFQWS2Adapter) observeOwnedRuntime(ctx context.Context) error {
	lease, err := a.verifyOwnedLists(false)
	if err != nil || lease == nil {
		return errors.New("owned NFQWS2 policy unavailable")
	}
	if err := a.verifyOwnedRuntime(lease, false); err != nil {
		return err
	}
	output, err := a.run(ctx, a.InitPath, "status")
	if err != nil || !runningOutput(string(output)) {
		return errors.New("owned NFQWS2 process unavailable")
	}
	return ctx.Err()
}
