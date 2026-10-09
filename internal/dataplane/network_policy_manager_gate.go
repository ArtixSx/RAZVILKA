package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const NetworkPolicyAdapterID = "lan-policy"

var ErrNetworkPolicyConsumers = errors.New("network policy consumers have not independently settled")
var ErrNetworkPolicyReplacement = errors.New("LAN generation replacement requires a verified shared cutover")

// NetworkPolicyAdapter owns only the shared LAN participant of the existing
// Manager. Binding is a concrete mixed-receipt owner; its guards/RetireCheck
// must inspect actual admission and every consumer. No independent worker or
// execution journal is created here.
type NetworkPolicyAdapter struct {
	StateRoot string
	Binding   *LANPolicyReceiptBinding
	identity  *networkPolicyIdentity
	// InventoryCheck must inspect the complete owned gate namespace, including
	// orphan generations. An absent owner file alone cannot prove inactivity.
	InventoryCheck func(context.Context) error
}

type networkPolicyGateState struct {
	Schema           int                   `json:"schema"`
	NetworkIdentity  *netidentity.Identity `json:"network_identity,omitempty"`
	PlanID           string                `json:"plan_id"`
	Digest           string                `json:"digest"`
	LAN              *LANPolicyRuntimePlan `json:"lan"`
	Promoted         bool                  `json:"promoted"`
	PromotionPending bool                  `json:"promotion_pending,omitempty"`
}

type networkPolicyGateSnapshot struct {
	Prior *networkPolicyGateState `json:"prior"`
}

func (a *NetworkPolicyAdapter) ID() string { return NetworkPolicyAdapterID }

func (a *NetworkPolicyAdapter) bindStateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return ErrLANPolicyRuntime
	}
	expected := filepath.Join(root, NetworkPolicyAdapterID)
	if a.StateRoot != "" && filepath.Clean(a.StateRoot) != expected {
		return ErrLANPolicyRuntime
	}
	a.StateRoot = expected
	return nil
}

func (a *NetworkPolicyAdapter) check() error {
	if a == nil || a.StateRoot == "" || a.Binding == nil || a.Binding.Runtime == nil ||
		a.Binding.ApplyGuard == nil || a.Binding.CleanupGuard == nil || a.Binding.RetireCheck == nil {
		return ErrLANPolicyRuntime
	}
	return nil
}

func networkPolicyGateFor(p Plan) (*networkPolicyGateState, error) {
	lan, err := p.FrozenLAN()
	if err != nil || !validExecutionPlanID(p.PlanID) || !validNetworkPolicyGeneration(p.Digest) {
		return nil, errors.Join(err, ErrLANPolicyRuntime)
	}
	return &networkPolicyGateState{Schema: 1, PlanID: p.PlanID, Digest: p.Digest, LAN: lan}, nil
}

func (a *NetworkPolicyAdapter) ownerPath() string { return filepath.Join(a.StateRoot, "owner.json") }

func (a *NetworkPolicyAdapter) receiptRoot(s *networkPolicyGateState) (string, error) {
	if err := a.check(); err != nil {
		return "", err
	}
	if !a.gateIdentityMatches(s) || s.Promoted && s.PromotionPending || !validExecutionPlanID(s.PlanID) || !validNetworkPolicyGeneration(s.Digest) || ValidateLANPolicyRuntime(s.LAN) != nil {
		return "", ErrLANPolicyRuntime
	}
	if s.Promoted {
		return filepath.Join(a.StateRoot, "receipts", s.PlanID), nil
	}
	return filepath.Join(filepath.Dir(a.StateRoot), "transactions", s.PlanID, NetworkPolicyAdapterID), nil
}

func (a *NetworkPolicyAdapter) readOwner() (*networkPolicyGateState, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	var state *networkPolicyGateState
	exists, err := readOptionalJournal(a.ownerPath(), &state)
	if err != nil || !exists {
		return nil, err
	}
	if _, err := a.receiptRoot(state); err != nil {
		return nil, err
	}
	return state, nil
}

func writeNetworkPolicyGate(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 1<<20 {
		return errors.Join(err, ErrLANPolicyRuntime)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return writeDataplaneJournal(path, data)
}

func (a *NetworkPolicyAdapter) clearOwner(expected *networkPolicyGateState) error {
	current, err := a.readOwner()
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.Join(err, ErrReviewChanged)
	}
	if current == nil {
		return nil
	}
	root, err := openJournalDirectory(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove("owner.json"); err != nil {
		return err
	}
	return syncDataplaneJournalDirectory(root)
}

func (a *NetworkPolicyAdapter) Snapshot(ctx context.Context, p Plan, root string) error {
	if _, err := a.gateFor(p); err != nil {
		return preflightRefusalError{err}
	}
	prior, err := a.readOwner()
	if err != nil {
		return err
	}
	if prior != nil {
		return preflightRefusalError{ErrNetworkPolicyReplacement}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeNetworkPolicyGate(filepath.Join(root, "snapshot.json"), networkPolicyGateSnapshot{})
}

func (a *NetworkPolicyAdapter) Stage(ctx context.Context, p Plan, root string) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	state, err := a.gateFor(p)
	if err != nil {
		return preflightRefusalError{err}
	}
	if err := a.check(); err != nil {
		return preflightRefusalError{err}
	}
	if err := a.Binding.Runtime.Preflight(ctx, state.LAN); err != nil {
		return preflightRefusalError{err}
	}
	return writeNetworkPolicyGate(filepath.Join(root, "candidate.json"), state)
}

func (a *NetworkPolicyAdapter) Validate(ctx context.Context, p Plan, root string) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	state, err := a.gateFor(p)
	if err != nil {
		return err
	}
	var candidate *networkPolicyGateState
	if found, err := readOptionalJournal(filepath.Join(root, "candidate.json"), &candidate); err != nil || !found || !reflect.DeepEqual(candidate, state) {
		return errors.Join(err, ErrReviewChanged)
	}
	return a.Binding.Runtime.Preflight(ctx, state.LAN)
}

func (a *NetworkPolicyAdapter) Activate(ctx context.Context, p Plan, root string) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	state, err := a.gateFor(p)
	if err != nil {
		return err
	}
	if a.identity != nil {
		if err := a.identity.check(ctx); err != nil {
			return err
		}
	}
	expected, err := a.receiptRoot(state)
	if err != nil || expected != filepath.Clean(root) {
		return errors.Join(err, ErrLANPolicyRuntime)
	}
	prior, err := a.readOwner()
	if err != nil || prior != nil {
		return preflightRefusalError{errors.Join(err, ErrNetworkPolicyReplacement)}
	}
	// Retain typed intent before receipt/effect creation. A crash can no longer
	// turn a missing manifest into permission to ignore a pending generation.
	if err := writeNetworkPolicyGate(a.ownerPath(), state); err != nil {
		return err
	}
	return a.Binding.Apply(ctx, state.LAN, root)
}

func (a *NetworkPolicyAdapter) Health(ctx context.Context, p Plan, root string) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	want, err := a.gateFor(p)
	if err != nil {
		return err
	}
	state, err := a.readOwner()
	if err != nil || !reflect.DeepEqual(state, want) {
		return errors.Join(err, ErrReviewChanged)
	}
	status, err := a.Binding.Inspect(ctx, state.LAN, root)
	if err != nil || !status.Complete || status.Removed || status.Unknown || status.Promoted {
		return errors.Join(err, ErrPolicyAdditionReceipt)
	}
	return a.Binding.Runtime.Verify(ctx, state.LAN)
}

func (a *NetworkPolicyAdapter) Commit(ctx context.Context, p Plan, root string) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	if err := a.Health(ctx, p, root); err != nil {
		return err
	}
	state, _ := a.gateFor(p)
	state.Promoted = true
	destination, err := a.receiptRoot(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	// Keep both compiler-derived roots during the transition. A guard can
	// definitely refuse BEFORE promotion while the source still owns the grant.
	state.Promoted, state.PromotionPending = false, true
	if err := writeNetworkPolicyGate(a.ownerPath(), state); err != nil {
		return err
	}
	if err := a.Binding.Promote(ctx, state.LAN, root, destination); err != nil {
		return err
	}
	state.Promoted, state.PromotionPending = true, false
	return writeNetworkPolicyGate(a.ownerPath(), state)
}

func (a *NetworkPolicyAdapter) cleanupReceiptRoot(ctx context.Context, state *networkPolicyGateState) (string, error) {
	source, err := a.receiptRoot(state)
	if err != nil || !state.PromotionPending {
		return source, err
	}
	destinationState := *state
	destinationState.Promoted, destinationState.PromotionPending = true, false
	destination, err := a.receiptRoot(&destinationState)
	if err != nil {
		return "", err
	}
	// Only the existing active source ACK (or known cleanup) plus a destination
	// with NO receipt proves a pre-promotion refusal. Any intent/copy/unknown retains
	// both references and fences cleanup; absence alone supplies no grant.
	status, err := a.Binding.Inspect(ctx, state.LAN, source)
	if err != nil || !status.Complete && !status.Removed || status.Unknown || status.Promoted {
		return "", errors.Join(err, ErrPolicyAdditionUnknown)
	}
	if _, err := os.Lstat(filepath.Join(destination, policyAdditionFile)); !errors.Is(err, os.ErrNotExist) {
		return "", errors.Join(err, ErrPolicyAdditionUnknown)
	}
	return source, ctx.Err()
}

func (a *NetworkPolicyAdapter) inspectAbsent(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	if err := a.check(); err != nil {
		return err
	}
	if lan != nil && lanPolicyDirectMode(lan.Mode) {
		// Direct preparation has no COMMON effects to iterate. Missing files
		// still require original retained cleanup, settled consumers and fresh
		// complete namespace/RPDB absence before the exact owner can be cleared.
		if a.InventoryCheck == nil {
			return ErrRuntimeInactivity
		}
		if err := a.Binding.directGuard(ctx, lan, true); err != nil {
			return err
		}
		if err := a.Binding.RetireCheck(ctx, CloneLANPolicyRuntime(lan)); err != nil {
			return err
		}
		if err := a.InventoryCheck(ctx); err != nil {
			return err
		}
		if err := a.Binding.Runtime.inspectDirectRPDB(ctx); err != nil {
			return err
		}
		return a.Binding.directGuard(ctx, lan, true)
	}
	effects, err := lan.Effects()
	if err != nil {
		return err
	}
	for _, effect := range effects {
		count, foreign, err := a.Binding.Runtime.InspectEffect(ctx, lan, effect)
		if err != nil || foreign || count != 0 {
			return errors.Join(err, ErrLANPolicyRuntime)
		}
	}
	return ctx.Err()
}

func (a *NetworkPolicyAdapter) Rollback(ctx context.Context, p Plan, root string) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	want, err := a.gateFor(p)
	if err != nil {
		return err
	}
	current, err := a.readOwner()
	if err != nil {
		return err
	}
	if current == nil {
		return a.inspectAbsent(ctx, want.LAN)
	}
	want.Promoted = current.Promoted
	want.PromotionPending = current.PromotionPending
	if !reflect.DeepEqual(current, want) {
		return ErrReviewChanged
	}
	receipt, err := a.cleanupReceiptRoot(ctx, current)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(receipt, policyAdditionFile)); errors.Is(err, os.ErrNotExist) {
		// No receipt means no deletion grant. Exact absence can settle a
		// registered intent that failed before the first receipt was written.
		if err := a.inspectAbsent(ctx, current.LAN); err != nil {
			return err
		}
	} else {
		if err != nil {
			return err
		}
		if err := a.Binding.Remove(ctx, current.LAN, receipt); err != nil {
			return err
		}
	}
	return a.clearOwner(current)
}

func (a *NetworkPolicyAdapter) VerifyRollback(ctx context.Context, p Plan, root string) (bool, error) {
	ctx = networkPolicyConsumerContext(ctx, p)
	state, err := a.gateFor(p)
	if err != nil {
		return false, err
	}
	owner, err := a.readOwner()
	if err != nil || owner != nil {
		return false, errors.Join(err, ErrLANPolicyRuntime)
	}
	err = a.inspectAbsent(ctx, state.LAN)
	return err == nil, err
}

func (a *NetworkPolicyAdapter) Deactivate(ctx context.Context) error {
	state, err := a.readOwner()
	if err != nil {
		return err
	}
	if state == nil {
		return a.VerifyRuntimeInactive(ctx)
	}
	root, err := a.cleanupReceiptRoot(ctx, state)
	if err != nil {
		return err
	}
	if err := a.Binding.Remove(ctx, state.LAN, root); err != nil {
		return err
	}
	return a.clearOwner(state)
}

func (a *NetworkPolicyAdapter) VerifyRuntimeInactive(ctx context.Context) error {
	state, err := a.readOwner()
	if err != nil || state != nil || a.InventoryCheck == nil {
		return errors.Join(err, ErrRuntimeInactivity)
	}
	return errors.Join(ctx.Err(), a.InventoryCheck(ctx), ctx.Err())
}

func (a *NetworkPolicyAdapter) Reconcile(ctx context.Context, p Plan) error {
	ctx = networkPolicyConsumerContext(ctx, p)
	want, err := a.gateFor(p)
	if err != nil {
		return err
	}
	want.Promoted = true
	state, err := a.readOwner()
	if err != nil || !reflect.DeepEqual(state, want) {
		return errors.Join(err, ErrReviewChanged)
	}
	root, err := a.receiptRoot(state)
	if err != nil {
		return err
	}
	status, err := a.Binding.Inspect(ctx, state.LAN, root)
	if err != nil || !status.Complete || status.Removed || status.Unknown || status.Promoted {
		return errors.Join(err, ErrPolicyAdditionReceipt)
	}
	// A new boot never adopts a stale receipt or applies a retained command.
	return a.Binding.Runtime.Verify(ctx, state.LAN)
}
