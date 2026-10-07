//go:build linux

package dataplane

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// Opt-in extension of the already active scoped native fixture. Only review,
// WAN identity and the local TLS CA are fixture allowances: Manager issuance,
// owner identity, assigned source, kernel effects, common receipts and HTTPS
// all use their real implementations. This is no Internet/router/HIL claim.
func nativeScopedXrayManagerTransit(t *testing.T, ctx context.Context, a *ProxyTunnelAdapter, active Plan, roots *x509.CertPool, expectedExit string) error {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("RAZVILKA_XRAY_TUN_NATIVE") != "1" ||
		os.Getenv("RAZVILKA_XRAY_TUN_ROLE") != "router" || os.Getenv("RAZVILKA_NODE_TRANSIT_MANAGER_NATIVE") != "1" || roots == nil {
		return errors.New("Manager transit requires its explicit owned native fixture role and CA")
	}
	if _, err := nativeRouterHTTPSNamespace(); err != nil {
		return err
	}
	fixtureRoot := os.Getenv("RAZVILKA_XRAY_TUN_ROOT")
	if !filepath.IsAbs(fixtureRoot) || a == nil || a.ID() != "xray" || filepath.Clean(a.StateRoot) != filepath.Join(fixtureRoot, "router-state", "xray") {
		return errors.New("Manager transit requires the actual fixture adapter")
	}
	registered := a
	if registered.scopedXray || !registered.xrayPlanDispatch || !registered.nodeRouterVerifier {
		return errors.New("Manager transit requires the ordinary app Xray dispatcher")
	}
	view, frozen, err := registered.dispatchCurrentXrayPlan(ctx, active)
	if err != nil || view == registered || !view.scopedXray || view.xrayPlanDispatch || !view.nodeRouterVerifier {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	a, active = view, frozen
	if _, err := a.checkScopedNodeState(ctx, active); err != nil {
		return err
	}
	state, exists, err := a.loadPolicy()
	if err != nil || !exists {
		return errors.Join(ErrNodeTransitUnavailable, err)
	}
	if err := a.verifyCommittedReceipt(ctx, state); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(a.TunnelCIDR)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(a.Interface)
	if err != nil {
		return err
	}
	// Bind the actual active intent to a private execution identity. Routes are
	// unchanged, so the existing manifest remains the independent owner check.
	encoded, err := json.Marshal(active)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	plan := active
	plan.SchemaVersion, plan.Ready, plan.State = SchemaVersion, true, "committed"
	plan.Digest = hex.EncodeToString(sum[:])
	plan.PlanID, plan.Adapters = "dp-"+plan.Digest[:16], []string{a.ID()}
	m := New(filepath.Join(fixtureRoot, "manager-transit-state"))
	m.FreshProfile = func(c context.Context) (string, error) { return plan.NetworkProfileID, c.Err() }
	if err := m.Register(registered); err != nil {
		return err
	}
	if err := m.Record(plan); err != nil {
		return err
	}
	boot, err := a.currentBootIdentity()
	if err != nil {
		return err
	}
	runtimeID, err := a.scopedRuntimeIdentity()
	if err != nil {
		return err
	}
	generation, err := a.nodeRouterPolicyGeneration(ctx, state, "")
	if err != nil {
		return err
	}
	spec := NodeTransitSpec{Schema: 1, Engine: a.ID(), BootID: boot, PlanID: plan.PlanID, PlanDigest: plan.Digest,
		NetworkProfile: plan.NetworkProfileID, RuntimeID: runtimeID, PolicyGeneration: generation,
		Interface: iface.Name, IfIndex: iface.Index, Source: prefix.Addr(), Destination: netip.MustParseAddr(nativeXrayHTTPSIP), Table: a.Table}
	for _, owner := range NodeTransitOwnershipSpecs() {
		if owner.Engine == spec.Engine && owner.Interface == spec.Interface && owner.Table == spec.Table {
			spec.Priority = owner.Priority
		}
	}
	owner, err := a.nodeTransitRuntimeFor(ctx, spec)
	if err != nil {
		return err
	}
	service := nativeRouterHTTPSService("https://service.example/probe", expectedExit)
	predicate, err := newProxyServicePredicate(service)
	if err != nil {
		return err
	}
	request := nodeRouterHTTPSRequest{URL: service.ProbeURL, ServiceID: service.ID, Predicate: predicate,
		Interface: spec.Interface, IfIndex: spec.IfIndex, Source: spec.Source, Destination: spec.Destination}
	guard := func(c context.Context) error {
		if err := owner.guard(c, spec); err != nil {
			return err
		}
		if _, err := a.checkScopedNodeState(c, active); err != nil {
			return err
		}
		return c.Err()
	}
	reviewed := WithReviewGuard(ctx, guard)
	checkPath := func(c context.Context) error {
		if err := guard(c); err != nil {
			return err
		}
		if err := nodeRouterReturnPath(c, spec.Interface); err != nil {
			return err
		}
		manifest, err := a.checkScopedNodeState(c, active)
		if err != nil {
			return err
		}
		if !nodeRouterPinInScope(spec.Destination, manifest.Requests[0].Destinations) {
			return ErrNodeEndpointChanged
		}
		return a.nodeRouterBackendDisjoint(c, manifest, spec.Source, spec.Destination)
	}
	if err := checkPath(reviewed); err != nil {
		return err
	}
	var accepted nodeRouterHTTPSResult
	err = m.WithExecutionResources(reviewed, plan, a.ID(), func(c context.Context) (resultErr error) {
		lease, registration, _, operation, err := nativeManagerTransitIssue(m, c, spec, owner)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(operation), 10*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, nativeManagerTransitRemove(cleanup, lease, registration))
		}()
		if err := lease.Apply(operation); err != nil {
			return err
		}
		if _, err := nativeManagerTransitJournal(m, spec, "prepared"); err != nil {
			return err
		}
		status, err := lease.Inspect(operation)
		if err != nil || !status.Complete || status.Unknown || status.Removed {
			return errors.Join(errors.New("actual common receipt did not acknowledge the native add"), err)
		}
		if err := lease.VerifyRoute(operation); err != nil {
			return err
		}
		if err := checkPath(operation); err != nil {
			return err
		}
		accepted, err = runNodeRouterHTTPSProbe(operation, request, nodeRouterHTTPSOptions{roots: roots})
		if err != nil {
			return err
		}
		body, _ := json.Marshal(map[string]any{"ip": expectedExit, "accepted": true})
		body = append(body, '\n')
		digest := sha256.Sum256(body)
		if !accepted.ServiceAccepted || accepted.Origin != nodeRouterHTTPSOrigin || accepted.Interface != spec.Interface || accepted.IfIndex != spec.IfIndex ||
			accepted.Source.Addr() != spec.Source || accepted.Source.Port() == 0 || accepted.Destination != netip.AddrPortFrom(spec.Destination, 443) ||
			accepted.ServiceID != service.ID || accepted.ProbeID != service.Probes[0].ID || accepted.PredicateHash != predicate.digest() ||
			accepted.HTTPStatus != 200 || accepted.BodySHA256 != hex.EncodeToString(digest[:]) || accepted.BodyBytes != len(body) ||
			accepted.StartedAt.IsZero() || accepted.FinishedAt.Before(accepted.StartedAt) {
			return errors.New("Manager native transit did not prove actual owned TUN HTTPS and expected body")
		}
		if err := lease.VerifyRoute(operation); err != nil {
			return err
		}
		return checkPath(operation)
	})
	if err != nil {
		return err
	}
	positive, err := nativeManagerTransitJournal(m, spec, "removed")
	if err != nil || positive.State != "temporary-complete" || positive.Steps[0].State != "passed" {
		return errors.Join(errors.New("Manager did not publish a successful removed native resource"), err)
	}
	if err := nativeManagerTransitCollision(reviewed, m, plan, spec, owner); err != nil {
		return err
	}
	if err := nativeManagerTransitCancelled(reviewed, m, plan, spec, owner); err != nil {
		return err
	}
	committed, exists, err := m.Committed()
	if err != nil || !exists || !reflect.DeepEqual(committed, plan) {
		return errors.Join(errors.New("temporary Manager transit changed its committed fixture plan"), err)
	}
	if err := New(m.StateRoot).CheckExecutionRecovery(ctx); err != nil {
		return err
	}
	t.Logf("actual Manager transit: RPDB add/readback/route, owned TUN HTTPS exit=%s body SHA256=%s, common removed receipt + IPv4/IPv6 absence, paired prepared->removed journals; IPv6 foreign collision refused; cancelled original scope cannot add", expectedExit, accepted.BodySHA256)
	return nil
}

// The native lifecycle seals the real service predicate before materializing
// each candidate. A and B keep distinct immutable intents for exact rollback.
func nativeXrayDispatcherPlan(plan Plan, expectedExit string) (Plan, error) {
	plan.Routes = cloneNetworkPolicyRoutes(plan.Routes)
	if len(plan.Routes) != 1 {
		return Plan{}, ErrNetworkPolicyProbe
	}
	service := nativeRouterHTTPSService(plan.Routes[0].ProbeURL, expectedExit)
	plan.Routes[0].ProbeService = &service
	if _, err := FrozenProbeService(plan.Routes[0]); err != nil {
		return Plan{}, err
	}
	plan.SchemaVersion, plan.Ready, plan.State = SchemaVersion, true, "prepared"
	plan.PlanID, plan.Digest, plan.Adapters = "", "", []string{"xray"}
	raw, err := json.Marshal(plan)
	if err != nil {
		return Plan{}, err
	}
	sum := sha256.Sum256(raw)
	plan.Digest = hex.EncodeToString(sum[:])
	plan.PlanID = "dp-" + plan.Digest[:16]
	return plan, nil
}

// Only the fixture's reviewed intent, WAN identity and local TLS CA are supplied.
// Manager issues, journals, verifies and settles the real temporary resources;
// the action still calls the registered dispatcher's public lifecycle method.
func nativeXrayDispatcherExecution(ctx context.Context, registered *ProxyTunnelAdapter, plan Plan, action func(context.Context) error) error {
	if registered == nil || registered.scopedXray || !registered.xrayPlanDispatch || !registered.nodeRouterVerifier || action == nil {
		return ErrNodeTransitUnavailable
	}
	if _, _, err := registered.dispatchCandidateXrayPlan(plan, "", false); err != nil {
		return err
	}
	m := New(filepath.Join(os.Getenv("RAZVILKA_XRAY_TUN_ROOT"), "dispatcher-manager-state"))
	m.FreshProfile = registered.FreshProfile
	if err := m.Register(registered); err != nil {
		return err
	}
	reviewed := WithReviewGuard(ctx, func(c context.Context) error {
		if registered.scopedXray || !registered.xrayPlanDispatch || !registered.nodeRouterVerifier {
			return ErrReviewChanged
		}
		return verifyNetworkProfile(c, plan.NetworkProfileID, registered.FreshProfile)
	})
	return m.WithExecutionResources(reviewed, plan, registered.ID(), action)
}

func nativeManagerTransitIssue(m *Manager, ctx context.Context, spec NodeTransitSpec, owner nodeTransitRuntime) (*nodeTransitLease, nodeTransitRegistration, *nodeRouterTransitReadback, context.Context, error) {
	readback := &nodeRouterTransitReadback{spec: spec, owner: func(c context.Context) error { return owner.guard(c, spec) }}
	observed := func(c context.Context, got NodeTransitSpec, root, digest string, mode networkPolicyTransitReadbackMode) error {
		if mode == networkPolicyTransitPrepared {
			if _, err := nativeManagerTransitJournal(m, spec, "prepared"); err != nil {
				return err
			}
			if err := nativeManagerTransitNoReceipt(root); err != nil {
				return err
			}
		}
		return readback.readback(c, got, root, digest, mode)
	}
	operation := context.WithValue(ctx, networkPolicyTransitReadbackKey{}, networkPolicyTransitReadback(observed))
	issuer, ok := operation.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
	if !ok || issuer == nil {
		return nil, nodeTransitRegistration{}, nil, operation, ErrNodeTransitUnavailable
	}
	registration, err := issuer(operation, spec)
	if err != nil {
		return nil, registration, nil, operation, err
	}
	owner.register = registration.register
	lease, err := newNodeTransitLease(spec, registration.root, owner)
	if err != nil {
		return nil, registration, nil, operation, err
	}
	readback.root, readback.lease = registration.root, lease
	readback.info, err = os.Lstat(registration.root)
	return lease, registration, readback, operation, err
}

func nativeManagerTransitRemove(ctx context.Context, lease *nodeTransitLease, registration nodeTransitRegistration) error {
	if err := registration.cleanupGuard(ctx); err != nil {
		return err
	}
	if err := lease.Remove(ctx); err != nil {
		return err
	}
	status, err := nodeTransitReadEffects(ctx, lease.plan, lease.root, lease.options.boot)
	if err != nil || !status.Removed || status.Unknown {
		return errors.Join(errors.New("native transit common removed receipt is unavailable"), err)
	}
	count, err := lease.presence(ctx) // The actual implementation reads both families.
	if err != nil || count != 0 {
		return errors.Join(errors.New("native transit kernel absence is unavailable"), err)
	}
	return registration.settle(ctx, lease.spec, lease.root, lease.digest)
}

func nativeManagerTransitJournal(m *Manager, spec NodeTransitSpec, resourceState string) (Execution, error) {
	var latest, transaction *Execution
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "latest-execution.json"), &latest); err != nil || !found || latest == nil {
		return Execution{}, errors.Join(ErrExecutionJournal, err)
	}
	if found, err := readOptionalJournal(filepath.Join(m.StateRoot, "transactions", latest.PlanID, "execution.json"), &transaction); err != nil || !found || !reflect.DeepEqual(latest, transaction) ||
		latest.ResourcePlanID != spec.PlanID || latest.Digest != spec.PlanDigest || len(latest.Resources) != 1 || latest.Resources[0].State != resourceState ||
		latest.Resources[0].NodeTransit == nil || *latest.Resources[0].NodeTransit != spec {
		return Execution{}, errors.Join(ErrExecutionJournal, err)
	}
	return *latest, validateExecutionResources(*latest, resourceState != "prepared")
}

func nativeManagerTransitNoReceipt(root string) error {
	for _, name := range []string{policyAdditionFile, policyAdditionLock} {
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(errors.New("before-effects native refusal created a common receipt/lock"), err)
		}
	}
	return nil
}

func nativeManagerTransitCollision(ctx context.Context, m *Manager, plan Plan, spec NodeTransitSpec, owner nodeTransitRuntime) (resultErr error) {
	// This exact foreign IPv6 tuple belongs only to the newly created router
	// fixture namespace. Its acknowledged add grants only its exact deletion.
	args := func(verb string) []string {
		return []string{"-6", "rule", verb, "priority", strconv.Itoa(spec.Priority), "from", "::1/128", "lookup", "254"}
	}
	if _, err := owner.runner.Run(ctx, owner.ip, args("add")...); err != nil {
		return err
	}
	foreign := true
	defer func() {
		if foreign {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer cancel()
			_, err := owner.runner.Run(cleanup, owner.ip, args("del")...)
			resultErr = errors.Join(resultErr, err)
		}
	}()
	err := m.WithExecutionResources(ctx, plan, spec.Engine, func(c context.Context) error {
		lease, registration, readback, operation, err := nativeManagerTransitIssue(m, c, spec, owner)
		if err != nil {
			return err
		}
		refusal := lease.Apply(operation)
		if !errors.Is(refusal, ErrNodeTransitUnavailable) || !isNodeTransitBeforeEffects(refusal) {
			return errors.Join(errors.New("real foreign IPv6 RPDB slot did not refuse before effects"), refusal)
		}
		if err := nativeManagerTransitNoReceipt(lease.root); err != nil {
			return err
		}
		lines, err := readPolicyRules(operation, numericPolicyReadRunner{base: owner.runner}, owner.ip, 6)
		if err != nil {
			return err
		}
		count := 0
		for _, line := range lines {
			if priority, ok := policyLinePriority(line); ok && priority == spec.Priority {
				rule, exact := parseKernelPolicyRule(6, line)
				if !exact || rule.source != "::1/128" || rule.destination != "::/0" || rule.table != 254 || rule.ingress != "" || rule.managed {
					return errors.New("native transit changed the exact foreign IPv6 fixture tuple")
				}
				count++
			}
		}
		if count != 1 {
			return errors.New("native transit altered the foreign IPv6 fixture rule")
		}
		// Never retry an uncertain ACK. The outer namespace cleanup retains
		// authority over this fixture namespace if exact deletion fails.
		foreign = false
		if _, err := owner.runner.Run(operation, owner.ip, args("del")...); err != nil {
			return err
		}
		if err := lease.VerifyUnused(operation); err != nil {
			return err
		}
		if !errors.As(refusal, &readback.unused) {
			return ErrNodeTransitUnavailable
		}
		return registration.settleUnused(operation, spec, lease.root, lease.digest)
	})
	if err != nil {
		return err
	}
	_, err = nativeManagerTransitJournal(m, spec, "unused")
	return err
}

func nativeManagerTransitCancelled(ctx context.Context, m *Manager, plan Plan, spec NodeTransitSpec, owner nodeTransitRuntime) error {
	original, cancel := context.WithCancel(ctx)
	defer cancel()
	checked := false
	err := m.WithExecutionResources(original, plan, spec.Engine, func(c context.Context) error {
		lease, _, _, operation, err := nativeManagerTransitIssue(m, c, spec, owner)
		if err != nil {
			return err
		}
		cancel()
		detached, stop := context.WithTimeout(context.WithoutCancel(operation), 5*time.Second)
		defer stop()
		issuer := detached.Value(nodeTransitRegistrarKey{}).(nodeTransitRegistrar)
		if _, err := issuer(detached, spec); !errors.Is(err, context.Canceled) {
			return fmt.Errorf("cancelled native original scope renewed its issuer: %w", err)
		}
		if err := lease.Apply(detached); !errors.Is(err, context.Canceled) || !isNodeTransitBeforeEffects(err) {
			return errors.Join(errors.New("cancelled original scope allowed a detached native lease add"), err)
		}
		if err := nativeManagerTransitNoReceipt(lease.root); err != nil {
			return err
		}
		count, err := lease.presence(detached)
		if err != nil || count != 0 {
			return errors.Join(errors.New("cancelled native scope left a late IPv4/IPv6 rule"), err)
		}
		checked = true
		return nil
	})
	if !checked || !errors.Is(err, context.Canceled) {
		return errors.Join(errors.New("native original-cancellation assertion did not finish"), err)
	}
	return nil
}
