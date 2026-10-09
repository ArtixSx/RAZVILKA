package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// NetworkPolicyChecks is a read-only bridge owned by the existing Manager.
// Bind once at trusted startup, AFTER registering every participant, including
// the typed LAN adapter. The original physical/admission/cleanup guards remain
// mandatory. These checks neither acquire a Manager operation nor grant effects.
type NetworkPolicyChecks struct {
	manager      *Manager
	gate         *NetworkPolicyAdapter
	binding      *LANPolicyReceiptBinding
	runtime      *LANPolicyRuntime
	tools        [3]string
	identity     *networkPolicyIdentity
	network      netidentity.Identity
	root         string
	anchor       os.FileInfo
	owner        *ownedfs.Root
	adapters     map[string]Adapter
	roots        map[string]string
	dependencies map[string][2]any
	proxies      map[string]ProxyTunnelAdapter
	ids          []string
	generation   uint64
	read         func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)
	inventory    *BackendInventory // SAME startup collector, never a supplied capture.
	closed       atomic.Bool
}

// BindNetworkPolicyChecks freezes actual registered instances, their registry
// generation and the existing Manager root. An empty/missing owner never means
// complete inactivity. In startup callback closures, a nil checks receiver
// refuses until this binding succeeds; no lazy first-request binding exists.
func (m *Manager) BindNetworkPolicyChecks(gate *NetworkPolicyAdapter, inventory *BackendInventory) (*NetworkPolicyChecks, error) {
	if inventory == nil || gate == nil || gate.identity == nil || gate.identity.provider == nil || inventory.reader.Provider != gate.identity.provider ||
		gate.Binding == nil || gate.Binding.Runtime == nil || inventory.reader.IPTables != gate.Binding.Runtime.IPTables || inventory.reader.IP6Tables != gate.Binding.Runtime.IP6Tables {
		return nil, ErrNetworkPolicyConsumers
	}
	frozen := *inventory
	c, err := m.bindNetworkPolicyChecks(gate, frozen.Read)
	if err == nil {
		c.inventory = &frozen
	}
	return c, err
}

func (m *Manager) bindNetworkPolicyChecks(gate *NetworkPolicyAdapter, read func(context.Context, netidentity.Identity) (BackendInventorySnapshot, error)) (*NetworkPolicyChecks, error) {
	if m == nil || gate == nil || gate.identity == nil || gate.identity.value.Validate() != nil || read == nil ||
		!filepath.IsAbs(m.StateRoot) || filepath.Clean(m.StateRoot) != m.StateRoot || gate.StateRoot != filepath.Join(m.StateRoot, NetworkPolicyAdapterID) {
		return nil, ErrNetworkPolicyConsumers
	}
	owner, anchor, err := openNetworkPolicyObservationRoot(m.StateRoot)
	if err != nil {
		return nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	if gate.Binding == nil || gate.Binding.Runtime == nil {
		owner.Close()
		return nil, ErrNetworkPolicyConsumers
	}
	r := gate.Binding.Runtime
	c := &NetworkPolicyChecks{manager: m, gate: gate, binding: gate.Binding, runtime: r, tools: [3]string{r.IP, r.IPTables, r.IP6Tables}, identity: gate.identity, network: gate.identity.value, root: m.StateRoot, anchor: anchor, owner: owner, read: read, adapters: map[string]Adapter{}, roots: map[string]string{}, dependencies: map[string][2]any{}, proxies: map[string]ProxyTunnelAdapter{}}
	m.registryMu.RLock()
	c.generation = m.registryGeneration
	for id, adapter := range m.Adapters {
		c.adapters[id] = adapter
		c.roots[id] = networkPolicyAdapterRoot(adapter)
		c.dependencies[id] = networkPolicyAdapterDependencies(adapter)
		if proxy, ok := adapter.(*ProxyTunnelAdapter); ok && proxy != nil {
			c.proxies[id] = *proxy
		}
		if id != NetworkPolicyAdapterID {
			c.ids = append(c.ids, id)
		}
	}
	m.registryMu.RUnlock()
	sort.Strings(c.ids)
	if c.adapters[NetworkPolicyAdapterID] != gate || len(c.ids) == 0 || c.current(context.Background()) != nil {
		c.Close()
		return nil, ErrNetworkPolicyConsumers
	}
	return c, nil
}

// Close revokes future observations; it cannot stop a consumer or remove rules.
func (c *NetworkPolicyChecks) Close() error {
	if c == nil || c.closed.Swap(true) {
		return nil
	}
	return c.owner.Close()
}

func (c *NetworkPolicyChecks) current(ctx context.Context) error {
	if c == nil || c.closed.Load() || ctx == nil || ctx.Err() != nil || c.manager == nil || c.gate == nil || c.gate.identity == nil ||
		c.manager.StateRoot != c.root || c.gate.StateRoot != filepath.Join(c.root, NetworkPolicyAdapterID) || c.gate.identity != c.identity || c.gate.identity.value != c.network ||
		c.gate.Binding != c.binding || c.binding.Runtime != c.runtime || [3]string{c.runtime.IP, c.runtime.IPTables, c.runtime.IP6Tables} != c.tools {
		return errors.Join(ErrNetworkPolicyConsumers, networkPolicyChecksContextError(ctx))
	}
	info, err := os.Lstat(c.root)
	if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(c.anchor, info) {
		return errors.Join(ErrNetworkPolicyConsumers, err)
	}
	c.manager.registryMu.RLock()
	unchanged := c.generation == c.manager.registryGeneration && reflect.DeepEqual(c.adapters, c.manager.Adapters)
	c.manager.registryMu.RUnlock()
	if !unchanged {
		return errors.Join(ErrNetworkPolicyConsumers, ErrReviewChanged)
	}
	for id, adapter := range c.adapters {
		if adapter == nil || reflect.ValueOf(adapter).Kind() == reflect.Pointer && reflect.ValueOf(adapter).IsNil() || adapter.ID() != id || networkPolicyAdapterRoot(adapter) != c.roots[id] {
			return ErrNetworkPolicyConsumers
		}
		actual := networkPolicyAdapterDependencies(adapter)
		for i, original := range c.dependencies[id] {
			if !sameNetworkPolicyDependency(actual[i], original) {
				return ErrNetworkPolicyConsumers
			}
		}
	}
	return nil
}

// Equality here preserves an already bound concrete owner; it issues no grant.
// Function code pointers cannot distinguish closure captures. Such dependencies
// refuse instead of treating a matching code address as an immutable owner.
func sameNetworkPolicyDependency(actual, original any) bool {
	if actual == nil || original == nil {
		return actual == nil && original == nil
	}
	a, b := reflect.ValueOf(actual), reflect.ValueOf(original)
	if a.Kind() == reflect.Pointer && a.IsNil() || b.Kind() == reflect.Pointer && b.IsNil() {
		return false
	}
	return a.Comparable() && b.Comparable() && a.Type() == b.Type() && actual == original
}

func networkPolicyAdapterDependencies(adapter Adapter) [2]any {
	switch a := adapter.(type) {
	case *NetworkPolicyAdapter:
		if a != nil && a.Binding != nil && a.Binding.Runtime != nil {
			return [2]any{a.Binding.Runtime.Runner, nil}
		}
	case *ProxyTunnelAdapter:
		if a != nil {
			return [2]any{a.Runner, a.Processes}
		}
	case *NFQWS2Adapter:
		if a != nil {
			return [2]any{a.Runner, nil}
		}
	case *WARPWireGuardAdapter:
		if a != nil {
			return [2]any{a.Runner, nil}
		}
	case *ScopedDNSAdapter:
		if a != nil {
			return [2]any{a.Runner, nil}
		}
	}
	return [2]any{}
}

func networkPolicyAdapterRoot(adapter Adapter) string {
	switch a := adapter.(type) {
	case *NetworkPolicyAdapter:
		if a != nil {
			return a.StateRoot
		}
	case *ProxyTunnelAdapter:
		if a != nil {
			return a.StateRoot
		}
	case *NFQWS2Adapter:
		if a != nil {
			return a.StateRoot
		}
	case *WARPWireGuardAdapter:
		if a != nil {
			return a.StateRoot
		}
	case *ScopedDNSAdapter:
		if a != nil {
			return a.StateRoot
		}
	}
	return ""
}

func networkPolicyPrivateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (runtime.GOOS == "windows" || info.Mode().Perm()&0077 == 0)
}

// Retain the same private inode before and after opening. Taking the path's
// anchor only AFTER Open could accidentally anchor a replacement directory.
func openNetworkPolicyObservationRoot(path string) (*ownedfs.Root, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, ErrNetworkPolicyConsumers
	}
	before, err := os.Lstat(path)
	if err != nil || !networkPolicyPrivateDirectory(before) {
		return nil, nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	owner, err := ownedfs.Open(path)
	if err != nil {
		return nil, nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	after, err := os.Lstat(path)
	if err != nil || !networkPolicyPrivateDirectory(after) || !os.SameFile(before, after) {
		owner.Close()
		return nil, nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	return owner, before, nil
}

func networkPolicyChecksContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrNetworkPolicyConsumers
	}
	return ctx.Err()
}

func (c *NetworkPolicyChecks) boundary(ctx context.Context, use func(context.Context) error) error {
	if err := c.current(ctx); err != nil {
		return err
	}
	return c.gate.identity.use(ctx, func(held context.Context) error {
		if err := c.current(held); err != nil {
			return err
		}
		err := use(held)
		return errors.Join(err, c.current(held))
	})
}

// RetireCheck excludes ONLY this exact registered LAN participant. Every other
// actual owner is observed freshly, including unused adapters. This is safe
// inside Apply/rollback/Stop: it does not recurse through VerifyRuntimeInactive
// or mistake the current operation's pending journal for a foreign recovery.
func (c *NetworkPolicyChecks) RetireCheck(ctx context.Context, lan *LANPolicyRuntimePlan) error {
	if ValidateLANPolicyRuntime(lan) != nil {
		return ErrLANPolicyRuntime
	}
	return c.boundary(ctx, func(held context.Context) error {
		var result error
		for _, id := range c.ids {
			if err := c.current(held); err != nil {
				return errors.Join(result, err)
			}
			if adapter, ok := c.adapters[id].(*NFQWS2Adapter); ok {
				if e, present := held.Value(nfqws2ActiveExecutionKey{}).(*nfqws2ActiveExecution); present && e != nil {
					if err := c.retiredNFQConsumer(held, adapter, e); err != nil {
						result = errors.Join(result, err)
					}
					result = errors.Join(result, c.current(held))
					continue
				}
			}
			observer, ok := c.adapters[id].(RuntimeInactivityObserver)
			if !ok || observer == nil || isNilRuntimeObserver(observer) {
				result = errors.Join(result, fmt.Errorf("%w: %s has no owner observer", ErrRuntimeInactivity, id))
				continue
			}
			if err := observer.VerifyRuntimeInactive(held); err != nil {
				result = errors.Join(result, fmt.Errorf("%w: %s: %w", ErrNetworkPolicyConsumers, id, err))
			}
			result = errors.Join(result, c.current(held))
		}
		return result
	})
}

type networkPolicyConsumerPlanKey struct{}

func networkPolicyConsumerContext(ctx context.Context, p Plan) context.Context {
	return context.WithValue(ctx, networkPolicyConsumerPlanKey{}, cloneExecutionResourcePlan(p))
}

func (c *NetworkPolicyChecks) consumerPlan(ctx context.Context, lan *LANPolicyRuntimePlan) (Plan, error) {
	p, found := ctx.Value(networkPolicyConsumerPlanKey{}).(Plan)
	if !found {
		// A cold observation consumes only the exact committed journal, never a
		// candidate/latest DTO or an inferred generation. The anchored root is
		// rechecked before and after the operation by boundary.
		data, err := c.owner.ReadLimited("latest-committed-plan.json", 8<<20)
		if err != nil || json.Unmarshal(data, &p) != nil || p.State != "committed" {
			return Plan{}, errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	if p.SchemaVersion != SchemaVersion || !validPlanID(p.PlanID) || !validPlanDigest(p.Digest) ||
		ValidateNetworkPolicyLAN(p.LAN, p.Routes) != nil || !reflect.DeepEqual(p.LAN, lan) {
		return Plan{}, ErrNetworkPolicyConsumers
	}
	state, err := c.gate.readOwner()
	if err != nil || state == nil || state.PlanID != p.PlanID || state.Digest != p.Digest || !reflect.DeepEqual(state.LAN, lan) {
		return Plan{}, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	return cloneExecutionResourcePlan(p), nil
}

// ScopedDNSInactiveCheck supplies the concrete common-inventory callback needed
// by the DNS owner's OS observer. It inspects DNS's namespace only, so a still
// active LAN gate cannot cause recursion or a false DNS-inactive verdict.
func (c *NetworkPolicyChecks) ScopedDNSInactiveCheck(ctx context.Context, identity netidentity.Identity) error {
	return c.boundary(ctx, func(held context.Context) error {
		if identity != c.gate.identity.value {
			return ErrNetworkPolicyIdentity
		}
		s, err := c.read(held, identity)
		if err != nil {
			return err
		}
		if err := s.RequireComplete(); err != nil || s.Scope.Network != identity {
			return errors.Join(ErrBackendInventoryUnknown, err)
		}
		for _, row := range s.Rows {
			if err := CheckScopedDNSInactiveRule(row.Family, row.Table, row.Tokens); err != nil {
				return err
			}
		}
		return held.Err()
	})
}
