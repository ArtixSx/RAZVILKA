package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrListScopeChanged = errors.New("original list scope binding unavailable or changed")

// ListScopeBinding retains original config/control and physical handles. It
// owns no executor, journal, effect admission or positive path/provider proof.
// Observe supplies only compiler data. CORE composes its actual path owners in
// DefaultRouteDependencies.Observe, then binds that compilation in BindIngress.
// ScopeCheck is the physical callback of the SAME LANPolicyRuntime participant.
// All uses require a fresh bounded context carrying the SAME App operation.
type ListScopeBinding struct {
	self                       *ListScopeBinding
	mu                         sync.Mutex
	app                        *App
	store                      *config.Store
	scope                      *defaultconsent.ScopeReview
	expected                   config.Config
	reference                  DefaultRouteAuthority
	facts                      physicalscope.Snapshot
	networkID                  string
	network                    func(context.Context) (string, error)
	verifyPhysical             func(context.Context) error
	verifyCleanupPhysical      func(context.Context) error
	physicalSnapshot           func() physicalscope.Snapshot
	closePhysical              func() error
	bound                      *dataplane.LANPolicyRuntimePlan
	boundOnce, invalid, closed bool
	closeErr                   error
}

func (*ListScopeBinding) String() string   { return "[private original list scope binding]" }
func (*ListScopeBinding) GoString() string { return "[private original list scope binding]" }

// Construction reads existing owners under original admission; it starts no
// worker or native effect. The caller retains this binding through Apply and
// active consumer lifetime, and closes it only after joined native cleanup.
// Close releases its physical Review and ScopeReview, not App's shared Owner.
func NewReviewedStockNC1812ListScopeBinding(ctx context.Context, a *App, provider *netidentity.Provider) (*ListScopeBinding, error) {
	if provider == nil {
		return nil, ErrListScopeChanged
	}
	var retained func(context.Context) error
	b, err := newListScopeBinding(ctx, a, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error) {
		observer := physicalscope.NewReviewedStockNC1812(provider, selection)
		review, err := observer.Observe(c)
		if err != nil {
			return nil, nil, nil, err
		}
		// These closed functions retain EXACT original pointers. No public
		// constructor accepts a fact reader, snapshot or permission callback.
		retained = func(c context.Context) error { return observer.VerifyRetainedIncarnation(c, review) }
		return func(c context.Context) error { return observer.Verify(c, review) }, review.Snapshot, review.Close, nil
	})
	if err != nil {
		return nil, err
	}
	b.verifyCleanupPhysical = retained
	return b, nil
}

// acquire is a private source-level test seam. Production always constructs
// the concrete stock Observer/Review above; tests explicitly model physics.
func newListScopeBinding(ctx context.Context, a *App, acquire func(context.Context, physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error)) (*ListScopeBinding, error) {
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if a == nil || a.Store == nil || acquire == nil {
		return nil, ErrListScopeChanged
	}
	b := &ListScopeBinding{app: a, store: a.Store, network: a.FreshProfile}
	b.self = b
	if b.network == nil {
		b.network = func(c context.Context) (string, error) { p, err := systemprobe.FreshWANProfile(c); return p.ID, err }
	}
	keep := false
	defer func() {
		if !keep {
			_ = b.Close()
		}
	}()
	err = a.Operations.WithExclusiveContext(c, func() error {
		var err error
		b.scope, err = a.ReviewListScope(c)
		if err != nil {
			return err
		}
		b.expected = b.store.Get()
		b.reference, err = defaultRouteScopeAuthority(c, b.store, b.scope)
		if err != nil {
			return err
		}
		b.networkID, err = b.network(c)
		if err != nil || b.networkID == "" {
			return errors.Join(ErrListScopeChanged, err)
		}
		b.verifyPhysical, b.physicalSnapshot, b.closePhysical, err = acquire(c, b.selection)
		if err != nil || b.verifyPhysical == nil || b.physicalSnapshot == nil || b.closePhysical == nil {
			return errors.Join(ErrListScopeChanged, err)
		}
		b.facts = b.physicalSnapshot()
		if b.facts.ReviewID == "" || b.facts.Identity.Validate() != nil || b.facts.Identity.Kind != netidentity.ReviewedSingleInitNet {
			return ErrListScopeChanged
		}
		if _, err := b.compilerScope(time.Now().UTC()); err != nil {
			return err
		}
		return b.currentLocked(c)
	})
	if err != nil {
		return nil, errors.Join(ErrListScopeChanged, err)
	}
	keep = true
	return b, nil
}

func listScopeContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrListScopeChanged
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, nil, ErrListScopeChanged
	}
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	return c, cancel, nil
}

// Called inside actual Observer Observe/Verify. Do not acquire b.mu or wrap a
// whole Verify in ScopeReview.WithCurrent: the original reader forbids reentry.
func (b *ListScopeBinding) selection(ctx context.Context) (physicalscope.Selection, error) {
	if b.app.Store != b.store || !b.scope.MatchesConfigStore(b.store) {
		return physicalscope.Selection{}, ErrListScopeChanged
	}
	if err := b.scope.Current(ctx); err != nil {
		return physicalscope.Selection{}, err
	}
	cfg := b.store.Get()
	if !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.NetworkPolicy == nil || cfg.DefaultRouteConsent == nil {
		return physicalscope.Selection{}, ErrListScopeChanged
	}
	s := physicalscope.Selection{Revision: cfg.DefaultRouteConsent.ApprovalRevision, PolicyRevision: cfg.NetworkPolicy.Revision, SegmentIDs: slices.Clone(cfg.NetworkPolicy.Clients.SegmentIDs)}
	slices.Sort(s.SegmentIDs)
	return s, b.scope.Current(ctx)
}

func (b *ListScopeBinding) changed(err error) error {
	b.invalid = true
	return errors.Join(ErrListScopeChanged, err)
}

func (b *ListScopeBinding) currentLocked(ctx context.Context) (resultErr error) {
	phase := "scope-owner"
	defer func() { resultErr = managedNFQFailureAt(phase, resultErr) }()
	if b.closed || b.invalid || b.scope == nil || b.verifyPhysical == nil || b.app.Store != b.store {
		return b.changed(nil)
	}
	phase = "scope-authority-before"
	ref, err := defaultRouteScopeAuthority(ctx, b.store, b.scope)
	if err != nil || ref != b.reference || !reflect.DeepEqual(b.store.Get(), b.expected) {
		return b.changed(err)
	}
	phase = "scope-selection"
	selection, err := b.selection(ctx)
	if err != nil || !reflect.DeepEqual(selection, b.facts.Selection) {
		return b.changed(err)
	}
	phase = "scope-physical-verify"
	if err := b.verifyPhysical(ctx); err != nil {
		return b.changed(err)
	}
	phase = "scope-physical-snapshot"
	if !reflect.DeepEqual(b.physicalSnapshot(), b.facts) {
		return b.changed(nil)
	}
	phase = "scope-wan-identity"
	network, err := b.network(ctx)
	if err != nil || network != b.networkID {
		return b.changed(err)
	}
	phase = "scope-authority-after"
	ref, err = defaultRouteScopeAuthority(ctx, b.store, b.scope)
	if err != nil || ref != b.reference || !reflect.DeepEqual(b.store.Get(), b.expected) {
		return b.changed(err)
	}
	return nil
}

func (b *ListScopeBinding) use(ctx context.Context, action func(context.Context) error) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.app.Operations.WithExclusiveContext(c, func() error {
		if err := b.currentLocked(c); err != nil {
			return err
		}
		if err := action(c); err != nil {
			return err
		}
		return b.currentLocked(c)
	})
}

// Observe is the scope portion of DefaultRouteDependencies.Observe. The caller
// supplies fresh source/path proofs separately. Times describe this successful
// Verify only; the DTO never extends the live Review or authorizes an effect.
func (b *ListScopeBinding) Observe(ctx context.Context) (DefaultRouteSnapshot, error) {
	var out DefaultRouteSnapshot
	err := b.use(ctx, func(context.Context) error {
		var err error
		out, err = b.compilerScope(time.Now().UTC())
		return err
	})
	if err != nil {
		return DefaultRouteSnapshot{}, err
	}
	return out, nil
}

func (b *ListScopeBinding) compilerScope(now time.Time) (DefaultRouteSnapshot, error) {
	s := DefaultRouteSnapshot{Authority: b.reference, DNSMode: "baseline", Scope: autonomy.ScopeObservation{BootID: b.facts.Identity.BootID, NetworkID: b.networkID, Revision: b.facts.Selection.Revision, ObservedAt: now, FreshUntil: now.Add(time.Minute)}}
	aliases := map[string]string{}
	for _, segment := range b.facts.Segments {
		id := ""
		for _, selected := range b.facts.Selection.SegmentIDs {
			if selected == segment.ID || selected == segment.NativeName {
				if id != "" {
					return DefaultRouteSnapshot{}, ErrListScopeChanged
				}
				id = selected
			}
		}
		if id == "" || aliases[segment.ID] != "" || segment.Home == segment.Guest {
			return DefaultRouteSnapshot{}, ErrListScopeChanged
		}
		aliases[segment.ID] = id
		observed := autonomy.HomeSegment{ID: id, Interface: segment.Interface, Home: segment.Home}
		for _, raw := range segment.Prefixes {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix != prefix.Masked() {
				return DefaultRouteSnapshot{}, ErrListScopeChanged
			}
			observed.Prefixes = append(observed.Prefixes, prefix)
		}
		s.Scope.Segments = append(s.Scope.Segments, observed)
		for _, router := range segment.RouterNeighbors {
			s.Infrastructure = append(s.Infrastructure, DefaultRouteInfrastructureNeighbor{SegmentID: id, Interface: segment.Interface, Address: router.Address, MAC: router.MAC, Flags: router.Flags, Type: router.Type})
		}
		if segment.Guest {
			s.GuestSegmentIDs = append(s.GuestSegmentIDs, id)
		}
	}
	if len(aliases) != len(b.facts.Selection.SegmentIDs) {
		return DefaultRouteSnapshot{}, ErrListScopeChanged
	}
	for _, device := range b.facts.Devices {
		id := aliases[device.SegmentID]
		if id == "" {
			return DefaultRouteSnapshot{}, ErrListScopeChanged
		}
		s.Scope.Devices = append(s.Scope.Devices, autonomy.DeviceBinding{ID: device.ID, MAC: device.MAC, Interface: device.Interface, SegmentID: id, Confirmed: true})
		addresses := DefaultRouteDevice{ID: device.ID}
		for _, raw := range device.Addresses {
			ip, err := netip.ParseAddr(raw)
			if err != nil || !ip.IsGlobalUnicast() || ip.Is4In6() || ip.Zone() != "" {
				return DefaultRouteSnapshot{}, ErrListScopeChanged
			}
			addresses.Addresses = append(addresses.Addresses, ip)
		}
		s.Devices = append(s.Devices, addresses)
	}
	return s, nil
}

// BindCompilation runs in existing BindIngress after actual path compilation.
// It freezes one exact immutable LAN plan, without changing that plan or Input.
// It cannot grant the path/effect and cannot be rebound to another generation.
func (b *ListScopeBinding) BindCompilation(ctx context.Context, compilation *DefaultRouteCompilation) error {
	return b.use(ctx, func(context.Context) (resultErr error) {
		phase := "bind-policy"
		defer func() { resultErr = managedNFQFailureAt(phase, resultErr) }()
		if compilation == nil || b.boundOnce || !reflect.DeepEqual(compilation.policy, b.expected.NetworkPolicy) {
			return ErrListScopeChanged
		}
		phase = "bind-observed-scope"
		actual, err := b.compilerScope(time.Now().UTC())
		if err != nil {
			return err
		}
		phase = "bind-snapshot"
		want, have := defaultRouteIdentity(actual), defaultRouteIdentity(compilation.snapshot)
		if have.Authority != want.Authority || have.DNSMode != "baseline" || have.Stopped || !reflect.DeepEqual(have.Scope, want.Scope) || !reflect.DeepEqual(have.Devices, want.Devices) || !slices.Equal(have.Infrastructure, want.Infrastructure) || !slices.Equal(have.GuestSegmentIDs, want.GuestSegmentIDs) {
			return ErrListScopeChanged
		}
		plan := compilation.LAN()
		if plan != nil {
			phase = "bind-lan-plan"
			if err := dataplane.ValidateLANPolicyRuntime(plan); err != nil {
				return errors.Join(ErrListScopeChanged, err)
			}
			phase = "bind-lan-generation"
			if plan.Generation != compilation.Digest() {
				return ErrListScopeChanged
			}
			phase = "bind-router-membership"
			for _, segment := range b.facts.Segments {
				for _, router := range segment.RouterNeighbors {
					// The frozen LAN plan uses canonical uppercase MACs while
					// native physical facts use net.HardwareAddr's lowercase form.
					routerMAC := strings.ToUpper(router.MAC)
					for _, ingress := range plan.Ingress {
						if ingress.Interface == segment.Interface && !slices.Contains(ingress.ExcludedMACs, routerMAC) {
							return ErrListScopeChanged
						}
					}
				}
			}
		}
		b.bound, b.boundOnce = dataplane.CloneLANPolicyRuntime(plan), true
		return nil
	})
}

func (b *ListScopeBinding) ScopeCheck(ctx context.Context, plan *dataplane.LANPolicyRuntimePlan) error {
	return b.use(ctx, func(context.Context) error {
		if !b.boundOnce || b.bound == nil || dataplane.ValidateLANPolicyRuntime(plan) != nil || !reflect.DeepEqual(plan, b.bound) {
			return ErrListScopeChanged
		}
		return nil
	})
}

// Call only after SAME Store's exact successful policy CAS, outside Store
// observation, with actual commit times. The original ScopeReview accepts the
// sanctioned image first; failed physical verification then poisons this owner.
// No ordinary edit, restored tuple or copied postimage can renew the binding.
func (b *ListScopeBinding) AcceptCommitted(ctx context.Context, after config.Config, started, finished time.Time) error {
	if b == nil || b.self != b || b.app == nil {
		return ErrListScopeChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.app.Operations.WithExclusiveContext(c, func() error {
		if b.closed || b.invalid || b.scope == nil || b.app.Store != b.store {
			return b.changed(nil)
		}
		actual := b.store.Get()
		if !reflect.DeepEqual(actual, after) || !defaultRouteCommittedConfig(b.expected, actual, b.expected.NetworkPolicy, b.expected.Services, started, finished) {
			return b.changed(nil)
		}
		if err := b.scope.AcceptCommitted(c, actual, started, finished); err != nil {
			return b.changed(err)
		}
		b.expected = actual // Store.Get's detached clone, never the caller DTO
		return b.currentLocked(c)
	})
}

func (b *ListScopeBinding) Close() error {
	if b == nil {
		return nil
	}
	if b.self != b {
		return ErrListScopeChanged
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.closeErr
	}
	b.closed = true
	if b.closePhysical != nil {
		b.closeErr = b.closePhysical()
	}
	if b.scope != nil {
		b.closeErr = errors.Join(b.closeErr, b.scope.Close())
	}
	return b.closeErr
}
