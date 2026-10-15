package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

// NFQWSPacketScopeSnapshot is comparison data, never a device observation or
// admission. It deliberately has no DeviceBinding or membership epoch.
type NFQWSPacketScopeSnapshot struct {
	Facts              physicalscope.IPv4LANPacketFacts
	Authority          DefaultRouteAuthority
	NetworkID, DNSMode string
}

type nfqwsPacketObserver interface {
	Current(context.Context) error
	RetainedCurrent(context.Context) error
	PacketFacts() physicalscope.IPv4LANPacketFacts
	Close() error
}

// NFQWSPacketScopeBinding retains the actual scope consent and structural
// packet reader through SAME managed NFQ Apply/Stop. No public fact/callback
// constructor can produce it. Ordinary DHCP membership is not its authority.
type NFQWSPacketScopeBinding struct {
	self                       *NFQWSPacketScopeBinding
	mu                         sync.Mutex
	app                        *App
	store                      *config.Store
	scope                      *defaultconsent.ScopeReview
	control                    *operationgate.ControlEpochReview
	physical                   nfqwsPacketObserver
	original                   *physicalscope.IPv4LANPacketScope
	expected                   config.Config
	snapshot                   NFQWSPacketScopeSnapshot
	network                    func(context.Context) (string, error)
	bound                      *dataplane.LANPolicyRuntimePlan
	boundOnce, invalid, closed bool
	closeErr                   error
}

func (*NFQWSPacketScopeBinding) String() string {
	return "[private original NFQ IPv4 LAN packet binding]"
}
func (*NFQWSPacketScopeBinding) GoString() string {
	return "[private original NFQ IPv4 LAN packet binding]"
}

func NewReviewedStockNC1812NFQWSPacketScopeBinding(ctx context.Context, a *App, provider *netidentity.Provider) (*NFQWSPacketScopeBinding, error) {
	if provider == nil {
		return nil, ErrListScopeChanged
	}
	return newNFQWSPacketScopeBinding(ctx, a, func(c context.Context, b *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
		p, err := physicalscope.NewReviewedStockNC1812IPv4LANPacketScope(c, provider, b.control, a.SelfUpdateFiles.ControlRoot, b.intent)
		if err == nil {
			b.original = p
		}
		return p, err
	})
}

// Private model seam; production always retains the concrete original above.
func newNFQWSPacketScopeBinding(ctx context.Context, a *App, acquire func(context.Context, *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error)) (*NFQWSPacketScopeBinding, error) {
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if a == nil || a.Store == nil || a.SelfUpdateFiles == nil || acquire == nil {
		return nil, ErrListScopeChanged
	}
	b := &NFQWSPacketScopeBinding{app: a, store: a.Store, network: a.FreshProfile}
	b.self = b
	if b.network == nil {
		b.network = func(c context.Context) (string, error) { p, e := systemprobe.FreshWANProfile(c); return p.ID, e }
	}
	keep := false
	defer func() {
		if !keep {
			_ = b.Close()
		}
	}()
	err = a.Operations.WithExclusiveContext(c, func() error {
		var e error
		b.scope, e = a.ReviewListScope(c)
		if e != nil {
			return e
		}
		b.expected = b.store.Get()
		if _, e = b.intent(c); e != nil {
			return e
		}
		b.snapshot.Authority, e = defaultRouteScopeAuthority(c, b.store, b.scope)
		if e != nil {
			return e
		}
		b.control, e = a.Operations.ReviewControlEpoch(c, a.SelfUpdateFiles.ControlRoot)
		if e != nil {
			return e
		}
		b.snapshot.NetworkID, e = b.network(c)
		if e != nil || b.snapshot.NetworkID == "" {
			return errors.Join(ErrListScopeChanged, e)
		}
		b.physical, e = acquire(c, b)
		if e != nil || b.physical == nil {
			return errors.Join(ErrListScopeChanged, e)
		}
		b.snapshot.Facts = b.physical.PacketFacts()
		b.snapshot.DNSMode = "baseline"
		if e = validateNFQWSPacketSnapshot(b.expected, b.snapshot); e != nil {
			return e
		}
		return b.currentLocked(c)
	})
	if err != nil {
		return nil, errors.Join(ErrListScopeChanged, err)
	}
	keep = true
	return b, nil
}

// Called by the actual physical reader. Never hold ScopeReview.WithCurrent
// across physical Current, whose intent callback must recheck this same owner.
func (b *NFQWSPacketScopeBinding) intent(ctx context.Context) (physicalscope.IPv4LANPacketIntent, error) {
	if b.app.Store != b.store || b.scope == nil || !b.scope.MatchesConfigStore(b.store) {
		return physicalscope.IPv4LANPacketIntent{}, ErrListScopeChanged
	}
	if err := b.scope.Current(ctx); err != nil {
		return physicalscope.IPv4LANPacketIntent{}, err
	}
	cfg := b.store.Get()
	if !reflect.DeepEqual(cfg, b.expected) {
		return physicalscope.IPv4LANPacketIntent{}, ErrListScopeChanged
	}
	i, err := nfqwsPacketIntent(cfg)
	if err != nil {
		return i, err
	}
	return i, b.scope.Current(ctx)
}

func nfqwsPacketIntent(cfg config.Config) (physicalscope.IPv4LANPacketIntent, error) {
	p := cfg.NetworkPolicy
	if cfg.SafeMode || cfg.ServiceControl.Stopped || !config.CurrentDefaultRouteScopeConsent(cfg) || cfg.DefaultRouteConsent == nil || p == nil || config.ValidateListNetworkPolicy(p) != nil || p.Clients.Mode != "lan_except" || p.Clients.NewDevices != "inherit" || len(p.Clients.SegmentIDs) != 1 || len(p.Clients.DeviceIDs) != 0 {
		return physicalscope.IPv4LANPacketIntent{}, ErrDefaultRouteCapability
	}
	i := physicalscope.IPv4LANPacketIntent{Revision: cfg.DefaultRouteConsent.ApprovalRevision, PolicyRevision: p.Revision, Mode: p.Clients.Mode, NewDevices: p.Clients.NewDevices, SegmentIDs: slices.Clone(p.Clients.SegmentIDs), ExcludedDeviceIDs: slices.Clone(p.Clients.ExcludedDeviceIDs), ExcludedCIDRs: slices.Clone(p.Clients.ExcludedCIDRs)}
	for _, id := range i.ExcludedDeviceIDs {
		raw := strings.ReplaceAll(strings.TrimPrefix(id, "mac-"), "-", ":")
		mac, e := nfqwsPacketMAC(raw)
		if e != nil || id != "mac-"+strings.ReplaceAll(mac, ":", "-") {
			return physicalscope.IPv4LANPacketIntent{}, ErrDefaultRouteCapability
		}
	}
	for _, state := range cfg.Services {
		if state.Enabled && len(state.Sources) != 0 {
			return physicalscope.IPv4LANPacketIntent{}, ErrDefaultRouteCapability
		}
	}
	slices.Sort(i.SegmentIDs)
	slices.Sort(i.ExcludedDeviceIDs)
	slices.Sort(i.ExcludedCIDRs)
	return i, nil
}

func (b *NFQWSPacketScopeBinding) changed(err error) error {
	b.invalid = true
	return errors.Join(ErrListScopeChanged, err)
}
func (b *NFQWSPacketScopeBinding) currentLocked(ctx context.Context) error {
	if b.closed || b.invalid || b.scope == nil || b.physical == nil || b.app.Store != b.store {
		return b.changed(nil)
	}
	ref, err := defaultRouteScopeAuthority(ctx, b.store, b.scope)
	if err != nil || ref != b.snapshot.Authority || !reflect.DeepEqual(b.store.Get(), b.expected) {
		return b.changed(err)
	}
	if err = b.physical.Current(ctx); err != nil {
		return b.changed(err)
	}
	if !reflect.DeepEqual(b.physical.PacketFacts(), b.snapshot.Facts) {
		return b.changed(nil)
	}
	network, err := b.network(ctx)
	if err != nil || network != b.snapshot.NetworkID {
		return b.changed(err)
	}
	ref, err = defaultRouteScopeAuthority(ctx, b.store, b.scope)
	if err != nil || ref != b.snapshot.Authority || !reflect.DeepEqual(b.store.Get(), b.expected) {
		return b.changed(err)
	}
	return nil
}
func (b *NFQWSPacketScopeBinding) use(ctx context.Context, action func(context.Context) error) error {
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
		if e := b.currentLocked(c); e != nil {
			return e
		}
		if e := action(c); e != nil {
			return e
		}
		return b.currentLocked(c)
	})
}
func (b *NFQWSPacketScopeBinding) Observe(ctx context.Context) (NFQWSPacketScopeSnapshot, error) {
	var s NFQWSPacketScopeSnapshot
	err := b.use(ctx, func(context.Context) error { s = b.snapshot; s.Facts = b.physical.PacketFacts(); return nil })
	if err != nil {
		return NFQWSPacketScopeSnapshot{}, err
	}
	return s, nil
}
func (b *NFQWSPacketScopeBinding) BindCompilation(ctx context.Context, c *DefaultRouteCompilation) error {
	return b.use(ctx, func(context.Context) error {
		if c == nil || b.boundOnce || c.packet == nil || !reflect.DeepEqual(c.packet, &b.snapshot) || !reflect.DeepEqual(c.policy, b.expected.NetworkPolicy) || c.LAN() == nil || c.LAN().Mode != dataplane.LANPolicyNFQWSDirectMode || c.LAN().Generation != c.Digest() {
			return ErrListScopeChanged
		}
		// Recompile the original immutable comparison to refuse replaced rules or
		// negative gates, including package-local partial/copy compositions.
		rebuilt, err := CompileNFQWSIPv4LANPacketPolicy(b.expected, b.snapshot, defaultRouteCloneRoutes(c.packetServices), c.snapshot.Paths, time.Now())
		if err != nil || !reflect.DeepEqual(rebuilt, c) {
			return errors.Join(ErrListScopeChanged, err)
		}
		b.bound = c.LAN()
		b.boundOnce = true
		return nil
	})
}
func (b *NFQWSPacketScopeBinding) ScopeCheck(ctx context.Context, p *dataplane.LANPolicyRuntimePlan) error {
	return b.use(ctx, func(context.Context) error {
		if !b.boundOnce || b.bound == nil || dataplane.ValidateLANPolicyRuntime(p) != nil || !reflect.DeepEqual(p, b.bound) {
			return ErrListScopeChanged
		}
		return nil
	})
}
func (b *NFQWSPacketScopeBinding) cleanupScopeCheck(ctx context.Context, p *dataplane.LANPolicyRuntimePlan) error {
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
	if b.closed || b.app.Store != b.store || b.physical == nil || !b.boundOnce || b.bound == nil || dataplane.ValidateLANPolicyRuntime(p) != nil || !reflect.DeepEqual(p, b.bound) || !reflect.DeepEqual(b.snapshot.Facts, b.physical.PacketFacts()) {
		return ErrListScopeChanged
	}
	// No ScopeReview/Store/intent read: an edited draft cannot strand original
	// receipt-owned cleanup. Actual caller still needs its preissued capability.
	if err := b.physical.RetainedCurrent(c); err != nil {
		return errors.Join(ErrListScopeChanged, err)
	}
	if !reflect.DeepEqual(b.snapshot.Facts, b.physical.PacketFacts()) {
		return ErrListScopeChanged
	}
	return c.Err()
}
func (b *NFQWSPacketScopeBinding) AcceptCommitted(ctx context.Context, after config.Config, started, finished time.Time) error {
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
		if b.closed || b.invalid || b.scope == nil || b.app.Store != b.store || !b.boundOnce {
			return b.changed(nil)
		}
		actual := b.store.Get()
		if !reflect.DeepEqual(actual, after) || !defaultRouteCommittedConfig(b.expected, actual, b.expected.NetworkPolicy, b.expected.Services, started, finished) {
			return b.changed(nil)
		}
		if err := b.scope.AcceptCommitted(c, actual, started, finished); err != nil {
			return b.changed(err)
		}
		b.expected = actual
		return b.currentLocked(c)
	})
}
func (b *NFQWSPacketScopeBinding) Close() error {
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
	if b.physical != nil {
		b.closeErr = b.physical.Close()
	}
	if b.control != nil {
		b.closeErr = errors.Join(b.closeErr, b.control.Close())
	}
	if b.scope != nil {
		b.closeErr = errors.Join(b.closeErr, b.scope.Close())
	}
	return b.closeErr
}
