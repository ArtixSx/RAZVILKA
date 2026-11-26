//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

type nativeFixtureNFQListPhysicalSource struct {
	self     *nativeFixtureNFQListPhysicalSource
	runtime  *ManagedNFQWSListRuntime
	app      *App
	provider *netidentity.Provider
}

func (s *nativeFixtureNFQListPhysicalSource) original(r *ManagedNFQWSListRuntime) bool {
	return s != nil && s.self == s && s.runtime == r && r != nil && r.self == r && r.physicalSource == s && s.app != nil && r.app == s.app && s.app.managedNFQList == r && s.provider != nil && r.provider == s.provider
}

func (s *nativeFixtureNFQListPhysicalSource) acquire(ctx context.Context, e *managedNFQWSListExecution, packet bool) error {
	if !s.original(s.runtime) || e == nil || e.self != e || e.runtime != s.runtime {
		return dataplane.ErrNFQWSScopedOwner
	}
	return s.provider.WithCurrent(ctx, func(c context.Context, id netidentity.Identity) error {
		if id.Kind != netidentity.ProcNetInode {
			return dataplane.ErrNFQWSScopedOwner
		}
		var err error
		if packet {
			e.packetScope, err = NewNativeFixtureNFQWSPacketScopeBinding(c, s.app, s.provider)
		} else {
			e.scope, err = NewNativeFixtureListScopeBinding(c, s.app, s.provider)
		}
		return err
	})
}

func installNativeFixtureNFQListPhysicalSource(r *ManagedNFQWSListRuntime) error {
	if r == nil || !r.original() || r.physicalSource != nil {
		return dataplane.ErrNFQWSScopedOwner
	}
	s := &nativeFixtureNFQListPhysicalSource{runtime: r, app: r.app, provider: r.provider}
	s.self = s
	r.physicalSource = s
	return nil
}

// NewNativeFixtureListScopeBinding retains the actual Linux Observer/Review.
// The dedicated tagged fixture owns the private namespace and fixed rzhome
// bridge; this helper models only its Home classification, never kernel facts
// or stock-router identity, and supplies no effect permission.
func NewNativeFixtureListScopeBinding(ctx context.Context, a *App, provider *netidentity.Provider) (*ListScopeBinding, error) {
	if provider == nil {
		return nil, ErrListScopeChanged
	}
	var observer *physicalscope.Observer
	var review *physicalscope.Review
	b, err := newListScopeBindingForIdentity(ctx, a, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.Snapshot, func() error, error) {
		var err error
		observer, review, err = physicalscope.ObserveNativeFixtureHome(c, provider, selection)
		if err != nil {
			return nil, nil, nil, err
		}
		return func(c context.Context) error { return observer.Verify(c, review) }, review.Snapshot, review.Close, nil
	}, netidentity.ProcNetInode, physicalscope.NativeFixtureHomeInterface)
	if err != nil {
		return nil, err
	}
	b.originalPhysicalObserver, b.originalPhysicalReview = observer, review
	b.verifyCleanupPhysical = func(c context.Context) error { return observer.VerifyRetainedIncarnation(c, review) }
	return b, nil
}

// NewNativeFixtureNFQWSPacketScopeBinding retains the same concrete packet
// scope as production, using actual Proc identity and the fixed fixture Home.
func NewNativeFixtureNFQWSPacketScopeBinding(ctx context.Context, a *App, provider *netidentity.Provider) (*NFQWSPacketScopeBinding, error) {
	if provider == nil {
		return nil, ErrListScopeChanged
	}
	return newNFQWSPacketScopeBindingForIdentity(ctx, a, func(c context.Context, b *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
		original, err := physicalscope.NewNativeFixtureIPv4LANPacketScope(c, provider, b.control, a.SelfUpdateFiles.ControlRoot, b.intent)
		if err == nil {
			b.original = original
		}
		return original, err
	}, netidentity.ProcNetInode)
}
