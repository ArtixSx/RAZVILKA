package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/sources"
)

var ErrListDNSResourcesChanged = errors.New("original list DNS resources unavailable or changed")

// ListDNSResourceBinding connects the existing DNS negative participant to the
// SAME selected-list scope, Store and complete App catalog. It owns no listener,
// operation, provider, positive client admission or lifecycle. Guard belongs in
// the resolver's guard; its separate admission and publisher must still retain
// actual physical INPUT/DNAT, generation and durable Stop owners.
type ListDNSResourceBinding struct {
	self       *ListDNSResourceBinding
	scope      *ListScopeBinding
	expected   config.Config
	catalog    string
	custom     *customservices.Manager
	sources    *sources.Manager
	services   []string
	identities map[string][]string
	exclusions *dnscontrol.NetworkPolicyDNSExclusions
	revoked    atomic.Bool
}

func (*ListDNSResourceBinding) String() string   { return "[private original list DNS resources]" }
func (*ListDNSResourceBinding) GoString() string { return "[private original list DNS resources]" }

// NewListDNSResourceBinding reads only concrete existing owners under a fresh
// bounded SAME App operation. No catalog reader or permission callback can be
// installed by a caller. A sanctioned policy CAS needs a new participant after
// the scope's AcceptCommitted; the old full-config participant never advances.
func NewListDNSResourceBinding(ctx context.Context, scope *ListScopeBinding) (*ListDNSResourceBinding, error) {
	if scope == nil || scope.self != scope || scope.app == nil {
		return nil, ErrListDNSResourcesChanged
	}
	b := &ListDNSResourceBinding{scope: scope}
	b.self = b
	err := scope.use(ctx, func(c context.Context) error {
		b.expected = scope.store.Get()
		b.custom, b.sources = scope.app.CustomServices, scope.app.Sources
		definitions := scope.app.catalogSnapshot()
		if len(definitions.Services) == 0 || catalog.Validate(definitions) != nil {
			return ErrListDNSResourcesChanged
		}
		b.catalog = applyReviewHash(definitions)
		b.identities = make(map[string][]string)
		for _, service := range definitions.Services {
			b.services = append(b.services, service.ID)
			for _, raw := range service.Domains {
				if err := c.Err(); err != nil {
					return err
				}
				name, err := config.ResourceHostname(raw)
				if err != nil {
					return errors.Join(ErrListDNSResourcesChanged, err)
				}
				// Disabled services and source-expanded definitions participate.
				// Matching IDs are negative facts, never DNS/flow permission.
				if !slices.Contains(b.identities[name], service.ID) {
					b.identities[name] = append(b.identities[name], service.ID)
				}
			}
		}
		if b.sources != nil && !b.sources.AutomaticUseReady(b.services) {
			return ErrListDNSResourcesChanged
		}
		for _, ids := range b.identities {
			slices.Sort(ids)
		}
		var err error
		b.exclusions, err = dnscontrol.NewNetworkPolicyDNSExclusions(c, scope.store, b.expected, b.serviceIdentities)
		return err
	})
	if err != nil {
		return nil, errors.Join(ErrListDNSResourcesChanged, err)
	}
	return b, nil
}

// Exclusions returns the original existing participant, not a reconstructed
// stamp. The resolver must use Guard as well; this pointer grants no admission.
func (b *ListDNSResourceBinding) Exclusions() *dnscontrol.NetworkPolicyDNSExclusions {
	if b == nil || b.self != b || b.revoked.Load() {
		return nil
	}
	return b.exclusions
}

func (b *ListDNSResourceBinding) changed(err error) error {
	b.revoked.Store(true)
	return errors.Join(ErrListDNSResourcesChanged, err)
}

// Guard checks resources only. The physical DNS admission separately verifies
// the original Observer/Review. No scope reentry or provider/catalog callback
// belongs inside the final Store observation's closed local-write leaf.
func (b *ListDNSResourceBinding) Guard(ctx context.Context) error {
	if b == nil || b.self != b || b.scope == nil || b.revoked.Load() {
		return ErrListDNSResourcesChanged
	}
	c, cancel, err := listScopeContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	s := b.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.app.Operations.WithExclusiveContext(c, func() error {
		if b.revoked.Load() || s.closed || s.invalid || s.scope == nil || s.app.Store != s.store ||
			!reflect.DeepEqual(s.expected, b.expected) || s.app.CustomServices != b.custom || s.app.Sources != b.sources {
			return b.changed(nil)
		}
		if err := s.scope.Current(c); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return b.changed(err)
		}
		if b.sources != nil && !b.sources.AutomaticUseReady(b.services) || applyReviewHash(s.app.catalogSnapshot()) != b.catalog {
			return b.changed(nil)
		}
		if err := s.scope.Current(c); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return b.changed(err)
		}
		return nil
	})
}

func (b *ListDNSResourceBinding) serviceIdentities(ctx context.Context, observed string) ([]string, error) {
	if err := b.Guard(ctx); err != nil {
		return nil, err
	}
	name, err := config.ResourceHostname(observed)
	if err != nil {
		return nil, err
	}
	var ids []string
	for {
		for _, id := range b.identities[name] {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
				if len(ids) > 128 {
					return nil, ErrListDNSResourcesChanged
				}
			}
		}
		next := strings.IndexByte(name, '.')
		if next < 0 {
			break
		}
		name = name[next+1:]
	}
	slices.Sort(ids)
	return ids, b.Guard(ctx)
}
