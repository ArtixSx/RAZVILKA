package physicalscope

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrDomainIPv4PolicyWindowChanged = errors.New("kernel reported a change during the IPv4 policy read")

// DomainIPv4ForwardedPolicyWindow binds a complete IPv4 policy inventory and
// an explicit FIB lookup to one bounded interval of the same kernel network
// identity. No subscribed change or loss was observed within the interval.
// The mark is caller-supplied. Packet marks, NAT, PREROUTING, netfilter and
// actual VPN forwarding are outside this read. The result grants no effects.
type DomainIPv4ForwardedPolicyWindow struct {
	Identity  netidentity.Identity
	Inventory DomainIPv4PolicyInventory
	Lookup    DomainIPv4PolicyLookup
}

// ReadDomainIPv4ForwardedPolicyWindow subscribes before making the sequential
// reads. It rejects changes even if the configuration already reverted by
// the end. A successful read supplies comparison evidence for this interval
// only. It cannot be held to authorize future use.
func ReadDomainIPv4ForwardedPolicyWindow(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity, query DomainIPv4PolicyLookupQuery) (DomainIPv4ForwardedPolicyWindow, error) {
	if provider == nil {
		return DomainIPv4ForwardedPolicyWindow{}, ErrUnknown
	}
	return readDomainIPv4ForwardedPolicyWindow(ctx, expected, query, provider.WithCurrent, domainIPv4PolicyWindowSources{
		open: platformOpenDomainIPv4PolicyWindow, dump: platformDomainIPv4PolicyDump, lookup: platformDomainIPv4PolicyRoute,
	})
}

type domainIPv4PolicyWindowMonitor interface {
	quiet(context.Context) error
	close() error
}

type domainIPv4PolicyWindowSources struct {
	open   func(context.Context) (domainIPv4PolicyWindowMonitor, error)
	dump   func(context.Context, uint16, byte) ([]message, error)
	lookup func(context.Context, DomainIPv4PolicyLookupQuery) (DomainIPv4PolicyLookup, error)
}

func readDomainIPv4ForwardedPolicyWindow(ctx context.Context, expected netidentity.Identity, query DomainIPv4PolicyLookupQuery,
	current func(context.Context, func(context.Context, netidentity.Identity) error) error, sources domainIPv4PolicyWindowSources) (result DomainIPv4ForwardedPolicyWindow, resultErr error) {
	var zero DomainIPv4ForwardedPolicyWindow
	if ctx == nil || ctx.Err() != nil || expected.Validate() != nil || query.IngressIndex == 0 || !query.valid() ||
		current == nil || sources.open == nil || sources.dump == nil || sources.lookup == nil {
		return zero, ErrUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return zero, ErrUnknown
	}
	bounded, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var monitor domainIPv4PolicyWindowMonitor
	defer func() {
		var releaseErr error
		if monitor != nil {
			releaseErr = monitor.close()
		}
		if err := errors.Join(releaseErr, bounded.Err()); err != nil {
			result, resultErr = zero, errors.Join(ErrUnknown, resultErr, err)
		}
	}()
	var observation DomainIPv4ForwardedPolicyWindow
	uses := 0
	err := current(bounded, func(held context.Context, actual netidentity.Identity) error {
		uses++
		if uses != 1 || actual != expected || held.Err() != nil {
			return ErrUnknown
		}
		var err error
		monitor, err = sources.open(held)
		if err != nil || monitor == nil {
			return errors.Join(ErrUnknown, err)
		}
		observation.Inventory, err = collectDomainIPv4PolicyInventory(held, sources.dump)
		if err != nil {
			return err
		}
		leaf, stop := context.WithTimeout(held, 2*time.Second)
		defer stop()
		observation.Lookup, err = sources.lookup(leaf, query)
		return errors.Join(err, leaf.Err())
	})
	if err != nil || uses != 1 || monitor == nil || bounded.Err() != nil {
		return zero, errors.Join(ErrUnknown, err, bounded.Err())
	}
	// The subscribed socket retains its original namespace independently of
	// the thread. Check its queue after the Provider's closing identity read.
	if err := monitor.quiet(bounded); err != nil || bounded.Err() != nil {
		return zero, errors.Join(ErrUnknown, err, bounded.Err())
	}
	if !domainIPv4PolicyWindowMatches(observation, query) {
		return zero, ErrUnknown
	}
	observation.Identity = expected
	return observation, nil
}

func domainIPv4PolicyWindowMatches(window DomainIPv4ForwardedPolicyWindow, query DomainIPv4PolicyLookupQuery) bool {
	path := window.Lookup
	if path.Source != query.Source || path.Destination != query.Destination || path.IngressIndex != query.IngressIndex ||
		path.Mark != query.Mark || path.EgressIndex <= 0 || path.EgressIndex == path.IngressIndex || path.Table == 0 || len(window.Inventory.Rules) == 0 {
		return false
	}
	usableLink := func(index int) bool {
		// IFF_UP and IFF_LOOPBACK are Linux UAPI flags returned by GETLINK,
		// with values distinct from the corresponding Go net.Flags.
		const linuxInterfaceUp, linuxInterfaceLoopback uint32 = 0x1, 0x8
		return slices.ContainsFunc(window.Inventory.Links, func(link DomainIPv4PolicyLink) bool {
			return link.Index == index && link.Flags&(linuxInterfaceUp|linuxInterfaceLoopback) == linuxInterfaceUp
		})
	}
	return usableLink(path.IngressIndex) && usableLink(path.EgressIndex) &&
		slices.ContainsFunc(window.Inventory.Routes, func(route DomainIPv4PolicyRoute) bool { return route.Table == path.Table })
}
