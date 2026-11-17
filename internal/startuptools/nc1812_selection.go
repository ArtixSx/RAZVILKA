package startuptools

import (
	"context"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

type nc1812ToolSet uint8

const (
	nc1812BaseTools nc1812ToolSet = iota
	nc1812PolicyTools
	nc1812ManagedListTools
	nc1812WireGuardTools
	nc1812AmneziaWGTools
)

// These factories select one fixed package profile before acquisition. The
// main-image hint issues no lease: the chosen original acquisition independently
// verifies every byte, alias, dependency, provider and actual version child.
// A refused acquisition never tries another profile.
func AcquireReviewedNC1812(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireNC1812Selected(ctx, provider, nc1812BaseTools)
}

func AcquireReviewedNC1812Policy(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireNC1812Selected(ctx, provider, nc1812PolicyTools)
}

func AcquireReviewedNC1812ManagedList(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireNC1812Selected(ctx, provider, nc1812ManagedListTools)
}

func AcquireReviewedNC1812WireGuard(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireNC1812Selected(ctx, provider, nc1812WireGuardTools)
}

func AcquireReviewedNC1812AmneziaWG(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireNC1812Selected(ctx, provider, nc1812AmneziaWGTools)
}

func nc1812ProfileForHint(digest string, set nc1812ToolSet) (profile, error) {
	current := false
	switch digest {
	case stockProfile().mainSHA:
	case nc1812Entware202611Profile().mainSHA:
		current = true
	default:
		return profile{}, at("NC1812_SELECTION_UNKNOWN", nil)
	}
	switch set {
	case nc1812BaseTools:
		if current {
			return nc1812Entware202611Profile(), nil
		}
		return stockProfile(), nil
	case nc1812PolicyTools:
		if current {
			return nc1812Entware202611PolicyProfile(), nil
		}
		return stockPolicyProfile(), nil
	case nc1812ManagedListTools:
		if current {
			return nc1812Entware202611ManagedListProfile(), nil
		}
		return managedListProfile(), nil
	case nc1812WireGuardTools:
		if current {
			return nc1812Entware202611WGProfile("wireguard"), nil
		}
		return wgProfile(true, "wireguard"), nil
	case nc1812AmneziaWGTools:
		if current {
			return nc1812Entware202611WGProfile("amneziawg"), nil
		}
		return wgProfile(true, "amneziawg"), nil
	default:
		return profile{}, at("NC1812_SELECTION_SET", nil)
	}
}

// A zero deadline preserves the explicit factories' original two-second
// acquisition cap. Selection supplies the absolute deadline established BEFORE
// its hint. Only this first phase shares that budget; WG's original second
// version phase retains its existing separate cap. Neither context is a Lease
// lifetime and a caller cannot extend the original cap with a later deadline.
func acquisitionContext(lifetime context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return context.WithTimeout(lifetime, operationTimeout)
	}
	limit := time.Now().Add(operationTimeout)
	if deadline.Before(limit) {
		limit = deadline
	}
	return context.WithDeadline(lifetime, limit)
}
