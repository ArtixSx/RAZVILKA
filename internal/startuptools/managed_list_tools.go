package startuptools

import (
	"context"
	"errors"
	"os"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

const managedListWGProfile = "managed-list"

func managedListProfile() profile {
	p := wgProfile(true, managedListWGProfile)
	p.id = "stock-nc1812-arm64-managed-list-optional-wg-v1"
	return p
}

// AcquireReviewedStockNC1812ManagedList retains one original policy/IP/xtables
// lease and both fixed WG aliases. Missing WG/AWG is held absence, so other
// consumers can start; present entries must pass original ELF/dependency and
// actual held-fd --version checks. There is no PATH discovery or fallback.
func AcquireReviewedStockNC1812ManagedList(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireWG(ctx, provider, managedListProfile())
}

func wgRequiredEntry(mode string) (int, error) {
	switch mode {
	case "wireguard":
		return 0, nil
	case "amneziawg":
		return 1, nil
	case managedListWGProfile:
		return -1, nil
	default:
		return -1, at("WG_PROFILE", nil)
	}
}

// This is a callback-free subset of the full Linux held closure check. It
// prevents descriptor issuance for another engine after an absent WG alias
// changes. Actual commands still require the original complete Lease.Check
// and held-fd Start/Wait; this comparison alone issues no native tool proof.
func (r *heldReview) wgAbsencesCurrent(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return at("WG_ABSENCE", nil)
	}
	if _, err := wgRequiredEntry(r.profile.wgEngine); err != nil {
		return err
	}
	for i, alias := range r.profile.wgAliases {
		if alias == "" {
			return at("WG_PROFILE", nil)
		}
		if r.wgEntry[i] != nil {
			continue
		}
		if !r.absent[alias] {
			return at("WG_ABSENCE_UNISSUED", nil)
		}
		if _, err := os.Lstat(alias); !errors.Is(err, os.ErrNotExist) {
			return at("WG_ABSENCE_CHANGED", err)
		}
	}
	return ctx.Err()
}
