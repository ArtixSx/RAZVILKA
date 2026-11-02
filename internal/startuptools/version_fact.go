package startuptools

import (
	"context"
	"encoding/hex"
	"reflect"
	"slices"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// This is a transient observation of TWO fixed static version strings, not a
// process/kernel fact or an execution grant. It cannot escape its original
// read-only scope; no serialized values or subsequent scopes can recreate it.
type scopedVersionFact struct {
	self        *scopedVersionFact
	lease       *Lease
	scope       *toolReadObservation
	review      *heldReview
	provider    *netidentity.Provider
	lifetime    context.Context
	entry       [2]*heldImage
	identity    netidentity.Identity
	digest      string
	profile     profile
	environment []string
}

// Exact reviewed code/profile pairs only. Ubuntu's 1.8.10 binary was also
// matched byte-for-byte to the official 1.8.10-3ubuntu2 amd64 package and its
// applied distro patch series; see
// docs/measurements/2026-11-01/native-version-fact/README.md.
// Unknown builds retain real version subprocesses on every Check.
func staticVersionProfile(p profile) bool {
	base := ubuntuProfile()
	if p.stock {
		base = stockProfile()
	}
	if p.arch != base.arch || p.aliases != base.aliases || p.main != base.main || p.loader != base.loader || p.extension != base.extension || !slices.Equal(p.libraries, base.libraries) || !reflect.DeepEqual(p.pins, base.pins) {
		return false
	}
	if p.mainSHA == base.mainSHA && p.version == base.version {
		return true
	}
	return !p.stock && (p.id == "ci-only-native-platform-classification-modeled" || p.id == "ci-only-native-platform-classification-modeled-managed-list") && p.mainSHA == "38ac0252c751be1c89ebc2e2eb6a05bf1720b05eea552a1dee8380af94d72a52" && p.version == "1.8.10 (legacy)"
}

func cloneVersionProfile(p profile) profile {
	p.libraries = slices.Clone(p.libraries)
	if p.pins != nil {
		pins := make(map[string][]string, len(p.pins))
		for path, hashes := range p.pins {
			pins[path] = slices.Clone(hashes)
		}
		p.pins = pins
	}
	return p
}

func (l *Lease) versionFactSource() bool {
	if l == nil || l.review == nil || !staticVersionProfile(l.profile) {
		return false
	}
	image := l.review.entry[0]
	return image != nil && image == l.review.entry[1] && image.file != nil && image.path == l.profile.main && hex.EncodeToString(image.hash[:]) == l.profile.mainSHA
}

// Called with the original gate held. Any supplied marker must still be the
// live original source; invalid markers never fall back to ordinary execution.
func (l *Lease) retainedVersionFact(ctx context.Context) (*scopedVersionFact, error) {
	o, present := readObservationMarker(ctx)
	if !present {
		return nil, nil
	}
	if err := l.readObservationCurrent(ctx); err != nil {
		return nil, err
	}
	f := l.versionFact
	if f == nil || f.scope != o {
		return nil, nil
	}
	if f.self != f || f.lease != l || f.review != l.review || f.provider != l.provider || f.lifetime != l.lifetime || f.entry != l.review.entry || f.identity != l.identity || f.digest != l.digest || !reflect.DeepEqual(f.profile, l.profile) || !slices.Equal(f.environment, l.profile.environment()) || !l.versionFactSource() {
		return nil, at("VERSION_FACT_CHANGED", nil)
	}
	return f, nil
}

// Only Lease.current calls this AFTER the complete version batch AND the
// Provider's closing observation succeeded. Never mark a partial/failed batch.
func (l *Lease) rememberVersionFact(ctx context.Context) error {
	o, present := readObservationMarker(ctx)
	if !present {
		return nil
	}
	if err := l.readObservationCurrent(ctx); err != nil {
		return err
	}
	if !l.versionFactSource() {
		return nil
	}
	if existing, err := l.retainedVersionFact(ctx); err != nil {
		return err
	} else if existing != nil {
		return nil
	}
	f := &scopedVersionFact{lease: l, scope: o, review: l.review, provider: l.provider, lifetime: l.lifetime, entry: l.review.entry, identity: l.identity, digest: l.digest, profile: cloneVersionProfile(l.profile), environment: slices.Clone(l.profile.environment())}
	f.self = f
	l.versionFact = f // At most one scope retained; the original marker revokes it.
	return nil
}

func (l *Lease) forgetVersionFact(ctx context.Context) {
	o, present := readObservationMarker(ctx)
	if present && l.versionFact != nil && l.versionFact.scope == o {
		l.versionFact = nil
	}
}
