package startuptools

import (
	"context"
	"regexp"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// These are the existing engine catalog's native CLI locations. No factory
// accepts PATH, a file/hash, a version DTO, a runner or a callback as issuer.
func wgProfile(stock bool, engine string) profile {
	p := ubuntuPolicyProfile()
	p.wgAliases = [2]string{"/usr/bin/wg", "/usr/bin/awg"}
	if stock {
		p = stockPolicyProfile()
		p.wgAliases = [2]string{"/opt/bin/wg", "/opt/sbin/awg"}
	}
	p.wgEngine = engine
	p.id += "-" + engine + "-native-v1"
	return p
}

func AcquireUbuntuLegacyWireGuard(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireWG(ctx, provider, wgProfile(false, "wireguard"))
}
func AcquireUbuntuLegacyAmneziaWG(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireWG(ctx, provider, wgProfile(false, "amneziawg"))
}
func AcquireReviewedStockNC1812WireGuard(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireWG(ctx, provider, wgProfile(true, "wireguard"))
}
func AcquireReviewedStockNC1812AmneziaWG(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquireWG(ctx, provider, wgProfile(true, "amneziawg"))
}

var wgToolVersion = [2]*regexp.Regexp{
	regexp.MustCompile(`^wireguard-tools v[0-9]+\.[0-9]+\.[0-9]+(?: - https://git\.zx2c4\.com/wireguard-tools/?)?$`),
	regexp.MustCompile(`^amneziawg-tools v[0-9]+\.[0-9]+\.[0-9]+(?: - https://amnezia\.org)?$`),
}

func validWGVersion(index int, data []byte) bool {
	return index >= 0 && index < 2 && len(data) > 0 && len(data) <= 256 && strings.HasSuffix(string(data), "\n") && wgToolVersion[index].MatchString(strings.TrimSuffix(string(data), "\n"))
}

type wgRunner struct {
	lease  *Lease
	engine string
}

// WGCommandTools requires the WG-enabled single lease. The same lease also
// owns IP/xtables, loader, dependency and path/absence closure and Close/Wait.
func (l *Lease) WGCommandTools(engine string) (dataplane.WGCommandTools, error) {
	if l == nil || l.lifetime == nil {
		return dataplane.WGCommandTools{}, at("WG_UNISSUED", nil)
	}
	c, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return dataplane.WGCommandTools{}, err
	}
	defer l.unlock()
	primary := 0
	if engine == "amneziawg" {
		primary = 1
	}
	if engine != "wireguard" && engine != "amneziawg" || l.profile.wgEngine == "" || l.review == nil || l.review.wgEntry[primary] == nil || l.review.ipEntry == nil || l.digest == "" || l.provider == nil || l.identity.Validate() != nil {
		return dataplane.WGCommandTools{}, at("WG_UNISSUED", nil)
	}
	if l.review.profile.wgEngine != l.profile.wgEngine || l.review.profile.wgAliases != l.profile.wgAliases {
		return dataplane.WGCommandTools{}, at("WG_UNISSUED", nil)
	}
	if err := l.review.wgAbsencesCurrent(c); err != nil {
		return dataplane.WGCommandTools{}, err
	}
	aliases := l.profile.wgAliases
	for i := range aliases {
		if l.review.wgEntry[i] == nil {
			aliases[i] = ""
		} else {
			aliases[i] = l.review.wgEntry[i].path
		}
	}
	return dataplane.WGCommandTools{EngineID: engine, WG: aliases[0], AWG: aliases[1], IP: l.profile.ipAlias, IPTables: l.profile.aliases[0], IP6Tables: l.profile.aliases[1], ReviewSHA256: l.digest, Identity: l.identity, Provider: l.provider, Runner: &wgRunner{l, engine}}, nil
}

func (r *wgRunner) CheckWG(ctx context.Context, expected netidentity.Identity) error {
	if r == nil || r.lease == nil {
		return at("WG_UNISSUED", nil)
	}
	return r.lease.Check(ctx, expected)
}

func (r *wgRunner) RunWG(ctx context.Context, admission dataplane.WGCommandAdmission, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil || admission == nil {
		return nil, at("WG_UNISSUED", nil)
	}
	return r.lease.runWG(WithCommandAdmission(ctx, admission), r.engine, name, args...)
}
