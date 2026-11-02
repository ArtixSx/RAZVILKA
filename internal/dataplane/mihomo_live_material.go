package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

var errMihomoLiveMaterial = errors.New("exact original Mihomo IPv4 node material is unavailable")

// Compilation data only. This review does not reuse another engine's health,
// start a child or admit any policy. The live transaction must independently
// retain the original node/config/WAN owner and earn fresh runtime proof.
func reviewMihomoLiveProfile(ctx context.Context, node *NodeDefaultSourceReview, source *components.MihomoLiveSource, endpoint netip.Addr, port int) (*components.MihomoLiveProfile, error) {
	if node == nil || !node.valid() || node.ref.EngineID != "mihomo" || source == nil {
		return nil, errMihomoLiveMaterial
	}
	var result *components.MihomoLiveProfile
	err := node.WithMaterial(ctx, func(material []byte) error {
		profile, err := providerprofile.VLESSProfileFromJSON(material)
		if err != nil || profile.Transport != "tcp" || profile.Security != "tls" || profile.Insecure {
			return errMihomoLiveMaterial
		}
		raw, err := mihomoNodeSourceProfile(material)
		defer clear(raw)
		if err != nil {
			return err
		}
		options := backendprofile.MihomoOptions{SOCKSPort: port}
		base, err := backendprofile.Mihomo(string(raw), options)
		if err != nil {
			return err
		}
		result, err = source.ReviewProfile(ctx, string(raw), options, nodeDefaultSourceMaterialHash([]byte(base.Config)), profile.Server, endpoint)
		return err
	})
	if err != nil {
		return nil, errors.Join(errMihomoLiveMaterial, err)
	}
	return result, nil
}

// Initial supported intent is one explicit selected node and one service with
// explicit canonical IPv4 prefixes. A DNS/domain/mixed/group plan cannot reach
// the future live transaction by borrowing this structural predicate.
func mihomoLiveIntentNode(plan Plan) (string, error) {
	if plan.LAN != nil || plan.DNS != nil || plan.DomainPolicy != nil || plan.SyntheticDNS != nil || plan.SuspendDNS || plan.DiscardDNS || len(plan.Routes) != 1 {
		return "", errMihomoLiveMaterial
	}
	route := plan.Routes[0]
	node, found := strings.CutPrefix(route.Resolved, "mihomo:")
	if !found || !exactNodeIDPattern.MatchString(node) || route.Selected != route.Resolved || len(route.Domains) != 0 || len(route.CIDRs) == 0 || len(route.CIDRs) > maxPolicyPrefixes {
		return "", errMihomoLiveMaterial
	}
	if len(route.Sources) == 0 || len(route.Sources) > 64 {
		return "", errMihomoLiveMaterial
	}
	for _, raw := range route.Sources {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			address, parseErr := netip.ParseAddr(raw)
			if parseErr != nil || address.String() != raw {
				return "", errMihomoLiveMaterial
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if !prefix.Addr().Is4() || prefix != prefix.Masked() || !privateLANPrefix(prefix) {
			return "", errMihomoLiveMaterial
		}
	}
	seen := map[string]bool{}
	for _, raw := range route.CIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != raw || prefix.Bits() == 0 || seen[raw] {
			return "", errMihomoLiveMaterial
		}
		seen[raw] = true
	}
	if _, err := FrozenProbeService(route); err != nil {
		return "", errors.Join(errMihomoLiveMaterial, err)
	}
	return node, nil
}
