package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// BuildManagedNFQWSIPv4LANList is a separate, concrete packet-purpose issuer.
// A DTO, caller callback or wider source prefix cannot extend the legacy
// host-only issuer. It requires the SAME original consent Store, actual packet
// scope, selected material and exact Home/negative gates. It issues no command.
// These owners must remain retained by the actual App Apply/Stop participant.
func BuildManagedNFQWSIPv4LANList(ctx context.Context, input Input, material *NFQWSActiveMaterial, scope *defaultconsent.ScopeReview, packet *physicalscope.IPv4LANPacketScope, store *config.Store, expected config.Config, now time.Time) (Plan, error) {
	if now.IsZero() || material == nil || material.self != material || scope == nil || packet == nil || store == nil || !scope.MatchesConfigStore(store) || !reflect.DeepEqual(store.Get(), expected) || input.managedNFQWS != nil {
		return Plan{}, ErrNFQWSScopedOwner
	}
	check := func() error {
		if !scope.MatchesConfigStore(store) || !reflect.DeepEqual(store.Get(), expected) {
			return ErrReviewChanged
		}
		if err := scope.Current(ctx); err != nil {
			return err
		}
		if err := packet.Current(ctx); err != nil {
			return err
		}
		if err := material.Current(ctx); err != nil {
			return err
		}
		if !reflect.DeepEqual(packet.PacketFacts().Identity, material.intent.NetworkIdentity) || packet.PacketFacts().Control != material.control.Reference() {
			return ErrNFQWSScopedOwner
		}
		if err := scope.Current(ctx); err != nil {
			return err
		}
		if !scope.MatchesConfigStore(store) || !reflect.DeepEqual(store.Get(), expected) {
			return ErrReviewChanged
		}
		return nil
	}
	if err := check(); err != nil {
		return Plan{}, errors.Join(ErrNFQWSScopedOwner, err)
	}
	facts := packet.PacketFacts()
	selection := material.source.Selection()
	if selection.Mode != strategylab.ModeManual || !selection.Frozen || selection.ServiceID != material.reference.ServiceID || selection.Protocol != "tcp" || selection.IPFamily != "ipv4" {
		return Plan{}, ErrNFQWSScopedOwner
	}
	if err := nfqwsIPv4LANPacketInput(input, expected, scope.Reference(), facts, material.reference.ServiceID, material.reference.Protocol, material.reference.IPFamily); err != nil {
		return Plan{}, err
	}
	input.managedNFQWS = material
	plan, err := BuildAt(input, now)
	if err != nil {
		return Plan{}, err
	}
	if err := check(); err != nil {
		return Plan{}, errors.Join(ErrNFQWSScopedOwner, err)
	}
	return plan, nil
}

// Pure comparison only, not a producer. The public issuer above requires all
// concrete original owners before and after using this immutable projection.
func nfqwsIPv4LANPacketInput(input Input, cfg config.Config, ref defaultconsent.Reference, f physicalscope.IPv4LANPacketFacts, serviceID, protocol, family string) error {
	p := cfg.NetworkPolicy
	if input.SafeMode || input.managedXraySelectedTCP != nil || input.DNS != nil || input.DomainPolicy != nil || input.SyntheticDNS != nil || input.SuspendDNS || input.DiscardDNS || len(input.RetiringAdapters) != 0 || len(input.EngineConfigDrafts) != 0 || !lanPolicyHash(input.NetworkProfileID) {
		return ErrNFQWSScopedOwner
	}
	engineIDs := map[string]bool{}
	for _, e := range input.Engines {
		if e.ID != "nfqws2" && e.ID != NetworkPolicyAdapterID || engineIDs[e.ID] {
			return ErrNFQWSScopedOwner
		}
		engineIDs[e.ID] = true
	}
	if len(engineIDs) != 2 {
		return ErrNFQWSScopedOwner
	}
	if cfg.Revision == 0 || cfg.Revision == ^uint64(0) || cfg.SafeMode || cfg.ServiceControl.Stopped || !config.CurrentDefaultRouteScopeConsent(cfg) || p == nil || config.ValidateListNetworkPolicy(p) != nil || cfg.DefaultRouteConsent == nil || p.Clients.Mode != "lan_except" || p.Clients.NewDevices != "inherit" || len(p.Clients.DeviceIDs) != 0 || len(p.Clients.SegmentIDs) != 1 || protocol != "tcp" || family != "ipv4" || len(f.IPv4Prefixes) != 1 || input.Revision != cfg.Revision+1 || len(input.Routes) != 1 || input.LAN == nil || ValidateLANPolicyRuntime(input.LAN) != nil || input.LAN.Mode != LANPolicyNFQWSDirectMode || len(input.LAN.Ingress) != 1 {
		return ErrNFQWSScopedOwner
	}
	consent := cfg.DefaultRouteConsent
	if ref.Schema != 1 || ref.NodeGeneration != 0 || ref.NodeMaterialSHA256 != "" || ref.ApprovalRevision != consent.ApprovalRevision || ref.PolicyRevision != p.Revision || ref.ConsentDigest != consent.Digest || ref.InstallationID != f.Control.InstallationID || ref.Sequence != f.Control.Sequence || ref.EngineID != "" || ref.NodeID != "" || ref.Resolved != "" || f.Intent.Revision != consent.ApprovalRevision || f.Intent.PolicyRevision != p.Revision || f.Intent.Mode != "lan_except" || f.Intent.NewDevices != "inherit" || !slices.Equal(f.Intent.SegmentIDs, p.Clients.SegmentIDs) || !nfqwsPacketSameStrings(f.Intent.ExcludedDeviceIDs, p.Clients.ExcludedDeviceIDs) || !nfqwsPacketSameStrings(f.Intent.ExcludedCIDRs, p.Clients.ExcludedCIDRs) {
		return ErrNFQWSScopedOwner
	}
	if !f.Home.Home || f.Home.Guest || (p.Clients.SegmentIDs[0] != f.Home.ID && p.Clients.SegmentIDs[0] != f.Home.NativeName) {
		return ErrNFQWSScopedOwner
	}
	route := input.Routes[0]
	state, exists := cfg.Services[serviceID]
	enabled := 0
	for _, v := range cfg.Services {
		if v.Enabled {
			enabled++
		}
	}
	if !exists || !state.Enabled || state.Route != "nfqws2" || enabled != 1 || len(state.Sources) != 0 || route.LogicalServiceID != serviceID || route.Selected != "nfqws2" || route.Resolved != "nfqws2" || route.NetworkPolicyRole != "override" || route.NetworkPolicyGeneration != input.LAN.Generation || len(route.Domains) != 0 || len(route.SourceRefs) != 0 || len(route.CIDRs) == 0 || len(route.CIDRs) > 1024 || !slices.Equal(route.Sources, f.IPv4Prefixes) || !slices.Equal(route.Ingress, []string{f.Home.Interface}) {
		return ErrNFQWSScopedOwner
	}
	source, e := netip.ParsePrefix(f.IPv4Prefixes[0])
	if e != nil || !source.Addr().Is4() || source != source.Masked() || source.Bits() == 0 {
		return ErrNFQWSScopedOwner
	}
	for _, raw := range route.CIDRs {
		d, e := netip.ParsePrefix(raw)
		if e != nil || !d.Addr().Is4() || d.String() != raw || d != d.Masked() || !nfqwsScopedPublic(d) {
			return ErrNFQWSScopedOwner
		}
	}
	if err := nfqwsPacketDestinationExclusions(p, route.CIDRs); err != nil {
		return err
	}
	g := input.LAN.Ingress[0]
	if g.SegmentID != p.Clients.SegmentIDs[0] || g.Interface != f.Home.Interface || g.Membership != "all" || len(g.IncludedMACs) != 0 || !slices.Equal(g.Sources, f.IPv4Prefixes) {
		return ErrNFQWSScopedOwner
	}
	expectedMACs := []string{}
	for _, m := range append(slices.Clone(f.OwnedMACs), f.ExcludedMACs...) {
		expectedMACs = append(expectedMACs, strings.ToUpper(m))
	}
	for _, r := range f.Home.RouterNeighbors {
		expectedMACs = append(expectedMACs, strings.ToUpper(r.MAC))
	}
	slices.Sort(expectedMACs)
	expectedMACs = slices.Compact(expectedMACs)
	if len(f.OwnedMACs) == 0 || !slices.Equal(g.ExcludedMACs, expectedMACs) {
		return ErrNFQWSScopedOwner
	}
	negatives := []string{}
	for _, raw := range p.Clients.ExcludedCIDRs {
		n, e := netip.ParsePrefix(raw)
		if e != nil {
			return ErrNFQWSScopedOwner
		}
		if n.Addr().Is4() && n.Overlaps(source) {
			if n.Bits() < source.Bits() {
				n = source
			}
			negatives = append(negatives, n.String())
		}
	}
	for _, raw := range f.OwnedAddresses {
		a, e := netip.ParseAddr(raw)
		if e != nil {
			return ErrNFQWSScopedOwner
		}
		if a.Is4() && source.Contains(a) {
			negatives = append(negatives, netip.PrefixFrom(a, 32).String())
		}
	}
	slices.Sort(negatives)
	negatives = slices.Compact(negatives)
	minimal := []string{}
	for _, raw := range negatives {
		n := netip.MustParsePrefix(raw)
		covered := false
		for _, other := range negatives {
			o := netip.MustParsePrefix(other)
			if other != raw && o.Bits() < n.Bits() && o.Contains(n.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			minimal = append(minimal, raw)
		}
	}
	negatives = minimal
	if !slices.Equal(g.ExcludedSources, negatives) {
		return ErrNFQWSScopedOwner
	}
	return nil
}
func nfqwsPacketSameStrings(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// Independently preserve the saved exclusion contract at the issuer, even if
// a caller composes a different CIDR DTO around the original scope owners.
func nfqwsPacketDestinationExclusions(p *config.NetworkPolicy, positive []string) error {
	exclusions, err := config.EffectiveResourceExclusions(p)
	if err != nil || len(exclusions.BroadTLDs) != 0 {
		return ErrNFQWSScopedOwner
	}
	var negative []netip.Prefix
	add := func(kind, value string) error {
		switch kind {
		case "ip":
			a, e := netip.ParseAddr(value)
			if e != nil {
				return ErrNFQWSScopedOwner
			}
			negative = append(negative, netip.PrefixFrom(a, a.BitLen()))
		case "cidr":
			p, e := netip.ParsePrefix(value)
			if e != nil {
				return ErrNFQWSScopedOwner
			}
			negative = append(negative, p)
		default:
			return ErrNFQWSScopedOwner
		}
		return nil
	}
	for _, set := range [][]config.ResourceMatch{exclusions.Manual, exclusions.Russian} {
		for _, m := range set {
			if err := add(m.Kind, m.Value); err != nil {
				return err
			}
		}
	}
	for _, r := range p.Rules {
		if r.Action != "direct" || len(r.DeviceIDs) != 0 {
			return ErrNFQWSScopedOwner
		}
		if err := add(r.Kind, r.Value); err != nil {
			return err
		}
	}
	for _, raw := range positive {
		d, err := netip.ParsePrefix(raw)
		if err != nil {
			return ErrNFQWSScopedOwner
		}
		for _, n := range negative {
			if d.Overlaps(n) {
				return ErrNFQWSScopedOwner
			}
		}
	}
	return nil
}
