package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strconv"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// SyntheticBaselineTransitionEffects compiles the standby tuple from the
// ORIGINAL retained mapping. It is common receipt intent only: the SAME
// Manager must prove firmware equivalence, perform ACKed additions/readback
// and register capture dependencies before any DNS publication can use it.
// Neither returning this plan nor its digest is transition readiness.
func SyntheticBaselineTransitionEffects(ctx context.Context, transport *SyntheticDNSTransportPlan, domain *DomainPolicyRuntimePlan, mapping *dnscontrol.SyntheticDNSMapping) (PolicyEffectPlan, error) {
	if ctx == nil || mapping == nil || ValidateSyntheticDNSTransportPlan(transport, domain) != nil {
		return PolicyEffectPlan{}, ErrSyntheticBaselineTransition
	}
	record, err := mapping.Observation(ctx)
	if err != nil {
		return PolicyEffectPlan{}, err
	}
	definition := transport.Definition
	if record.Authority.Generation != domain.Generation || record.Authority.Exclusions != transport.DNS.Exclusions || record.Client != definition.Client || record.DeviceID != definition.DeviceID || record.MAC != definition.MAC || record.Ingress != definition.Ingress || !slices.Contains(definition.ExactNames, record.QName) {
		return PolicyEffectPlan{}, ErrSyntheticBaselineTransition
	}
	plan, err := syntheticBaselineTransitionEffects(record)
	if err != nil {
		return PolicyEffectPlan{}, err
	}
	if err := mapping.Current(ctx); err != nil {
		return PolicyEffectPlan{}, err
	}
	return plan, nil
}

// Private pure serializer for already compared original observations. Tests
// use comparison models here; there is no apply/ready API taking these DTOs.
func syntheticBaselineTransitionEffects(record dnscontrol.SyntheticDNSMappingObservation) (PolicyEffectPlan, error) {
	if !lanPolicyHash(record.Authority.Generation) || len(record.PublicationID) != 32 || !netip.MustParsePrefix("198.18.0.0/15").Contains(record.Synthetic) || !record.RealIPv4.Is4() || !record.RealIPv4.IsGlobalUnicast() || record.RealIPv4.IsPrivate() || record.RealIPv4.IsLoopback() || netip.MustParsePrefix("198.18.0.0/15").Contains(record.RealIPv4) || dnscontrol.ValidateSyntheticDNSDefinition(dnscontrol.SyntheticDNSDefinition{Client: record.Client, DeviceID: record.DeviceID, MAC: record.MAC, Ingress: record.Ingress, ExactNames: []string{record.QName}}) != nil {
		return PolicyEffectPlan{}, ErrSyntheticBaselineTransition
	}
	id := sha256.Sum256([]byte(record.Authority.Generation + "\x00" + record.PublicationID + "\x00" + record.Client.String() + "\x00" + record.MAC + "\x00" + record.Ingress + "\x00" + record.Synthetic.String() + "\x00" + record.RealIPv4.String()))
	chain := "RZSB_" + hex.EncodeToString(id[:10])
	plan := PolicyEffectPlan{Generation: record.Authority.Generation}
	plan.Effects = append(plan.Effects,
		PolicyEffect{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-N", chain}, Delete: []string{"-t", "nat", "-X", chain}},
		PolicyEffect{Tool: PolicyEffectIPTables, Add: []string{"-t", "nat", "-A", chain, "-p", "tcp", "-j", "DNAT", "--to-destination", record.RealIPv4.String()}, Delete: []string{"-t", "nat", "-D", chain, "-p", "tcp", "-j", "DNAT", "--to-destination", record.RealIPv4.String()}, Needs: []int{0}},
	)
	for _, port := range []int{80, 443} {
		args := []string{"PREROUTING", "-i", record.Ingress, "-s", record.Client.String() + "/32", "-d", record.Synthetic.String() + "/32", "-m", "mac", "--mac-source", record.MAC, "-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(port), "-j", chain}
		plan.Effects = append(plan.Effects, PolicyEffect{Tool: PolicyEffectIPTables, Add: append([]string{"-t", "nat", "-A"}, args...), Delete: append([]string{"-t", "nat", "-D"}, args...), Needs: []int{0, 1}})
	}
	// No positive bypass mark: this exact restorative tuple must continue to
	// accept the OLD now-excluded client after its proxy selector is removed.
	// No RPDB/default-route/foreign-bit reset or router-originated WAN socket.
	if _, err := PolicyEffectPlanDigest(plan); err != nil {
		return PolicyEffectPlan{}, err
	}
	return plan, nil
}
