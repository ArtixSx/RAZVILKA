package app

import (
	"context"
	"slices"
	"strings"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Acquire only comparison data from the original finite, current source.
// Its owner must retain the original review and component lease for admission
// at actual leaves; this helper grants no queue, LAN or process permission.
func defaultRouteNFQWSReference(ctx context.Context, original *strategylab.SelectedCandidateReview) (strategylab.SelectedCandidateReference, error) {
	reference, err := original.Reference(ctx)
	if err != nil {
		return strategylab.SelectedCandidateReference{}, err
	}
	if !defaultRouteNFQWSReferenceValid(&reference) {
		return strategylab.SelectedCandidateReference{}, strategylab.ErrSelectedCandidateTraffic
	}
	return reference, nil
}

// Shape and detached-image integrity checks cannot recreate a source owner.
func defaultRouteNFQWSReferenceValid(r *strategylab.SelectedCandidateReference) bool {
	if r == nil || r.ServiceID == "" || r.ServiceID == "default" || len(r.ServiceID) > 128 || strings.TrimSpace(r.ServiceID) != r.ServiceID || strings.ContainsAny(r.ServiceID, "\x00\r\n") || r.CandidateID == "" || len(r.CandidateID) > 128 || strings.TrimSpace(r.CandidateID) != r.CandidateID || strings.ContainsAny(r.CandidateID, "\x00\r\n") || !defaultRouteNFQWSID(r.Incarnation) || !defaultRouteNFQWSID(r.ReceiptID) || r.IPFamily != "ipv4" && r.IPFamily != "ipv6" || len(r.Arguments) == 0 || len(r.Arguments) > 128 || len(r.Traffic) == 0 || len(r.Traffic) > 16 {
		return false
	}
	for _, hash := range []string{r.ManifestSHA256, r.SelectionDigest, r.SourceDigest, r.CompatibilityDigest, r.MaterialDigest, r.ArgumentsDigest, r.TrafficDigest} {
		if !defaultRouteHash(hash) {
			return false
		}
	}
	protocol := r.Protocol
	if protocol == "quic" {
		protocol = "udp"
	}
	if protocol != "tcp" && protocol != "udp" {
		return false
	}
	for _, argument := range r.Arguments {
		if argument == "" || len(argument) > 2048 || strings.ContainsAny(argument, "\x00\r\n") {
			return false
		}
	}
	for i, traffic := range r.Traffic {
		if traffic.Protocol != protocol || traffic.IPFamily != r.IPFamily || traffic.First == 0 || traffic.Last < traffic.First || i > 0 && uint32(traffic.First) <= uint32(r.Traffic[i-1].Last)+1 {
			return false
		}
	}
	return r.ArgumentsDigest == defaultRouteDigest(r.Arguments) && r.TrafficDigest == defaultRouteDigest(r.Traffic)
}

func defaultRouteNFQWSID(value string) bool {
	return len(value) == 32 && strings.Trim(value, "0123456789abcdef") == ""
}

func defaultRouteCloneNFQWSReference(reference *strategylab.SelectedCandidateReference) *strategylab.SelectedCandidateReference {
	if reference == nil {
		return nil
	}
	copy := *reference
	copy.Arguments = slices.Clone(copy.Arguments)
	copy.Traffic = slices.Clone(copy.Traffic)
	return &copy
}

// NFQWSReference returns the exact source comparison for a compiled positive
// service. The actual managed constructor must compare it with the same
// retained source and consume Rules' exact family/protocol/port coverage.
func (c *DefaultRouteCompilation) NFQWSReference(serviceID string) (strategylab.SelectedCandidateReference, bool) {
	if c != nil {
		for _, rule := range c.rules {
			if rule.ServiceID == serviceID && rule.Route == "nfqws2" {
				if reference := defaultRouteCloneNFQWSReference(c.snapshot.Paths[serviceID].NFQWS); reference != nil {
					return *reference, true
				}
			}
		}
	}
	return strategylab.SelectedCandidateReference{}, false
}

func defaultRouteTrafficOverlaps(left, right DefaultRouteRule) bool {
	return left.Protocol == "" || right.Protocol == "" || left.Protocol == right.Protocol && left.FirstPort <= right.LastPort && right.FirstPort <= left.LastPort
}
