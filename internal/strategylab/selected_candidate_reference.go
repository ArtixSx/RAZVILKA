package strategylab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var ErrSelectedCandidateTraffic = errors.New("saved strategy has no unambiguous supported traffic coverage for its selected protocol and family")

// These values compare the original current producer, never recreate it.
// Traffic is restricted to the saved selection's family and transport; every
// native profile must have an explicit supported filter for that transport.
type SelectedCandidateReference struct {
	ServiceID, Protocol, IPFamily, CandidateID, Incarnation string
	ReceiptID, ManifestSHA256                               string
	SelectionDigest, SourceDigest, CompatibilityDigest      string
	MaterialDigest, ArgumentsDigest, TrafficDigest          string
	Arguments                                               []string
	Traffic                                                 []SelectedCandidateTraffic
}

type SelectedCandidateTraffic struct {
	Protocol, IPFamily string
	First, Last        uint16
}

func (r *SelectedCandidateReview) Reference(ctx context.Context) (SelectedCandidateReference, error) {
	return r.reference(ctx, nil)
}

// ManagedReference compares the original managed owners and builds the detached
// reference within one fresh WithCurrent bracket. The result grants no ongoing
// permission; callers must retain their closing observation after other reads.
func (r *SelectedCandidateReview) ManagedReference(ctx context.Context, runtime *components.ManagedNFQWSRuntimeLease, control *operationgate.ControlEpochReview) (SelectedCandidateReference, error) {
	if runtime == nil || control == nil {
		return SelectedCandidateReference{}, ErrSelectedCandidateChanged
	}
	return r.reference(ctx, func() error {
		if r.runtime != runtime || r.provider == nil || r.provider.managedControl != control {
			return ErrSelectedCandidateChanged
		}
		return nil
	})
}

func (r *SelectedCandidateReview) reference(ctx context.Context, owners func() error) (SelectedCandidateReference, error) {
	var reference SelectedCandidateReference
	err := r.WithCurrent(ctx, func() error {
		if owners != nil {
			if err := owners(); err != nil {
				return err
			}
		}
		var err error
		reference, err = r.referenceLocked()
		return err
	})
	if err != nil {
		return SelectedCandidateReference{}, err
	}
	return reference, nil
}

// Called only inside the original source observation with its handle and
// Manager read locks held. This pure construction performs no new observation.
func (r *SelectedCandidateReview) referenceLocked() (SelectedCandidateReference, error) {
	arguments, err := parseArguments(r.binding.candidate.Arguments)
	if err != nil {
		return SelectedCandidateReference{}, err
	}
	traffic, err := selectedCandidateTraffic(r.selection, arguments)
	if err != nil {
		return SelectedCandidateReference{}, err
	}
	selection := r.selection
	sourceHash := sha256.Sum256(r.image.Data)
	reference := SelectedCandidateReference{ServiceID: selection.ServiceID, Protocol: selection.Protocol, IPFamily: selection.IPFamily,
		CandidateID: r.binding.candidate.ID, Incarnation: r.binding.candidate.Incarnation,
		ReceiptID: r.descriptor.ReceiptID, ManifestSHA256: r.descriptor.ManifestSHA256,
		SourceDigest: hex.EncodeToString(sourceHash[:]), Arguments: slices.Clone(arguments), Traffic: traffic}
	var failures []error
	for _, item := range []struct {
		value any
		to    *string
	}{{selection, &reference.SelectionDigest}, {r.binding.manager.state.CompatibilitySession, &reference.CompatibilityDigest},
		{struct{ Material, Runtime any }{r.review, r.descriptor}, &reference.MaterialDigest},
		{arguments, &reference.ArgumentsDigest}, {traffic, &reference.TrafficDigest}} {
		value, err := selectedReferenceDigest(item.value)
		*item.to = value
		failures = append(failures, err)
	}
	return reference, errors.Join(failures...)
}

func selectedReferenceDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// This deliberately supports only canonical positive decimal port lists and
// ranges. Missing/negative/named/ambiguous filters and a second transport stay
// closed; DEFAULT must not infer IPv6/UDP from a selected IPv4/TCP source.
func selectedCandidateTraffic(selection Selection, arguments []string) ([]SelectedCandidateTraffic, error) {
	if !validFamily(selection.IPFamily) || !validProtocol(selection.Protocol) {
		return nil, ErrSelectedCandidateTraffic
	}
	protocol := selection.Protocol
	if protocol == "quic" {
		protocol = "udp"
	}
	wanted := "--filter-" + protocol
	var result []SelectedCandidateTraffic
	profileHasFilter := false
	for _, argument := range arguments {
		if argument == "--new" {
			if !profileHasFilter {
				return nil, ErrSelectedCandidateTraffic
			}
			profileHasFilter = false
			continue
		}
		key, value, attached := strings.Cut(argument, "=")
		if key != "--filter-tcp" && key != "--filter-udp" {
			continue
		}
		if key != wanted || !attached || profileHasFilter {
			return nil, ErrSelectedCandidateTraffic
		}
		for _, token := range strings.Split(value, ",") {
			firstText, lastText, ranged := strings.Cut(token, "-")
			first, err := strconv.ParseUint(firstText, 10, 16)
			if err != nil || first == 0 || strconv.FormatUint(first, 10) != firstText {
				return nil, ErrSelectedCandidateTraffic
			}
			last := first
			if ranged {
				last, err = strconv.ParseUint(lastText, 10, 16)
				if err != nil || last < first || strconv.FormatUint(last, 10) != lastText {
					return nil, ErrSelectedCandidateTraffic
				}
			}
			result = append(result, SelectedCandidateTraffic{Protocol: protocol, IPFamily: selection.IPFamily, First: uint16(first), Last: uint16(last)})
		}
		profileHasFilter = true
	}
	if !profileHasFilter || len(result) == 0 {
		return nil, ErrSelectedCandidateTraffic
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].First < result[j].First || result[i].First == result[j].First && result[i].Last < result[j].Last
	})
	merged := make([]SelectedCandidateTraffic, 0, len(result))
	for _, traffic := range result {
		if len(merged) != 0 && uint32(traffic.First) <= uint32(merged[len(merged)-1].Last)+1 {
			if traffic.Last > merged[len(merged)-1].Last {
				merged[len(merged)-1].Last = traffic.Last
			}
			continue
		}
		merged = append(merged, traffic)
	}
	return merged, nil
}
