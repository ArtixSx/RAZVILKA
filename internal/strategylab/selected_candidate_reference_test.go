package strategylab

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestSelectedCandidateTrafficRestrictsSavedFamilyAndTransport(t *testing.T) {
	selection := Selection{Protocol: "tcp", IPFamily: "ipv4"}
	traffic, err := selectedCandidateTraffic(selection, []string{"--filter-tcp=443,80-81", "--lua-desync=fake:blob=tls_clienthello", "--new", "--filter-tcp=81-82"})
	wanted := []SelectedCandidateTraffic{{Protocol: "tcp", IPFamily: "ipv4", First: 80, Last: 82}, {Protocol: "tcp", IPFamily: "ipv4", First: 443, Last: 443}}
	if err != nil || !slices.Equal(traffic, wanted) {
		t.Fatal("explicit profile union changed protocol/family/ports", traffic, err)
	}
	selection = Selection{Protocol: "quic", IPFamily: "ipv6"}
	traffic, err = selectedCandidateTraffic(selection, []string{"--filter-udp=443"})
	if err != nil || !slices.Equal(traffic, []SelectedCandidateTraffic{{Protocol: "udp", IPFamily: "ipv6", First: 443, Last: 443}}) {
		t.Fatal("QUIC selection did not restrict actual UDP/IPv6 coverage", traffic, err)
	}
}

// This exercises reference construction against the actual saved source leaf,
// with a successful unchanged baseline. It does not model a component lease or
// claim that the source-only fixture can issue a public managed reference.
func TestSelectedCandidateReferenceConstructionRetainsClosingSourceCheck(t *testing.T) {
	for _, change := range []string{"unchanged", "selection-changed", "source-before", "source-after"} {
		t.Run(change, func(t *testing.T) {
			m, r := selectedReviewSourceFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			mutate := func() error {
				return os.WriteFile(m.Path, append(slices.Clone(r.image.Data), '\n'), 0600)
			}
			if change == "selection-changed" {
				changed := r.selection
				changed.Frozen = false
				m.state.Selections[selectionKey(changed.ServiceID, changed.Protocol, changed.IPFamily)] = changed
			}
			if change == "source-before" {
				if err := mutate(); err != nil {
					t.Fatal(err)
				}
			}
			reference, err := func() (SelectedCandidateReference, error) {
				r.mu.Lock()
				defer r.mu.Unlock()
				m.mu.RLock()
				defer m.mu.RUnlock()
				if err := r.sourceLocked(ctx); err != nil {
					return SelectedCandidateReference{}, err
				}
				ref, err := r.referenceLocked()
				if change == "source-after" {
					err = errors.Join(err, mutate())
				}
				if err = errors.Join(err, r.sourceLocked(ctx)); err != nil {
					return SelectedCandidateReference{}, err
				}
				return ref, nil
			}()
			if change == "unchanged" {
				if err != nil || reference.CandidateID != r.binding.candidate.ID || reference.SourceDigest == "" || len(reference.Traffic) == 0 {
					t.Fatalf("unchanged saved source refused: %v", err)
				}
			} else if err == nil || reference.CandidateID != "" {
				t.Fatalf("changed source issued reference: %v", err)
			}
		})
	}
}

func TestSelectedCandidateManagedReferenceCannotReconstructOwners(t *testing.T) {
	_, original := selectedReviewSourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, source := range []*SelectedCandidateReview{nil, {}, {self: original, binding: original.binding}, original} {
		for _, owners := range []struct {
			runtime *components.ManagedNFQWSRuntimeLease
			control *operationgate.ControlEpochReview
		}{{}, {runtime: &components.ManagedNFQWSRuntimeLease{}, control: &operationgate.ControlEpochReview{}}} {
			ref, err := source.ManagedReference(ctx, owners.runtime, owners.control)
			if err == nil || ref.CandidateID != "" || ref.SourceDigest != "" {
				t.Fatal("detached owners issued managed reference", ref, err)
			}
		}
	}
}

func TestSelectedCandidateTrafficRefusesMissingAmbiguousAndMixedProfiles(t *testing.T) {
	for _, arguments := range [][]string{
		{}, {"--lua-desync=fake:blob=tls_clienthello"}, {"--filter-udp=443"},
		{"--filter-tcp=443", "--filter-udp=443"}, {"--filter-tcp=443", "--new", "--filter-udp=443"},
		{"--filter-tcp=443", "--new"}, {"--new", "--filter-tcp=443"}, {"--filter-tcp=443", "--filter-tcp=80"},
		{"--filter-tcp=~443"}, {"--filter-tcp=https"}, {"--filter-tcp=*"}, {"--filter-tcp=0"},
		{"--filter-tcp=65536"}, {"--filter-tcp=0443"}, {"--filter-tcp=443-80"}, {"--filter-tcp=80-"}, {"--filter-tcp=443,"},
	} {
		if _, err := selectedCandidateTraffic(Selection{Protocol: "tcp", IPFamily: "ipv4"}, arguments); err == nil {
			t.Fatal("ambiguous native coverage granted", arguments)
		}
	}
}

func TestSelectedCandidateReferenceRejectsUncontrolledCopiedClosedSource(t *testing.T) {
	_, original := selectedReviewSourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, review := range []*SelectedCandidateReview{nil, {}, {self: original, binding: original.binding}, original} {
		ref, err := review.Reference(ctx)
		if err == nil || ref.CandidateID != "" || ref.SourceDigest != "" || len(ref.Traffic) != 0 {
			t.Fatal("uncontrolled source model issued comparison proof", ref, err)
		}
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if ref, err := original.Reference(ctx); err == nil || ref.CandidateID != "" {
		t.Fatal("closed source produced a reference", ref, err)
	}
}
