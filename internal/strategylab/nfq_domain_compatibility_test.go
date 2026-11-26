package strategylab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func nfqDomainReviewFixture(t *testing.T) (*nfqDomainFiles, compatibilityReview, []string) {
	t.Helper()
	f, err := newNFQDomainFiles(nfqDomainPrivateTestDir(t), []string{"video.example"}, []string{"private.video.example"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.close() })
	candidate := []string{"--filter-tcp=443", "--lua-desync=fake:blob=tls_clienthello"}
	digest, _ := selectedReferenceDigest(candidate)
	review := compatibilityReview{BaseArguments: compatibilityBase(t.TempDir()), Domain: &compatibilityDomainReview{1, strings.Repeat("a", 64), digest, f.include, f.exclude}}
	return f, review, candidate
}

// Real argv composition and closed parser, modeled two-phase native leaf.
// This test supplies no public source/component owner or runtime permission.
func TestNFQDomainCompatibilityUsesBothExactFinalCommands(t *testing.T) {
	for _, failure := range []string{"none", "dry-run", "lua-init", "unknown"} {
		t.Run(failure, func(t *testing.T) {
			_, review, candidate := nfqDomainReviewFixture(t)
			var commands [][]string
			v := CompatibleValidator{Binary: "reviewed-program", BaseArguments: slices.Clone(review.BaseArguments), TrustedAssets: true, Timeout: time.Second, domain: review.Domain, Provider: compatibilityProviderFunc(func(_ context.Context, _ string, args ...string) (CompatibilityCompletion, error) {
				phase, err := compatibilityReviewCommandPhase(review, args)
				if err != nil {
					t.Fatal("actual final argv refused", err)
				}
				commands = append(commands, slices.Clone(args))
				if failure == phase {
					return CompatibilityCompletion{Started: true, Quiescent: true}, errors.New("modeled native rejection")
				}
				if failure == "unknown" {
					return CompatibilityCompletion{Started: true}, ErrCompatibilityQuiescenceUnknown
				}
				return CompatibilityCompletion{Started: true, Quiescent: true}, nil
			})}
			result := v.Validate(context.Background(), candidate)
			if failure == "none" {
				if !result.OK || !result.Native || !result.LuaChecked || len(commands) != 2 {
					t.Fatal("complete modeled phases missing", result, len(commands))
				}
				if !slices.Equal(commands[0][1:], commands[1][:len(commands[1])-1]) {
					t.Fatal("different final commands")
				}
			} else if result.OK || result.LuaChecked || failure == "dry-run" && len(commands) != 1 || failure == "unknown" && !result.QuiescenceUnknown {
				t.Fatal("rejection/unknown promoted", result, len(commands))
			}
		})
	}
}

func TestNFQDomainTaggedGrammarRefusesRuntimePathsAndMissingNegatives(t *testing.T) {
	_, review, candidate := nfqDomainReviewFixture(t)
	command := append([]string{"--dry-run", "--intercept=0"}, review.BaseArguments...)
	command = append(command, candidate...)
	command = append(command, nfqDomainArguments(review.Domain.Include.Path, review.Domain.Exclude.Path)...)
	if _, err := compatibilityReviewCommandPhase(review, command); err != nil {
		t.Fatal(err)
	}
	if _, err := compatibilityCommandPhase(review.BaseArguments, command); err == nil {
		t.Fatal("domain argv entered legacy grammar")
	}
	for _, kind := range []string{"exclude-path", "include-path", "omit-exclude", "unsafe-reasm", "hostname-cache", "intercept", "extra-profile", "candidate", "unbound-tag"} {
		args := slices.Clone(command)
		changed := review
		switch kind {
		case "exclude-path":
			args[len(args)-1] = "--hostlist-exclude=/tmp/caller.list"
		case "include-path":
			args[len(args)-2] = "--hostlist=/tmp/caller.list"
		case "omit-exclude":
			args = args[:len(args)-1]
		case "unsafe-reasm":
			args[len(args)-5] = "--reasm-disable=quic_initial"
		case "hostname-cache":
			args[len(args)-3] = "--ipcache-hostname=1"
		case "intercept":
			args[1] = "--intercept=1"
		case "extra-profile":
			args = append(args, "--new")
		case "candidate":
			args[2+len(review.BaseArguments)] = "--filter-tcp=80"
		case "unbound-tag":
			changed.Domain = nil
		}
		if _, err := compatibilityReviewCommandPhase(changed, args); err == nil {
			t.Fatal("ambiguous/unowned command accepted", kind)
		}
	}
}

func TestNFQDomainMissingOriginalOwnersRefuseWithoutMaterialization(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	parent := t.TempDir()
	source := &SelectedCandidateReview{path: filepath.Join(parent, "strategy.json")}
	source.self = source
	for _, r := range []*SelectedCandidateReview{nil, {}, source} {
		if material, err := ReviewManagedNFQWSDomainMaterial(ctx, r, &components.ManagedNFQWSRuntimeLease{}, &operationgate.ControlEpochReview{}, []string{"video.example"}, nil); err == nil || material != nil {
			t.Fatal("DTO owners admitted material")
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused declaration wrote files", err)
	}
	for _, r := range []*NFQWSDomainMaterial{nil, {}, {self: &NFQWSDomainMaterial{}, ready: true}} {
		if r.Current(ctx) == nil || r.RetireCompatibility(ctx) == nil {
			t.Fatal("copied/declared material granted current/retirement")
		}
	}
}

func TestNFQDomainPendingCloseCannotReleaseOriginalCompletion(t *testing.T) {
	f, review, _ := nfqDomainReviewFixture(t)
	r := &NFQWSDomainMaterial{files: f, review: *review.Domain, pending: true, completion: &ManagedCompatibilityCompletion{}}
	r.self = r
	if !errors.Is(r.Close(), ErrCompatibilityQuiescenceUnknown) || r.closed || f.closed {
		t.Fatal("pending Close released material")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if r.RetireCompatibility(ctx) == nil || !r.pending || r.ready {
		t.Fatal("unknown completion became proof")
	}
	if r.Current(ctx) == nil {
		t.Fatal("pending material became current")
	}
	if p := (&SupervisedCompatibilityProvider{review: review}); p.managedReviewMaterial(ctx) == nil {
		t.Fatal("persisted domain DTO became original managed source")
	}
}

func TestNFQDomainTaggedReviewCannotAuthorizeOrdinarySelectedSource(t *testing.T) {
	d := managedMaterialFixture(t)
	approval, err := managedCompatibilityApproval(d, filepath.Join(t.TempDir(), "control"), operationgate.ControlEpochReference{InstallationID: strings.Repeat("a", 32), Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	review := compatibilityReview{Binary: compatibilityFileBinding{Path: approval.BinaryPath, SHA256: approval.BinarySHA256, Size: 1}, BaseArguments: approval.BaseArguments}
	for _, a := range approval.Assets {
		review.Assets = append(review.Assets, compatibilityFileBinding{Path: a.Path, SHA256: a.SHA256, Size: 1})
	}
	if selectedReviewMaterial(review, d) != nil {
		t.Fatal("baseline material changed")
	}
	_, domain, _ := nfqDomainReviewFixture(t)
	review.Domain = domain.Domain
	if selectedReviewMaterial(review, d) == nil {
		t.Fatal("domain comparison granted legacy CIDR/source")
	}
}
