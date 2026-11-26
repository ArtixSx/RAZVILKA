package strategylab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Source-only model: existing modeled terminal receipts are saved to the real
// fixture file. There is no Components lease, protected asset review, native
// process or public reader issuance, and no compatibility/runtime PASS.
func selectedReviewSourceFixture(t *testing.T) (*Manager, *SelectedCandidateReview) {
	t.Helper()
	m, provider, candidate, validation := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	candidate.Validation = validation
	m.state.Candidates[candidate.ID] = candidate
	m.state.CompatibilityFinalizing = false
	m.nativeRunning = false
	selection := Selection{ServiceID: "youtube", Protocol: "tcp", IPFamily: "ipv4", CandidateID: candidate.ID, SelectedAt: packTime.Format(time.RFC3339), Frozen: true}
	m.state.Selections[selectionKey(selection.ServiceID, selection.Protocol, selection.IPFamily)] = selection
	after, err := compatibilityStateImage(m.state)
	if err != nil {
		t.Fatal(err)
	}
	target, err := restorejournal.OpenFileTarget(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	err = errors.Join(target.CompareAndSwap(context.Background(), m.image, after), target.Close())
	if err != nil {
		t.Fatal(err)
	}
	m.image = after
	// Keep both source-parent replacement images inside the already owned
	// TempDir so its normal cleanup owns them without an extra deletion path.
	sourceParent := filepath.Join(filepath.Dir(m.Path), "source")
	if err := os.Mkdir(sourceParent, 0700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceParent, filepath.Base(m.Path))
	if err := os.Rename(m.Path, sourcePath); err != nil {
		t.Fatal(err)
	}
	m.Path = sourcePath
	m.Validator = CompatibleValidator{Binary: provider.review.Binary.Path, BaseArguments: slices.Clone(provider.review.BaseArguments), TrustedAssets: true, Provider: provider}
	foundation, err := newManagerAdaptiveFoundation(m)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := foundation.bind(candidate)
	if err != nil {
		t.Fatal(err)
	}
	r := &SelectedCandidateReview{binding: binding, selection: selection, path: m.Path, image: after, provider: provider, review: provider.review}
	r.self = r
	r.file, err = selectedReviewFileIdentity(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	r.parent, err = selectedReviewFileIdentity(filepath.Dir(m.Path))
	if err != nil {
		t.Fatal(err)
	}
	return m, r
}

func selectedReviewSourceCall(m *Manager, r *SelectedCandidateReview, ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return r.sourceLocked(ctx)
}

func TestSelectedCandidateReviewSourceRetainsExactSelectionAndNoPublicGrant(t *testing.T) {
	m, r := selectedReviewSourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before := compatibilityStoreBytes(t, m)
	if err := selectedReviewSourceCall(m, r, ctx); err != nil {
		t.Fatal("unchanged source model refused", err)
	}
	candidate := r.Candidate()
	candidate.Validation.Arguments[0] = "caller mutation"
	if r.Candidate().Validation.Arguments[0] == candidate.Validation.Arguments[0] || r.Selection() != r.selection {
		t.Fatal("detached source data mutated the original binding")
	}
	called := false
	if err := r.WithCurrent(ctx, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("source model without an actual runtime lease issued a public use")
	}
	if !bytes.Equal(before, compatibilityStoreBytes(t, m)) || m.nativeRunning {
		t.Fatal("read-only source entered validation or rewrote the saved choice")
	}
	if err := r.Close(); err != nil || r.Current(ctx) == nil || r.Candidate().ID != "" || r.Selection().CandidateID != "" {
		t.Fatal("closed source review stayed usable", err)
	}
}

func TestSelectedCandidateReviewRefusesSourceInvalidation(t *testing.T) {
	for _, change := range []string{"selection-deleted", "selection-changed", "candidate-deleted", "incarnation", "arguments", "origin", "pack", "unknown", "write-blocked", "native-running", "provider-session-missing", "provider-unknown", "validator-replaced", "foreign-manager", "state-bytes", "same-bytes-file-replaced", "parent-replaced", "configured-path"} {
		t.Run(change, func(t *testing.T) {
			m, r := selectedReviewSourceFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			candidate := m.state.Candidates[r.binding.candidate.ID]
			switch change {
			case "selection-deleted":
				delete(m.state.Selections, selectionKey("youtube", "tcp", "ipv4"))
			case "selection-changed":
				changed := r.selection
				changed.Frozen = false
				m.state.Selections[selectionKey("youtube", "tcp", "ipv4")] = changed
			case "candidate-deleted":
				delete(m.state.Candidates, candidate.ID)
			case "incarnation", "arguments", "origin", "pack":
				switch change {
				case "incarnation":
					candidate.Incarnation = strings.Repeat("f", 32)
				case "arguments":
					candidate.Arguments += " --filter-tcp=8443"
				case "origin":
					candidate.Origin = "another owner"
				case "pack":
					candidate.Origin = "pack:publisher:whole-payload"
				}
				m.state.Candidates[candidate.ID] = candidate
			case "unknown":
				m.compatibilityUnknown = true
			case "write-blocked":
				m.writeBlocked = true
			case "native-running":
				m.nativeRunning = true
			case "provider-session-missing":
				r.provider.session = nil
			case "provider-unknown":
				r.provider.unknown = true
			case "validator-replaced":
				m.Validator = fakeValidator{result: candidate.Validation}
			case "foreign-manager":
				other, err := New(m.Path)
				if err != nil {
					t.Fatal(err)
				}
				other.Validator = m.Validator
				r.binding.manager = other
			case "state-bytes":
				if err := os.WriteFile(m.Path, append(slices.Clone(r.image.Data), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "same-bytes-file-replaced":
				// Keep the original inode alive to avoid inode-number reuse.
				if err := os.Rename(m.Path, m.Path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(m.Path, r.image.Data, 0600); err != nil {
					t.Fatal(err)
				}
			case "parent-replaced":
				parent := filepath.Dir(m.Path)
				if err := os.Rename(parent, parent+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(m.Path, r.image.Data, 0600); err != nil {
					t.Fatal(err)
				}
			case "configured-path":
				m.Path += ".other"
			}
			if err := selectedReviewSourceCall(m, r, ctx); err == nil {
				t.Fatal("changed source admitted", change)
			}
		})
	}
}

func TestSelectedCandidateReviewCompatibilityNeedsActualCompletedOwnerSession(t *testing.T) {
	for _, change := range []string{"native-bools-only", "dry-run-only", "unacknowledged", "wrong-arguments", "wrong-payload", "wrong-protocol"} {
		t.Run(change, func(t *testing.T) {
			m, r := selectedReviewSourceFixture(t)
			session := compatibilityRecordClone(t, *m.state.CompatibilitySession)
			m.state.CompatibilitySession = &session
			candidate := r.binding.candidate
			selection := r.selection
			switch change {
			case "native-bools-only":
				m.state.CompatibilitySession = nil
			case "dry-run-only":
				session.Active, session.LuaInit = "dry-run", nil
			case "unacknowledged":
				session.LuaInit.Acknowledged = false
			case "wrong-arguments":
				candidate.Validation.Arguments = []string{"--filter-tcp=80"}
			case "wrong-payload":
				session.LuaInit.Command.Review.Binary.SHA256 = strings.Repeat("e", 64)
				compatibilityRecordReseal(session.LuaInit)
			case "wrong-protocol":
				selection.Protocol = "udp"
			}
			if selectedReviewCompatibility(m.state, candidate, selection, r.review) == nil {
				t.Fatal("incomplete or mismatched compatibility became source proof")
			}
		})
	}
}

func TestSelectedCandidateReviewMaterialRequiresSameCompleteRuntime(t *testing.T) {
	review := compatibilityRecordFixture(t).DryRun.Command.Review
	quic := compatibilityFileBinding{Path: filepath.Join(filepath.Dir(review.Binary.Path), "quic.bin"), SHA256: strings.Repeat("c", 64), Size: 2}
	review.Assets = append(review.Assets[:3:3], quic, review.Assets[3])
	review.BaseArguments = append(review.BaseArguments[:3:3], "--blob=quic_initial:@"+quic.Path, review.BaseArguments[3])
	d := components.NFQWSRuntimeDescriptor{ReceiptID: strings.Repeat("1", 32), ManifestSHA256: strings.Repeat("2", 64), Executable: components.NFQWSRuntimeAsset{Path: review.Binary.Path, SHA256: review.Binary.SHA256}}
	for _, asset := range review.Assets[:3] {
		d.Lua = append(d.Lua, components.NFQWSRuntimeAsset{Path: asset.Path, SHA256: asset.SHA256})
	}
	d.Blobs = []components.NFQWSRuntimeBlob{{Alias: "quic_initial", Path: quic.Path, SHA256: quic.SHA256}, {Alias: "tls_clienthello", Path: review.Assets[4].Path, SHA256: review.Assets[4].SHA256}}
	if selectedReviewMaterial(review, d) != nil {
		t.Fatal("same complete material model refused")
	}
	for _, change := range []string{"binary", "lua", "blob", "alias", "missing", "order"} {
		t.Run(change, func(t *testing.T) {
			changed := d
			changed.Lua, changed.Blobs = slices.Clone(d.Lua), slices.Clone(d.Blobs)
			switch change {
			case "binary":
				changed.Executable.SHA256 = strings.Repeat("f", 64)
			case "lua":
				changed.Lua[0].Path += ".other"
			case "blob":
				changed.Blobs[1].SHA256 = strings.Repeat("f", 64)
			case "alias":
				changed.Blobs[0].Alias = "other"
			case "missing":
				changed.Blobs = changed.Blobs[:1]
			case "order":
				changed.Lua[0], changed.Lua[1] = changed.Lua[1], changed.Lua[0]
			}
			if selectedReviewMaterial(review, changed) == nil {
				t.Fatal("changed material admitted", change)
			}
		})
	}
}

func TestSelectedCandidateReviewRequiresOriginalHandleRuntimeAndFiniteContext(t *testing.T) {
	m, r := selectedReviewSourceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := m.RetainSelectedCandidateReview(ctx, "youtube", "tcp", "ipv4", nil); err == nil {
		t.Fatal("nil component lease issued a source review")
	}
	for _, handle := range []*SelectedCandidateReview{nil, {}, {self: r, binding: r.binding}} {
		if handle.Current(ctx) == nil || handle.Close() == nil || handle.Candidate().ID != "" {
			t.Fatal("zero or copied handle admitted")
		}
	}
	for _, invalid := range []context.Context{nil, context.Background()} {
		if r.Current(invalid) == nil {
			t.Fatal("missing finite context admitted")
		}
	}
	cancel()
	if err := r.Current(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller lost its cancellation", err)
	}
}
