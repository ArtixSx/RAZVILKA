package strategylab

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Declared-material model only. No lease, files, process or admission is issued.
func managedMaterialFixture(t *testing.T) components.NFQWSRuntimeDescriptor {
	t.Helper()
	generation := filepath.Join(t.TempDir(), "generation")
	d := components.NFQWSRuntimeDescriptor{ReceiptID: strings.Repeat("1", 32), ManifestSHA256: strings.Repeat("2", 64), GenerationPath: generation,
		Executable: components.NFQWSRuntimeAsset{Path: filepath.Join(generation, "rzv-nfqws2"), SHA256: strings.Repeat("3", 64)}}
	for _, name := range []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"} {
		d.Lua = append(d.Lua, components.NFQWSRuntimeAsset{Path: filepath.Join(generation, name), SHA256: strings.Repeat("4", 64)})
	}
	d.Blobs = []components.NFQWSRuntimeBlob{{Alias: "quic_initial", Path: filepath.Join(generation, "quic.bin"), SHA256: strings.Repeat("5", 64)},
		{Alias: "tls_clienthello", Path: filepath.Join(generation, "tls.bin"), SHA256: strings.Repeat("6", 64)}}
	return d
}

func TestManagedCompatibilityCompletionCannotAdoptModelReceiptOrCloseLease(t *testing.T) {
	m, p, candidate, _ := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before := compatibilityStoreBytes(t, m)
	gate := &operationgate.Gate{}
	original, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cleanup, err := gate.ReviewExclusiveCleanup(original)
	if err != nil {
		t.Fatal(err)
	}
	// Model data deliberately attempts every claimed outcome. Even a genuine
	// operation cleanup lifetime supplies no managed runtime/control producer.
	i := &managedCompatibilityInvocation{manager: m, provider: p, runtime: &components.ManagedNFQWSRuntimeLease{}, cleanup: cleanup,
		binding: adaptiveCandidateBinding{manager: m, candidate: candidate}, finished: true, settled: true, image: compatibilityImageCopy(m.image)}
	i.file, _ = selectedReviewFileIdentity(m.Path)
	i.parent, _ = selectedReviewFileIdentity(filepath.Dir(m.Path))
	r := &ManagedCompatibilityCompletion{invocation: i}
	r.self = r
	copy := &ManagedCompatibilityCompletion{self: r, invocation: i}
	for _, invalid := range []*ManagedCompatibilityCompletion{nil, {}, copy, r} {
		if err := invalid.RetireKnown(ctx); err == nil {
			t.Fatal("model receipt/completion adopted managed retirement")
		}
		if gate.Snapshot().Active != 1 || !bytes.Equal(before, compatibilityStoreBytes(t, m)) {
			t.Fatal("refused completion released original operation or changed source")
		}
	}
	if err := r.RetireKnown(context.Background()); !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("unbounded retirement", err)
	}
}

func TestManagedCompatibilityDeclarationPreservesExactMaterialAndNoGrant(t *testing.T) {
	d := managedMaterialFixture(t)
	root := filepath.Join(t.TempDir(), "control")
	ref := operationgate.ControlEpochReference{InstallationID: strings.Repeat("a", 32), Sequence: 1}
	approval, err := managedCompatibilityApproval(d, root, ref)
	if err != nil || approval.BinaryPath != d.Executable.Path || approval.BinarySHA256 != d.Executable.SHA256 || len(approval.Assets) != 5 || len(approval.BaseArguments) != 5 || approval.BaseArguments[3] != "--blob=quic_initial:@"+d.Blobs[0].Path || approval.ControlPath != root || approval.Sequence != ref.Sequence {
		t.Fatal("material declaration changed actual ordered inputs", err, approval)
	}
	approval.Assets[0].SHA256 = "caller mutation"
	if d.Lua[0].SHA256 == approval.Assets[0].SHA256 {
		t.Fatal("declaration aliases owner descriptor")
	}
	for _, change := range []string{"foreign-generation", "missing-lua", "wrong-blob-order", "invalid-hash"} {
		changed := d
		changed.Lua, changed.Blobs = slices.Clone(d.Lua), slices.Clone(d.Blobs)
		switch change {
		case "foreign-generation":
			changed.Executable.Path = filepath.Join(filepath.Dir(d.GenerationPath), "foreign")
		case "missing-lua":
			changed.Lua = changed.Lua[:2]
		case "wrong-blob-order":
			changed.Blobs[0], changed.Blobs[1] = changed.Blobs[1], changed.Blobs[0]
		case "invalid-hash":
			changed.Lua[0].SHA256 = "not a reviewed hash"
		}
		if _, err := managedCompatibilityApproval(changed, root, ref); err == nil {
			t.Fatal("unsupported declaration accepted", change)
		}
	}
}

func TestManagedCompatibilityCannotUseLegacyOrForgedLeaseContext(t *testing.T) {
	m, p, candidate, _ := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	m.state.CompatibilityFinalizing = false
	m.nativeRunning = false
	m.Validator = CompatibleValidator{Binary: p.review.Binary.Path, BaseArguments: slices.Clone(p.review.BaseArguments), TrustedAssets: true, Provider: p}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before := compatibilityStoreBytes(t, m)
	for _, lease := range []*components.ManagedNFQWSRuntimeLease{nil, {}} {
		if _, completion, err := m.ValidateManagedCandidate(ctx, candidate.ID, lease); err == nil || completion != nil {
			t.Fatal("uncontrolled provider or fabricated empty lease admitted validation")
		}
	}
	if !bytes.Equal(before, compatibilityStoreBytes(t, m)) || m.nativeRunning {
		t.Fatal("refused managed source entered native validation or changed saved state")
	}
	if _, _, err := NewManagedSupervisedCompatibilityProvider(ctx, m, nil, nil, p.review.ControlPath); err == nil {
		t.Fatal("DTO material without actual owners constructed managed provider")
	}
	if managedCompatibilityRun(context.Background(), p) {
		t.Fatal("raw or legacy context acquired managed synchronous owner")
	}
}

func TestManagedCompatibilityCopiedProviderCannotIssueOriginalInvocation(t *testing.T) {
	m, p, candidate, _ := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	p.self = p
	p.managedControl = &operationgate.ControlEpochReview{}
	copy := &SupervisedCompatibilityProvider{self: p, manager: m, review: p.review, session: p.session,
		managedControl: p.managedControl, managedDescriptor: p.managedDescriptor}
	m.Validator = CompatibleValidator{Binary: p.review.Binary.Path, BaseArguments: slices.Clone(p.review.BaseArguments), TrustedAssets: true, Provider: copy}
	m.mu.RLock()
	_, err := adaptiveManagedValidatorLocked(m)
	m.mu.RUnlock()
	if !errors.Is(err, errAdaptiveManagedValidator) {
		t.Fatal("copied producer adopted original control/session", err)
	}
	i := &managedCompatibilityInvocation{manager: m, provider: copy, binding: adaptiveCandidateBinding{manager: m, candidate: candidate}}
	ctx := context.WithValue(context.Background(), managedCompatibilityContextKey{}, i)
	if managedCompatibilityRun(ctx, copy) {
		t.Fatal("copied producer acquired managed execution lifetime")
	}
}
