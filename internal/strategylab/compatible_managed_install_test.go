package strategylab

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestManagedCompatibilityInstallRefusesDeclaredProviderOrInactiveReview(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "strategy-lab.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddCandidate("tcp-tls", "actual saved draft", "--filter-tcp=443 --lua-desync=fake:blob=0x00000000", "expert"); err != nil {
		t.Fatal(err)
	}
	m.Executor, m.Validator = nil, CompatibleValidator{}
	before := compatibilityStoreBytes(t, m)
	info, err := os.Stat(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	control := &operationgate.ControlEpochReview{}
	p := &SupervisedCompatibilityProvider{manager: m, managedControl: control}
	p.self = p
	validator := CompatibleValidator{Provider: p, TrustedAssets: true, Timeout: 8 * time.Second}
	review := &ManagedCompatibilityInactiveReview{manager: m, control: control}
	review.self = review
	copy := &ManagedCompatibilityInactiveReview{self: review, manager: m, control: control}
	for _, inactive := range []*ManagedCompatibilityInactiveReview{nil, {}, copy, review} {
		if err := m.InstallManagedCompatibilityValidator(ctx, control, p, validator, inactive); err == nil {
			t.Fatal("caller-declared provider/source became actual installed validation")
		}
	}
	current := m.Validator.(CompatibleValidator)
	after, statErr := os.Stat(m.Path)
	if current.Provider != nil || current.TrustedAssets || statErr != nil || !os.SameFile(info, after) || !bytes.Equal(before, compatibilityStoreBytes(t, m)) || m.nativeRunning {
		t.Fatal("refused handover changed the original slot/source or began validation")
	}
}

func TestManagedCompatibilityInstallRejectsCopiedProducerAndValidatorDeclarations(t *testing.T) {
	m, p, _, _ := compatibilityStoreFinalizationFixture(t, "lua-init", 0)
	p.self = p
	control := &operationgate.ControlEpochReview{}
	p.managedControl = control
	copy := &SupervisedCompatibilityProvider{self: p, manager: m, review: p.review, managedControl: control, managedDescriptor: p.managedDescriptor}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, change := range []string{"copy", "binary", "base", "timeout", "untrusted", "foreign-provider"} {
		declared := CompatibleValidator{Binary: p.review.Binary.Path, BaseArguments: slices.Clone(p.review.BaseArguments), TrustedAssets: true, Timeout: 8 * time.Second, Provider: p}
		provider := p
		switch change {
		case "copy":
			provider, declared.Provider = copy, copy
		case "binary":
			declared.Binary = "foreign"
		case "base":
			declared.BaseArguments = append(declared.BaseArguments, "foreign")
		case "timeout":
			declared.Timeout = time.Second
		case "untrusted":
			declared.TrustedAssets = false
		case "foreign-provider":
			declared.Provider = copy
		}
		if managedCompatibilityValidatorMatches(m, control, provider, declared) {
			t.Fatal("model declaration adopted exact constructor shape", change)
		}
		if err := m.InstallManagedCompatibilityValidator(ctx, control, provider, declared, nil); !errors.Is(err, errAdaptiveManagedValidator) {
			t.Fatal("missing original inactive review did not refuse handover", err)
		}
	}
}
