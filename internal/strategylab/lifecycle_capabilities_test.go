package strategylab

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestLifecycleRegistrationDoesNotPromoteDisabledOrOpaqueExecutors(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	m.Validator = CompatibleValidator{}
	m.Executor = nil
	if got := m.LifecycleRegistration(); got.NativeValidation != "absent" || got.ManagedCandidateProbe != "absent" {
		t.Fatal("disabled defaults claimed native registration", got)
	}
	m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation {
		t.Fatal("readback executed validator")
		return Validation{}
	})
	m.Executor = &adaptiveFoundationExecutor{}
	if got := m.LifecycleRegistration(); got.NativeValidation != "unknown" || got.ManagedCandidateProbe != "unknown" {
		t.Fatal("opaque callback invented managed capability", got)
	}
	m.Validator = adaptiveFoundationOwnedConfig(t, m)
	if got := m.LifecycleRegistration(); got.NativeValidation != "unknown" {
		t.Fatal("data-only provider replaced actual original registration")
	}
}
func TestLifecycleRegistrationReadsActualConfiguredSupervisedProvider(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("actual protected provider requires Linux ownership proof")
	}
	model, approval, _ := compatibilityProviderPreflightFixture(t)
	if err := os.Chmod(filepath.Dir(approval.BinaryPath), 0700); err != nil {
		t.Fatal(err)
	}
	control, err := operationgate.InitializeSelfUpdateControl(context.Background(), approval.ControlPath)
	if err != nil {
		t.Fatal(err)
	}
	approval.InstallationID, approval.Sequence = control.InstallationID, control.Sequence
	provider, err := NewSupervisedCompatibilityProvider(model.manager, approval)
	if err != nil {
		t.Fatal(err)
	}
	m := model.manager
	m.Validator = CompatibleValidator{Binary: provider.review.Binary.Path, BaseArguments: slices.Clone(provider.review.BaseArguments), TrustedAssets: true, Provider: provider}
	if got := m.LifecycleRegistration(); got.NativeValidation != "registered" {
		t.Fatal("actual configured supervised entry point lost", got)
	}
	if m.nativeRunning || m.state.CompatibilitySession != nil {
		t.Fatal("readback started a compatibility phase")
	}
}
func TestLifecycleRegistrationConcurrentConfigurationReadback(t *testing.T) {
	m, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			m.mu.Lock()
			m.Validator = CompatibleValidator{}
			if i%2 == 0 {
				m.Validator = adaptiveFoundationValidatorFunc(func(context.Context, []string) Validation { return Validation{} })
			}
			m.Executor = nil
			m.mu.Unlock()
		}
	}()
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			m.LifecycleRegistration()
		}
	}()
	workers.Wait()
}
