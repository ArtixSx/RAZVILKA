//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Observe inside the actual Manager's original compensation, before it closes
// the real scope. No test constructs or renews a cleanup context or unused DTO.
func withXrayOriginalUnusedInventory(t *testing.T, audit func(*xrayPreparedManagerFixture, context.Context, *XraySelectedTCPExecutionResource)) {
	t.Helper()
	called := false
	f := newXrayPreparedManagerFixture(t, func(f *xrayPreparedManagerFixture, _ context.Context, r *XraySelectedTCPExecutionResource) {
		original := f.checks.read
		f.checks.read = func(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
			e := f.x.material.execution
			e.mu.Lock()
			retired := e.retired
			e.mu.Unlock()
			if !called && retired && r.material.IsCleanupContext(ctx) {
				called = true
				audit(f, ctx, r)
			}
			return original(ctx, identity)
		}
	})
	result, err := f.x.manager.Apply(f.ctx, f.plan, nil)
	assertXrayPreparedOriginalRollback(t, f, result, err)
	if !called {
		t.Fatal("original Manager cleanup never supplied its unused observation")
	}
}

func TestXrayUnusedInventoryOriginalCleanupAndSubstitutions(t *testing.T) {
	withXrayOriginalUnusedInventory(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
		observe := func(ctx context.Context) ([]networkPolicyXraySelectedTCPObservation, error) {
			return f.checks.singleXraySelectedTCPConsumers(ctx, nil)
		}
		out, err := observe(ctx)
		defer closeNetworkPolicyXrayObservations(out)
		if err != nil || len(out) != 1 || !out[0].unused || !out[0].absent || out[0].borrowed || len(out[0].rows) != 0 || len(out[0].required) != 0 {
			t.Fatal("same actually retired unused resource did not produce a zero-row witness")
		}
		for _, key := range []any{xrayOperationCleanupKey{}, xrayOperationOwnerKey{}, xrayOperationMaterialKey{}, xraySelectedTCPExecutionKey{}} {
			changed := context.WithValue(ctx, key, nil)
			observations, err := observe(changed)
			closeNetworkPolicyXrayObservations(observations)
			if err == nil && len(observations) != 0 || out[0].current(changed) == nil {
				t.Fatal("missing original cleanup association was accepted")
			}
		}
		e := f.x.material.execution
		e.mu.Lock()
		e.resource = &XraySelectedTCPExecutionResource{}
		e.mu.Unlock()
		if out[0].current(ctx) == nil {
			t.Fatal("substituted actual resource passed final bookend")
		}
		e.mu.Lock()
		e.resource = r
		e.mu.Unlock()
		r.scope.mu.Lock()
		i, err := r.matching()
		if err != nil {
			r.scope.mu.Unlock()
			t.Fatal("original registered resource unavailable")
		}
		original := cloneExecutionResources([]ExecutionResource{r.scope.execution.Resources[i]})[0]
		r.scope.execution.Resources[i].State, r.scope.execution.Resources[i].Phase = "prepared", "planned"
		r.scope.mu.Unlock()
		if out[0].current(ctx) == nil {
			t.Fatal("changed terminal record passed final bookend")
		}
		r.scope.mu.Lock()
		r.scope.execution.Resources[i] = original
		r.scope.mu.Unlock()
		anchor := r.anchor
		r.anchor, err = os.Stat(t.TempDir())
		if err != nil {
			t.Fatal("replacement root fixture unavailable")
		}
		if out[0].current(ctx) == nil {
			t.Fatal("replaced resource root passed final bookend")
		}
		r.anchor = anchor
		if out[0].current(ctx) != nil {
			t.Fatal("original unused witness did not recover after fixture restoration")
		}
	})
}

func TestXrayUnusedInventoryNativeAndCOMMONPublicationRefuse(t *testing.T) {
	withXrayOriginalUnusedInventory(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
		out, err := f.checks.singleXraySelectedTCPConsumers(ctx, nil)
		defer closeNetworkPolicyXrayObservations(out)
		if err != nil || len(out) != 1 {
			t.Fatal("original zero-row observation unavailable")
		}
		for _, flag := range []*bool{&r.versionUsed, &r.versionVerified, &r.startUsed, &r.startACK, &r.startFailed, &r.selectorUsed, &r.active, &r.stopped, &r.descriptorsClosed} {
			r.observationMu.Lock()
			*flag = true
			r.observationMu.Unlock()
			refused := out[0].current(ctx) != nil
			r.observationMu.Lock()
			*flag = false
			r.observationMu.Unlock()
			if !refused {
				t.Fatal("actual native/effect history passed the final unused bookend")
			}
		}
		for _, child := range []**xraySelectedTCPProcess{&r.child, &r.versionChild} {
			r.observationMu.Lock()
			*child = &xraySelectedTCPProcess{}
			r.observationMu.Unlock()
			refused := out[0].current(ctx) != nil
			r.observationMu.Lock()
			*child = nil
			r.observationMu.Unlock()
			if !refused {
				t.Fatal("actual child publication passed the final unused bookend")
			}
		}
		r.commonMu.Lock()
		r.common = &xraySelectedTCPCommonPublication{}
		r.commonMu.Unlock()
		refused := out[0].current(ctx) != nil
		r.commonMu.Lock()
		r.common = nil
		r.commonMu.Unlock()
		if !refused {
			t.Fatal("actual COMMON pointer passed the final unused bookend")
		}
		for _, name := range []string{policyAdditionFile, policyAdditionLock} {
			path := filepath.Join(r.rootPath, name)
			if err := os.WriteFile(path, []byte("unowned unused publication"), 0600); err != nil {
				t.Fatal("COMMON fixture publication unavailable")
			}
			observations, err := f.checks.singleXraySelectedTCPConsumers(ctx, nil)
			closeNetworkPolicyXrayObservations(observations)
			refused := err != nil && out[0].current(ctx) != nil
			if err := os.Remove(path); err != nil {
				t.Fatal("COMMON fixture restoration failed")
			}
			if !refused {
				t.Fatal("actual COMMON receipt/lock publication was accepted")
			}
		}
	})
}

func TestXrayUnusedInventoryFinalImageAndReservedRowsRefuse(t *testing.T) {
	withXrayOriginalUnusedInventory(t, func(f *xrayPreparedManagerFixture, ctx context.Context, r *XraySelectedTCPExecutionResource) {
		original := f.checks.read
		defer func() { f.checks.read = original }()
		for _, which := range []string{"final-native", "final-common", "RZX", "RZG"} {
			reads := 0
			f.checks.read = func(ctx context.Context, identity netidentity.Identity) (BackendInventorySnapshot, error) {
				image, err := original(ctx, identity)
				reads++
				if which == "RZX" || which == "RZG" {
					image.Rows = append(image.Rows, BackendInventoryRow{Family: 4, Table: "nat", Tokens: []string{"-N", which + "_unowned"}})
				}
				if reads == 2 && which == "final-native" {
					r.observationMu.Lock()
					r.selectorUsed = true
					r.observationMu.Unlock()
				}
				if reads == 2 && which == "final-common" {
					if err := os.WriteFile(filepath.Join(r.rootPath, policyAdditionLock), []byte("final unused publication"), 0600); err != nil {
						t.Fatal("final COMMON fixture publication unavailable")
					}
				}
				return image, err
			}
			err := f.checks.InventoryCheck(ctx, f.checks.network, nil)
			r.observationMu.Lock()
			r.selectorUsed = false
			r.observationMu.Unlock()
			if which == "final-common" {
				if err := os.Remove(filepath.Join(r.rootPath, policyAdditionLock)); err != nil {
					t.Fatal("final COMMON fixture restoration failed")
				}
			}
			if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatalf("nil-LAN unused inventory accepted publication: case=%s reads=%d", which, reads)
			}
		}
	})
}
