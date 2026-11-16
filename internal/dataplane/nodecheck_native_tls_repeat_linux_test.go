//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/nativecheckfixture"
)

// A fixed sample population, not retry-until-success. Each failed Check fails
// the test permanently; only verified cleanup permits collecting the next row.
func TestNativeVLESSRepeatedLiveTLS(t *testing.T) {
	if os.Getenv("RAZVILKA_NODE_NATIVE_TLS_REPEAT") != "1" {
		t.Skip("requires isolated native repeated TLS fixture")
	}
	fixture, observation := nativecheckfixture.StartWithTLSObservation(t)
	checker := NewExactXrayNodeCheckerSlots(filepath.Join(fixture.Root, "client"), 1)
	checker.Binary, checker.Port = fixture.Binary, 29185
	checker.FreshProfile = func(context.Context) (string, error) { return nativecheckfixture.Profile, nil }
	request := NodeCheckRequest{NodeID: checkedNodeID, Outbound: fixture.Outbound, NetworkProfile: nativecheckfixture.Profile, Service: catalog.Service{ID: "telegram", ProbeURL: fixture.ProbeURL, Strategy: []string{"xray"}}}
	for sample := 0; sample < 100; sample++ {
		fixture.SetService("live", 40*time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
		ctx = WithNodeResourceGuard(ctx, func(ctx context.Context, _ string, ip netip.Addr) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !ip.IsValid() {
				return nil
			}
			if ip.String() != nativecheckfixture.HTTPSIP && ip.String() != nativecheckfixture.ServerIP {
				return ErrNodeResourceDenied
			}
			return nil
		})
		before := observation.Snapshot()
		calls := fixture.ServiceCalls.Load()
		started := time.Now()
		result, err := checker.Check(ctx, request)
		elapsed := time.Since(started)
		cancel()
		counts := observation.Snapshot().Since(before)
		serviceRequests := fixture.ServiceCalls.Load() - calls
		serviceProof := result.Available && result.EgressIP == nativecheckfixture.ExitIP && serviceRequests == 1
		stage := "other"
		switch result.Stage {
		case "queued", "dns", "transport", "prepare", "start", "ready", "direct", "proxy", "service", "service_transport", "service_ip", "cleanup":
			stage = result.Stage
		}
		cleanup := result.CleanupStatus == NodeCleanupVerified
		ownedRunning := false
		for slot := range checker.Capacity() {
			ownedRunning = checker.Processes.Running(checker.session(slot).Spec) || ownedRunning
		}
		// The fixed counters may include a previous connection's late log; they
		// are observation-window counts, not proof of causal sample attribution.
		t.Logf("native_tls_repeat sample=%d elapsed_ms=%.3f stage=%s check_error=%t available=%t service_proof=%t cleanup_verified=%t owned_running=%t service_requests=%d record_version_123e=%d other_tls=%d eof=%d unknown=%d overflow=%d", sample, float64(elapsed)/float64(time.Millisecond), stage, err != nil, result.Available, serviceProof, cleanup, ownedRunning, serviceRequests, counts.RecordVersion123e, counts.OtherTLS, counts.EOF, counts.Unknown, counts.Overflow)
		if !cleanup || ownedRunning {
			t.Fatalf("sample %d cleanup unverified; population stopped", sample)
		}
		if err != nil || !serviceProof {
			t.Errorf("sample %d genuine live proof failed", sample)
		}
		if counts.RecordVersion123e != 0 {
			t.Errorf("sample %d observation window reproduced TLS record-version defect", sample)
		}
	}
	t.Log("native repeated live TLS population complete; isolated PC fixture, not LAN/router acceptance")
}
