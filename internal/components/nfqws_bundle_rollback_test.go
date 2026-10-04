package components

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestManagedNFQWSBundleRollbackRestartAtPublicationBoundaries(t *testing.T) {
	points := []string{"before:" + UpdateRollbackStarted, "after:" + UpdateRollbackStarted, "before:nfqws-rollback-receipt", "after:nfqws-rollback-receipt", "before:" + UpdateRolledBack, "after:" + UpdateRolledBack}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			first, input, _ := bundleFixtureManifest(t, "fixture-a")
			m := bundleFixtureManager(t, input)
			a := bundleFixtureAuthority()
			old, err := m.InstallManagedBundle(ctx, first, 7, a)
			if err != nil {
				t.Fatal(err)
			}
			next, nextInput, _ := bundleFixtureManifest(t, "fixture-b")
			m.Client.Transport = bundleFixtureTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nextInput)), ContentLength: int64(len(nextInput)), Request: r}, nil
			})
			candidate, err := m.UpdateManagedBundle(ctx, next, 7, a)
			if err != nil {
				t.Fatal(err)
			}
			interrupted := errors.New("rollback interrupted")
			m.updateFault = func(p string) error {
				if p == point {
					return interrupted
				}
				return nil
			}
			if _, err := m.RecoverManagedBundle(ctx, candidate.TransactionID, "rollback", a); !errors.Is(err, interrupted) {
				t.Fatal("fault boundary missed", err)
			}
			n := &Manager{StateDir: m.StateDir, nfqwsReleases: m.nfqwsReleases, nfqwsFixture: m.nfqwsFixture, nfqwsPublish: m.nfqwsPublish, Runner: bundleForbiddenRunner{t}}
			state, pending, err := n.PendingManagedUpdate()
			if err != nil {
				t.Fatal(err)
			}
			if state.Phase != UpdateRolledBack {
				if point != "before:"+UpdateRollbackStarted && !pending {
					t.Fatal("interrupted rollback lost pending fence", state)
				}
				if restored, err := n.RecoverManagedBundle(ctx, candidate.TransactionID, "rollback", a); err != nil || restored != old {
					t.Fatal(restored, err)
				}
			}
			lease, err := n.AcquireManagedNFQWSRuntime(ctx, old.TransactionID)
			if err != nil {
				t.Fatal("verified original unavailable", err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := m.verifyManagedNFQWS(ctx, candidate.GenerationPath, candidate.ManifestSHA256); err != nil {
				t.Fatal("candidate deleted by rollback", err)
			}
		})
	}
}

func TestManagedNFQWSBundleLateCancellationIsNotAPISuccess(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "fixture-a")
	m := bundleFixtureManager(t, input)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.updateFault = func(p string) error {
		if p == "after:"+UpdateAcceptedIdle {
			cancel()
		}
		return nil
	}
	if _, err := m.InstallManagedBundle(ctx, manifest, 7, bundleFixtureAuthority()); !errors.Is(err, context.Canceled) {
		t.Fatal("late cancellation returned success", err)
	}
	// The already published bytes are retained as file evidence. This metadata
	// authorizes no runtime; CORE/NFQWS must freshly admit actual Start/acceptance.
	state, pending, err := m.PendingManagedUpdate()
	if err != nil || pending || state.Phase != UpdateAcceptedIdle {
		t.Fatal("known complete files were fabricated as a command outcome", state, pending, err)
	}
}
