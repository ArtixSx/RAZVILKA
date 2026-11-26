package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

type usqueCanaryStopFailure struct {
	proxyFakeProcesses
	stops        int
	clearRunning bool
}

func (p *usqueCanaryStopFailure) Stop(ctx context.Context, spec ProcessSpec) error {
	p.stops++
	if p.stops == 1 {
		if p.clearRunning {
			delete(p.running, spec.ID)
		}
		return errors.New("owned child stop refused")
	}
	return p.proxyFakeProcesses.Stop(ctx, spec)
}

func TestUSQUECanaryRequiresAuthorityAndFullPredicateBeforeStart(t *testing.T) {
	for _, kind := range []string{"missing-guard", "revoked", "canceled", "missing-predicate", "missing-pin"} {
		t.Run(kind, func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			processes := &proxyFakeProcesses{running: map[string]bool{}}
			fixture.a.Processes = processes
			calls := 0
			fixture.a.ownedUSQUEProbe = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				calls++
				panic("producer must not run before preflight")
			}
			ctx := fixture.ctx
			switch kind {
			case "missing-guard":
				ctx = context.Background()
			case "revoked":
				ctx = WithReviewGuard(context.Background(), func(context.Context) error { return ErrReviewChanged })
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing-predicate":
				fixture.plan.Routes[0].ProbeService = nil
			case "missing-pin":
				if err := os.WriteFile(filepath.Join(fixture.spec.Dir, "engine.json"), []byte(`{"endpoint_h2_v4":"162.159.193.10"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fixture.a.runCanaryAttempt(ctx, fixture.plan, fixture.spec, fixture.address); err == nil || len(processes.startSpecs) != 0 || calls != 0 {
				t.Fatal("refused preflight started a child or producer", err)
			}
		})
	}
}

func TestUSQUECanaryStopFailureCannotPersistTransportOrEvidence(t *testing.T) {
	for _, clearRunning := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "reported-stopped"}[clearRunning], func(t *testing.T) {
			fixture := usqueOwnedBridgeNewFixture(t, usqueTransport{})
			transaction := filepath.Join(fixture.spec.Dir, "transaction")
			if err := os.Mkdir(transaction, 0700); err != nil {
				t.Fatal(err)
			}
			config := `{"private_key":"fixture-key","endpoint_pub_key":"fixture-pub","id":"fixture-device","access_token":"fixture-token","endpoint_v4":"1.1.1.1","endpoint_h2_v4":"162.159.193.10"}`
			if err := os.WriteFile(filepath.Join(transaction, "engine.staged.json"), []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			adapter, err := NewProxyTunnelAdapter("usque", engineconfig.New(filepath.Join(fixture.spec.Dir, "configs"), filepath.Join(fixture.spec.Dir, "backups")), filepath.Join(fixture.spec.Dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			adapter.EngineBin = fixture.a.EngineBin
			adapter.FreshProfile = fixture.a.FreshProfile
			processes := &usqueCanaryStopFailure{proxyFakeProcesses: proxyFakeProcesses{running: map[string]bool{}}, clearRunning: clearRunning}
			adapter.Processes = processes
			adapter.SOCKSProbe = func(context.Context, string) error { return nil }
			producerCalls := 0
			adapter.ownedUSQUEProbe = func(_ context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				producerCalls++
				return usqueOwnedBridgeProof(options), nil
			}
			if err := adapter.Canary(fixture.ctx, fixture.plan, transaction); !errors.Is(err, errProxyCanaryCleanup) || processes.stops != 1 || len(processes.startSpecs) != 1 || producerCalls != 1 {
				t.Fatal("failed Stop was accepted", err)
			}
			for _, name := range []string{"transport.staged.json", "evidence.staged.json"} {
				if _, err := os.Lstat(filepath.Join(transaction, name)); !os.IsNotExist(err) {
					t.Fatal("failed Stop persisted candidate selection", name, err)
				}
			}
		})
	}
}
