package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

func dispatcherConnectivityRequest(r NodeCheckRequest) NodeConnectivityRequest {
	return NodeConnectivityRequest{NodeID: r.NodeID, NetworkProfile: r.NetworkProfile, Outbound: r.Outbound}
}

func TestDispatcherConnectivityProductionView(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		for _, cleanupFailure := range []bool{false, true} {
			t.Run(engine+map[bool]string{false: "/ready", true: "/cleanup-failed"}[cleanupFailure], func(t *testing.T) {
				d, s, x := dispatcherFixture(t, 1)
				checker, request := s, checkedNodeRequest()
				if engine == "xray" {
					checker, request = x, xrayCheckedRequest()
				}
				probes, cleaned := 0, 0
				checker.connectivityProbe = func(context.Context, string) (int, error) { probes++; return 204, nil }
				checker.cleanup = func(context.Context, exactNodeSession) error {
					cleaned++
					if len(d.gate) != 1 {
						t.Fatal("shared slot released before cleanup")
					}
					if err := d.Recover(context.Background()); !errors.Is(err, ErrExactNodeBusy) {
						t.Fatal("recovery overlapped connectivity cleanup", err)
					}
					other, _ := d.ForEngine(map[string]string{"sing-box": "xray", "xray": "sing-box"}[engine])
					otherRequest := xrayCheckedRequest()
					if engine == "xray" {
						otherRequest = checkedNodeRequest()
					}
					if _, err := other.Check(context.Background(), otherRequest); !errors.Is(err, ErrExactNodeBusy) {
						t.Fatal("service check bypassed shared connectivity quota", err)
					}
					if _, err := other.CheckConnectivity(context.Background(), dispatcherConnectivityRequest(otherRequest)); !errors.Is(err, ErrExactNodeBusy) {
						t.Fatal("connectivity bypassed shared quota", err)
					}
					if cleanupFailure {
						return errors.New("cleanup not confirmed")
					}
					return nil
				}
				// This is the same view/interface boundary used by production App.NodeChecker.
				view, err := d.ForEngine(engine)
				if err != nil {
					t.Fatal(err)
				}
				var nodeChecker NodeChecker = view
				connectivity, ok := nodeChecker.(NodeConnectivityChecker)
				if !ok {
					t.Fatal("production dispatcher view lost connectivity capability")
				}
				result, err := connectivity.CheckConnectivity(context.Background(), dispatcherConnectivityRequest(request))
				if probes != 1 || cleaned != 1 || len(d.gate) != 0 || result.Engine != engine || result.ProbeID == "" {
					t.Fatalf("lost runtime/lifecycle: %+v err=%v probes=%d cleanup=%d", result, err, probes, cleaned)
				}
				if cleanupFailure {
					if result.Ready || result.CleanupVerified || result.Verdict == evidence.VerdictPass || !checker.poisoned.Load() {
						t.Fatal("cleanup gap promoted readiness", result, err)
					}
				} else if err != nil || !result.Ready || !result.CleanupVerified || result.Verdict != evidence.VerdictPass {
					t.Fatal("connectivity not forwarded", result, err)
				}
			})
		}
	}
}

func TestDispatcherConnectivityAdmissionBeforeQuotaAndDNS(t *testing.T) {
	for _, name := range []string{"unsupported", "cancel", "poisoned", "nil"} {
		t.Run(name, func(t *testing.T) {
			d, _, x := dispatcherFixture(t, 1)
			x.resolve = func(context.Context, string) ([]netip.Addr, error) {
				t.Fatal("rejected admission reached DNS")
				return nil, nil
			}
			view, _ := d.ForEngine("xray")
			request := dispatcherConnectivityRequest(xrayCheckedRequest())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrExactNodeUnsupported
			switch name {
			case "unsupported":
				request.Outbound = []byte(strings.TrimSuffix(xrayNodeMaterial, "}") + `,"transport":{"type":"xhttp"}}`)
			case "cancel":
				cancel()
				want = context.Canceled
			case "poisoned":
				x.poisoned.Store(true)
				want = ErrExactNodeUnavailable
			case "nil":
				view = nil
				want = ErrExactNodeUnavailable
			}
			d.gate <- struct{}{}
			result, err := view.CheckConnectivity(ctx, request)
			if !errors.Is(err, want) || result.ProbeID != "" || result.Ready || result.CleanupVerified || len(d.gate) != 1 {
				t.Fatal("admission bypassed or consumed shared quota", result, err)
			}
			<-d.gate
		})
	}
}
