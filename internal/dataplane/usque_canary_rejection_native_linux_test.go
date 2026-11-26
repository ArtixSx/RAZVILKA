//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

// This tagged test executable doubles as the exact scoped child. It opens
// only the candidate's loopback listener. It closes SOCKS requests locally,
// so the owned network leaf returns a real failure without an external test.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "-c" && os.Getenv("RAZVILKA_USQUE_CANARY_LOCAL_CHILD") == "1" {
		os.Exit(runUSQUECanaryLocalChild(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runUSQUECanaryLocalChild(args []string) int {
	if len(args) < 9 || !filepath.IsAbs(args[1]) || !slices.Equal(args[2:6], []string{"socks", "-b", "127.0.0.1", "-p"}) {
		return 2
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", args[6]))
	if err != nil {
		return 2
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	defer func() { _ = listener.Close(); <-joined }()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-signals:
		return 0
	case <-timer.C:
		return 2
	}
}

func nativeUSQUECanaryTarget(t *testing.T, ctx context.Context, fixture *usqueLifecycleFixture, missing bool) context.Context {
	t.Helper()
	route := &fixture.plan.Routes[0]
	service := *route.ProbeService
	service.Domains = nil
	service.CIDRs = slices.Clone(route.CIDRs)
	service.ProbeURL, service.Probes, service.SourceRefs = "https://8.8.8.8/status", nil, nil
	route.ProbeURL, route.ProbeService = service.ProbeURL, &service
	if missing {
		return ctx
	}
	configPath, control := filepath.Join(fixture.base, "config.json"), filepath.Join(fixture.base, "control")
	store, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "auto"}); err != nil {
		t.Fatal(err)
	}
	if _, err := operationgate.InitializeSelfUpdateControl(ctx, control); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	ctx, release, err := gate.ExclusiveContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	var nodes *nodestore.Store
	owner, err := defaultconsent.NewOwner(ctx, gate, &store, &nodes, configPath, "", control, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	review, err := owner.ReviewLegacyUSQUEProbeTargets(ctx, store.Get(), catalog.Catalog{Services: []catalog.Service{service}}, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = usquediag.WithOwnedLegacyUSQUEProbeTargetReview(ctx, review, service.ID, service.ProbeURL)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

type usqueObservedOriginals struct {
	OSProcessController
	children   []*OriginalProcess
	failSecond bool
}

func (p *usqueObservedOriginals) StartOriginal(ctx context.Context, spec ProcessSpec, address string) (*OriginalProcess, error) {
	if p.failSecond && len(p.children) == 1 {
		return nil, errors.New("fixture cannot start the second transport")
	}
	child, err := p.OSProcessController.StartOriginal(ctx, spec, address)
	if err == nil {
		p.children = append(p.children, child)
	}
	return child, err
}

func TestUSQUECanaryNativeJoinedRejection(t *testing.T) {
	scenarios := []string{"both-transports", "second-start-refused", "readiness-refused", "canceled", "cleanup-refused", "target-refused", "runtime-proof-refused"}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			fixture := newUSQUELifecycleFixture(t)
			a := fixture.a
			originals := &usqueObservedOriginals{failSecond: scenario == "second-start-refused"}
			t.Setenv("RAZVILKA_USQUE_CANARY_LOCAL_CHILD", "1")
			a.Processes = originals
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			a.EngineBin = self
			a.Timeout = 6 * time.Second
			if scenario == "readiness-refused" {
				a.Timeout = time.Second
			}
			a.SOCKSProbe = func(ctx context.Context, address string) error {
				connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
				if err != nil {
					return err
				}
				err = connection.Close()
				if scenario == "readiness-refused" {
					return errors.New("fixture SOCKS negotiation refused")
				}
				return err
			}
			ctx, cancel := context.WithTimeout(fixture.ctx, 17*time.Second)
			defer cancel()
			ctx = nativeUSQUECanaryTarget(t, ctx, fixture, scenario == "target-refused")
			var transports []string
			a.ownedUSQUEProbe = func(ctx context.Context, options usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
				transports = append(transports, options.Runtime.Transport)
				if scenario == "canceled" {
					cancel()
				}
				if scenario == "cleanup-refused" {
					child := originals.children[0]
					if err := os.WriteFile(child.spec.PIDPath, []byte("1\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "runtime-proof-refused" {
					return usquediag.OwnedRuntimeEvidence{}, errors.New("fixture local runtime proof refused")
				}
				return usquediag.OwnedRuntimeEvidence{}, usquediag.ProbeOwnedNetworkNativeFixture(ctx, options.Network)
			}
			defer func() {
				for _, child := range originals.children {
					cleanup, finish := context.WithTimeout(context.Background(), 6*time.Second)
					if scenario == "cleanup-refused" {
						if err := os.WriteFile(child.spec.PIDPath, child.pidRaw, 0600); err != nil {
							t.Error("restore own fixture pathname", err)
						}
					}
					if err := child.StopAndJoin(cleanup); err != nil {
						t.Error("final original fixture cleanup", err)
					}
					finish()
				}
			}()
			m := New(filepath.Join(fixture.base, "manager"))
			m.FreshProfile = a.FreshProfile
			if err := m.Register(a); err != nil {
				t.Fatal(err)
			}
			previous, err := Build(Input{Revision: 1})
			if err != nil {
				t.Fatal(err)
			}
			previous.State = "committed"
			if err := m.Record(previous); err != nil {
				t.Fatal(err)
			}
			plan, err := Build(Input{Revision: 2, NetworkProfileID: fixture.plan.NetworkProfileID, Routes: fixture.plan.Routes, EngineConfigDrafts: fixture.plan.EngineDrafts,
				Engines: []Engine{{ID: "usque", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: HostState{IPCommand: true, TUN: true, SingBox: true}})
			if err != nil || !plan.Ready {
				t.Fatal("invalid fixture plan", err, plan.Blockers)
			}
			x, err := m.Apply(ctx, plan, func() (func() error, error) { t.Fatal("rejected canary reached config commit"); return nil, nil })
			if err == nil || x.State != "canary-failed" {
				t.Fatal("real original listener fixture did not reach a rejected canary", x, err, transports)
			}
			accepted := ConfirmedUSQUECanaryRejection(ctx, m, plan, x, err)
			if scenario == "readiness-refused" {
				if accepted || len(transports) != 0 || len(originals.children) != 2 {
					t.Fatal("cleaned children that missed SOCKS readiness certified alternate admission", transports, err)
				}
				return
			}
			if scenario != "both-transports" {
				wantAttempts := 1
				if scenario == "runtime-proof-refused" {
					wantAttempts = 2
				}
				if accepted || len(transports) != wantAttempts {
					t.Fatal("unproven attempt certified alternate admission", transports, err)
				}
				if scenario == "target-refused" && !errors.Is(err, defaultconsent.ErrProbeTargetUnknown) {
					t.Fatal("missing target was hidden as a network refusal", err)
				}
				return
			}
			if !accepted || !slices.Equal(transports, []string{"QUIC", "HTTP/2"}) || len(originals.children) != 2 {
				t.Fatal("both original joined transports did not certify", transports, err)
			}
			for _, child := range originals.children {
				if originalProcessPIDAbsent(child.child.Pid) != nil || originalProcessListenerAbsent(ctx, child.port) != nil {
					t.Fatal("original process or listener remains after authenticated cleanup")
				}
			}
			occupied, listenErr := net.Listen("tcp4", originals.children[1].endpoint)
			if listenErr != nil {
				t.Fatal("post-cleanup listener registration", listenErr)
			}
			if ConfirmedUSQUECanaryRejection(ctx, m, plan, x, err) {
				t.Error("reoccupied listener accepted old cleanup")
			}
			if err := occupied.Close(); err != nil {
				t.Fatal(err)
			}
			fixture.revoked = true
			if ConfirmedUSQUECanaryRejection(ctx, m, plan, x, err) {
				t.Error("revoked original route review accepted old cleanup")
			}
			fixture.revoked = false
			changed := plan
			changed.NetworkProfileID = "wan-123456789abd"
			if ConfirmedUSQUECanaryRejection(ctx, New(m.StateRoot), plan, x, err) || ConfirmedUSQUECanaryRejection(ctx, m, changed, x, err) ||
				ConfirmedUSQUECanaryRejection(ctx, m, plan, x, errors.Join(err, ErrExecutionJournal)) ||
				ConfirmedUSQUECanaryRejection(ctx, m, plan, x, errors.New(err.Error())) {
				t.Fatal("cleanup proof survived altered owner, scope, or error identity")
			}
			next, buildErr := Build(Input{Revision: 3})
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			next.State = "committed"
			if recordErr := m.Record(next); recordErr != nil {
				t.Fatal(recordErr)
			}
			if ConfirmedUSQUECanaryRejection(ctx, m, plan, x, err) {
				t.Fatal("replaced committed plan accepted old cleanup")
			}
		})
	}
}
