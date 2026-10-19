package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// A capability message names the limit and what to change; it never claims a
// rollback or promises a retry that cannot succeed.
func requireTerminalCapabilityMessage(t *testing.T, r autonomy.Runtime, want string) {
	t.Helper()
	if r.State != "capability-refused" || !strings.Contains(r.Message, want) || !strings.Contains(r.Message, "Автопилот ждёт изменения настроек") {
		t.Fatalf("not a terminal capability state: %+v", r)
	}
	for _, wrong := range []string{"откат", "защит", "повтор", "NETWORK_POLICY", "SERVICE_HAS"} {
		if strings.Contains(r.Message, wrong) {
			t.Fatalf("capability message contains %q: %s", wrong, r.Message)
		}
	}
}

// The first-setup starter route is fixed to NFQWS2. A limit of the saved mode
// is named before any component check, budget or probe; nothing else on App
// is needed to reach that decision.
func TestAutonomyStarterCapabilityRefusalPrecedesChecksAndBudget(t *testing.T) {
	starter := starterService(t, "youtube")
	custom := catalog.Service{ID: "custom-cidr", Name: "Свой", CIDRs: []string{"203.0.113.0/24"}, ProbeURL: "https://custom.example/"}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{starter, custom}}}
	p := autonomy.Default()
	switches := []time.Time{time.Now().Add(-time.Minute)}
	for _, tc := range []struct {
		name    string
		service catalog.Service
		mutate  func(*config.Config)
		want    string
	}{
		{"inactive-negative", starter, func(c *config.Config) {
			c.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 1, Manual: []config.ResourceMatch{{Kind: "suffix", Value: "unrelated.example"}}}
		}, "Очистите список «Сайты без обхода»"},
		{"list-domain-service", starter, func(c *config.Config) { c.NetworkPolicy = autonomyExclusionPolicy() }, "задан доменами"},
		{"list-cidr-service", custom, func(c *config.Config) { c.NetworkPolicy = autonomyExclusionPolicy() }, "узел Xray"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Services[tc.service.ID] = config.ServiceState{Enabled: true, Route: "nfqws2"}
			tc.mutate(&cfg)
			s := autonomy.Service{ID: tc.service.ID, Enabled: true, ExpectedRoute: "nfqws2"}
			r := a.runNFQWS2Starter(context.Background(), p, s, autonomy.Runtime{Switches: slices.Clone(switches)}, tc.service, cfg, "profile")
			requireTerminalCapabilityMessage(t, r, tc.want)
			if !slices.Equal(r.Switches, switches) || !r.CheckedAt.IsZero() {
				t.Fatalf("budget or check consumed: %+v", r)
			}
		})
	}
	// In list mode the service's own domains are named before the count of
	// the other bypassed services: they block it even when it is alone.
	cfg := config.Default()
	cfg.NetworkPolicy = autonomyExclusionPolicy()
	for _, id := range []string{"youtube", "custom-cidr"} {
		cfg.Services[id] = config.ServiceState{Enabled: true, Route: "nfqws2"}
	}
	if refusal := a.autonomyCapabilityRefusal(cfg, "youtube", "nfqws2"); refusal == nil || refusal.Code != capabilityServiceDomains {
		t.Fatalf("domains not named first: %+v", refusal)
	}
	if refusal := a.autonomyCapabilityRefusal(cfg, "custom-cidr", "xray:node-1"); refusal == nil || refusal.Code != capabilitySingleService {
		t.Fatalf("other bypassed service not named: %+v", refusal)
	}
	cfg.Services["youtube"] = config.ServiceState{Enabled: true, Route: "direct"}
	cfg.NetworkPolicy.Clients = config.ClientScope{Mode: "selected_devices", SegmentIDs: []string{"home"}, DeviceIDs: []string{"tv"}, NewDevices: "base"}
	if refusal := a.autonomyCapabilityRefusal(cfg, "custom-cidr", "xray:node-1"); refusal != nil {
		t.Fatalf("the wired managed Xray lane was refused: %+v", refusal)
	}
	if refusal := a.autonomyCapabilityRefusal(config.Default(), "youtube", "sing-box"); refusal != nil {
		t.Fatalf("an open legacy path was refused: %+v", refusal)
	}
}

// Refusals before Stage return the reserved switch and never claim a
// rollback; an attempted transaction keeps its own wording and budget.
func TestAutonomyApplyRefusedBeforeStageReturnsSwitch(t *testing.T) {
	reserved := func() autonomy.Runtime {
		r := autonomy.Runtime{}
		if !r.ReserveSwitch(time.Now(), 4) {
			t.Fatal("reserve")
		}
		return r
	}
	refusal := legacyExecutorRefusal(config.Config{NetworkPolicy: autonomyExclusionPolicy()})
	r := reserved()
	state, message, blocked := autonomyRouteDependency(fmt.Errorf("plan: %w", refusal), &r)
	r.State, r.Message = state, message
	if !blocked || len(r.Switches) != 0 {
		t.Fatalf("capability refusal kept the switch: %v %+v", blocked, r)
	}
	requireTerminalCapabilityMessage(t, r, "NFQWS2")

	r = reserved()
	state, message, blocked = autonomyRouteDependency(errAutonomyPlanNotReady, &r)
	if !blocked || state != "apply-refused" || len(r.Switches) != 0 || !strings.Contains(message, "не начиналось") || strings.Contains(message, "откат") {
		t.Fatalf("unready plan: %v %q %q %+v", blocked, state, message, r)
	}

	r = reserved()
	state, message = autonomyLegacyApplyRefused(dataplane.ErrReviewChanged, &r, "attempted")
	if state != "apply-refused" || len(r.Switches) != 0 || !strings.Contains(message, "не начиналось") || strings.Contains(message, "откат") {
		t.Fatalf("refusal before Stage: %q %q %+v", state, message, r)
	}

	r = reserved()
	state, message = autonomyLegacyApplyRefused(&autonomyApplyFailure{Cause: errors.New("health")}, &r, "attempted")
	if state != "apply-refused" || message != "attempted" || len(r.Switches) != 1 {
		t.Fatalf("attempted transaction lost its wording or budget: %q %q %+v", state, message, r)
	}
}

// Real coordinator, Store and node registry: a saved mode that no autopilot
// route can carry ends the round before any node check or Apply, and later
// rounds stay quiet until the owner changes it.
func TestAutonomyRoundNamesCapabilityLimitWithoutChecks(t *testing.T) {
	for _, mode := range []string{"inactive-negative", "list-lan-except"} {
		t.Run(mode, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			if mode == "list-lan-except" {
				autonomyExclusionSetup(t, a, autonomyExclusionPolicy())
			} else {
				manual := []config.ResourceMatch{{Kind: "suffix", Value: "unrelated.example"}}
				if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &manual, nil); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			a.NodeChecker = jobNodeChecker(func(_ context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
				checks++
				return autofallbackResult(request, true), nil
			})
			before := a.Store.Get()
			switches := slices.Clone(autonomyTestState(a).Switches)
			for round := 0; round < 2; round++ {
				autonomyTestDue(a, false)
				a.autonomyRound(context.Background(), time.Now())
				r := autonomyTestState(a)
				// The fixture also keeps YouTube enabled through USQUE.
				want := "Сайты без обхода"
				if mode == "list-lan-except" {
					want = "один сервис"
				}
				requireTerminalCapabilityMessage(t, r, want)
				if checks != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !slices.Equal(switches, r.Switches) {
					t.Fatalf("round %d checked, applied or spent budget: checks=%d calls=%v", round, checks, adapter.calls)
				}
			}
			if mode != "inactive-negative" {
				return
			}
			// Clearing the list is the owner's change: the next round works normally.
			clear := []config.ResourceMatch{}
			if _, err := a.Store.UpdateResourceExclusions(context.Background(), a.Store.Get(), &clear, nil); err != nil {
				t.Fatal(err)
			}
			autonomyTestDue(a, false)
			a.autonomyRound(context.Background(), time.Now())
			if r := autonomyTestState(a); checks == 0 || r.State == "capability-refused" {
				t.Fatalf("cleared list did not resume the autopilot: checks=%d %+v", checks, r)
			}
		})
	}
}

func TestPanelDoctorCapabilityRefusalPromisesNoRetry(t *testing.T) {
	a := doctorFixture(t, true, true)
	a.autonomy.doc.Runtime["discord"] = autonomy.Runtime{State: "capability-refused", Message: "Сервис задан доменами."}
	c := a.doctorServices()
	if c.Status != "fail" || strings.Contains(c.Detail, "продолжает попытки") || !strings.Contains(c.Detail, "текущем режиме") {
		t.Fatalf("doctor promised a retry for a capability limit: %+v", c)
	}
	a.autonomy.doc.Runtime["youtube"] = autonomy.Runtime{State: "apply-refused", Message: "Не удалось включить."}
	if c = a.doctorServices(); strings.Contains(c.Detail, "продолжает попытки") || !strings.Contains(c.Detail, "изменения настроек") {
		t.Fatalf("mixed problems: %+v", c)
	}
}

// A runtime message longer than the journal bound used to make the journal
// refuse the write and block the whole autopilot until restart.
func TestAutonomyRuntimeMessageIsBoundedForTheJournal(t *testing.T) {
	long := strings.Repeat("Длинное объяснение причины. ", 60)
	got := boundedAutonomyMessage(long)
	if len(got) > autonomyMessageLimit || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
		t.Fatalf("message not bounded on a character boundary: %d bytes", len(got))
	}
	if short := "Короткое сообщение."; boundedAutonomyMessage(short) != short {
		t.Fatal("short message changed")
	}
}
