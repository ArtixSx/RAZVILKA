package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestAutonomyInheritanceKeepsExplicitServiceDeviceScope(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	const id = "telegram"
	want := []string{"192.168.1.44/32"}
	draft := config.ServiceState{Enabled: true, Route: "auto", Sources: want}
	if err := a.Store.UpdateService(id, draft); err != nil {
		t.Fatal(err)
	}
	if err := a.inheritAutonomyService(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	spec := a.autonomy.doc.Services[id]
	if !spec.Enabled || spec.AllLAN || !slices.Equal(spec.Sources, want) {
		t.Fatalf("saved devices were replaced with the wizard default: %+v", spec)
	}
}

func TestAutonomyReenableReplacesQueuedDisableWithoutRemovingAppliedRoute(t *testing.T) {
	ctx := t.Context()
	a, _, adapter := autonomousIntegrationFixture(t)
	const id = "my-independent-site"
	enroll := httptest.NewRecorder()
	a.autonomyEnroll(enroll, autonomyRequest(http.MethodPost, "/api/v1/autonomy/services", map[string]any{
		"service_id": id, "enabled": true, "sources": []string{"192.168.1.62/32"},
		"expected_revision": a.autonomyPolicy().Revision, "confirm": "MANAGE_SERVICE",
	}))
	if enroll.Code != http.StatusOK {
		t.Fatalf("could not set service-specific scope: %d %s", enroll.Code, enroll.Body.String())
	}
	a.NodeChecker = jobNodeChecker(func(_ context.Context, req dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, error) {
		return d10Result(req, "sing-box", true), nil
	})
	a.autonomyRound(ctx, time.Now())
	applied := a.Store.Get().AppliedServices[id]
	if !applied.Enabled {
		t.Fatalf("expected an applied route before changing the intent: %+v", autonomyTestState(a))
	}
	adapter.calls = nil
	save := func(enabled bool) {
		t.Helper()
		w := httptest.NewRecorder()
		a.service(w, autonomyRequest(http.MethodPut, "/api/v1/services/"+id, config.ServiceState{Enabled: enabled, Route: "auto"}))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"autonomy_warning":""`) {
			t.Fatalf("save enabled=%v: %d %s", enabled, w.Code, w.Body.String())
		}
	}
	save(false)
	removal := a.autonomy.doc.Services[id]
	removalPolicy := a.autonomyPolicy()
	if !removal.Removing || autonomyTestState(a).State != "removal-pending" {
		t.Fatal("disable did not queue scoped removal")
	}
	save(true)
	if a.autonomyConsent(removalPolicy, removal) {
		t.Fatal("the previous revision can still remove the newly enabled route")
	}
	fresh := &App{Store: a.Store, Catalog: a.Catalog}
	if err := fresh.loadAutonomy(ctx); err != nil {
		t.Fatal(err)
	}
	intent := fresh.autonomy.doc.Services[id]
	if !intent.Enabled || intent.Removing || intent.ExpectedRoute != "auto" || intent.AllLAN ||
		!slices.Equal(intent.Sources, applied.Sources) || intent.DraftFingerprint != autonomyDraftFingerprint(a.Store.Get().Services[id]) {
		t.Fatalf("reenable did not retain the scoped intent: %+v", intent)
	}
	a.autonomyRound(ctx, time.Now())
	if got := a.Store.Get().AppliedServices[id]; !reflect.DeepEqual(got, applied) || slices.Contains(adapter.calls, "commit") {
		t.Fatalf("the superseded removal changed the working route: %+v, calls=%v", got, adapter.calls)
	}
}

// Enrollment of an inactive, reviewed WG draft must not silently turn its
// profile binding into legacy unreviewed intent when it joins the active list.
func TestAutonomyActivationPreservesReviewedDraftBindingAndConsentedScope(t *testing.T) {
	for _, sources := range [][]string{nil, {"192.168.1.50/32"}} {
		t.Run(strings.Join(sources, ","), func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			const id = "my-independent-site"
			before := config.ServiceState{
				Enabled: false, Mode: "wireguard:backup", Route: "wireguard:backup",
				WireGuardProfileRevision: strings.Repeat("a", 64),
				Sources:                  []string{"192.168.1.40/32"},
			}
			if err := a.Store.UpdateService(id, before); err != nil {
				t.Fatal(err)
			}
			a.autonomy.mu.Lock()
			spec := a.autonomy.doc.Services[id]
			spec.ExpectedRoute = before.Route
			spec.Sources = append([]string(nil), sources...)
			spec.AllLAN = len(sources) == 0
			spec.DraftFingerprint = autonomyDraftFingerprint(a.Store.Get().Services[id])
			a.autonomy.doc.Services[id] = spec
			a.autonomy.mu.Unlock()
			a.autonomyRound(context.Background(), time.Now())
			want := before
			want.Enabled, want.Sources = true, append([]string(nil), sources...)
			got := a.Store.Get().Services[id]
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("activation changed the reviewed draft outside consent: got %+v, want %+v", got, want)
			}
			a.autonomy.mu.Lock()
			fingerprint := a.autonomy.doc.Services[id].DraftFingerprint
			a.autonomy.mu.Unlock()
			if fingerprint != autonomyDraftFingerprint(got) || len(adapter.calls) != 0 {
				t.Fatal("activation did not retain the exact draft or unexpectedly applied it")
			}
		})
	}
}
