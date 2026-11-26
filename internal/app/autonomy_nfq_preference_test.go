package app

import (
	"context"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyNFQFirstStartKeepsAutoAndConfirmsAppliedRoute(t *testing.T) {
	a, model, probes := autoNFQFirstStartFixture(t)
	const id = "discord"
	first := runAutoNFQDispatcher(t, a, id, func() bool { return true }, nil)
	if first.State != "applied" || !first.CheckedAt.IsZero() || *probes != 0 || !model.committed {
		t.Fatalf("first round did not commit the local route before confirmation: %+v, calls=%v, probes=%d", first, model.calls, *probes)
	}

	before := a.Store.Get()
	image, err := restorejournal.ReadFileImage(context.Background(), a.autonomy.path)
	if err != nil || !image.Exists {
		t.Fatalf("read saved Auto intent: %v", err)
	}
	doc, err := decodeAutonomy(image.Data)
	if err != nil {
		t.Fatal(err)
	}
	saved, applied := doc.Services[id], before.AppliedServices[id]
	if saved.ExpectedRoute != "auto" || saved.DraftFingerprint != autonomyDraftFingerprint(before.Services[id]) || !applied.Enabled || selectedRoute(applied) != "nfqws2" {
		t.Fatalf("committed NFQWS2 replaced the Auto intent or saved a stale draft: intent=%q applied=%+v", saved.ExpectedRoute, applied)
	}
	if !nfqws2FirstStartConfirmationPending(before, saved, first) {
		t.Fatal("the committed Auto assignment did not request its first confirmation")
	}

	policy := a.autonomyPolicy()
	var requested []string
	attributed := false
	a.RouteProber = autonomyResourceRouteProber(func(_ context.Context, service catalog.Service, route string) testlab.Result {
		requested = append(requested, service.ID+"/"+route)
		return testlab.Result{ServiceID: service.ID, ServiceName: service.Name, ProbeURL: service.ProbeURL,
			Route: route, Status: "pass", Verdict: evidence.VerdictPass, Outcome: evidence.OutcomeServiceAccepted,
			HTTPStatus: http.StatusOK, CheckedAt: time.Now().UTC().Format(time.RFC3339), RouteConfirmed: attributed}
	})
	model.calls = nil
	previous := first
	for _, want := range []string{"unconfirmed", "healthy"} {
		if !a.autonomyRuntime(policy.Revision, id, previous) {
			t.Fatal("could not save the previous round")
		}
		result := runAutoNFQDispatcher(t, a, id, func() bool {
			t.Error("an applied route called the cold start review")
			return false
		}, func(_ *autonomy.Policy, _ *autonomy.Service, r *autonomy.Runtime, _ *context.Context) {
			r.State = "checking"
		})
		if result.State != want || result.CheckedAt.IsZero() || result.FailureNode != "nfqws2" || !slices.Equal(result.Switches, first.Switches) {
			t.Fatalf("confirmation with route attribution %v scored %+v, want %q", attributed, result, want)
		}
		previous = result
		attributed = true
	}
	if !slices.Equal(requested, []string{"discord/nfqws2", "discord/nfqws2"}) || len(model.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("confirmation reran Apply, changed settings, or checked a different route: probes=%v calls=%v", requested, model.calls)
	}
}
