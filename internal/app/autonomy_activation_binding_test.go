package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

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
