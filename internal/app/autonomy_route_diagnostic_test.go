package app

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/testlab"
)

func TestAutonomyRouteRefusalHasBoundedDiagnosticWithoutPublishingEvidence(t *testing.T) {
	for _, tc := range []struct{ scenario, reason string }{
		{"resource-before", "resource-before-refused"},
		{"network-after", "network-after-refused"},
		{"resource-after", "resource-after-refused"},
		{"unproved", "route-proof-unconfirmed"},
		{"timeout", "probe-timeout"},
		{"stale", "result-not-fresh"},
		{"foreign-detail", "route-proof-unconfirmed"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			a, _, adapter := autonomousIntegrationFixture(t)
			runner := testlab.NewRunner()
			a.TestLab = runner
			service, _ := a.autonomyService("my-independent-site")
			profile, _ := a.freshNetworkProfile(context.Background())
			changed := false
			a.FreshProfile = func(context.Context) (string, error) {
				if changed && tc.scenario == "network-after" {
					return "wan-ffffffffffff", nil
				}
				return profile, nil
			}
			calls := 0
			const private = "private-node-config-https://secret.invalid/?token=hidden"
			a.RouteProber = autonomyResourceRouteProber(func(ctx context.Context, s catalog.Service, route string) testlab.Result {
				calls++
				changed = true
				result := confirmedRouteProber{}.Probe(ctx, s, route)
				if tc.scenario == "resource-after" {
					a.autonomy.mu.Lock()
					a.autonomy.doc.Policy.Enabled = false
					a.autonomy.mu.Unlock()
				}
				switch tc.scenario {
				case "unproved", "foreign-detail":
					result.RouteConfirmed = false
					result.RouteProofError = private
					result.Detail = private
					result.ErrorCode = private
				case "timeout":
					result.RouteConfirmed = false
					result.Status = "fail"
					result.Detail = "TLS handshake timeout " + private
					result.ErrorCode = "timeout"
				case "stale":
					result.CheckedAt = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
				}
				return result
			})
			if tc.scenario == "resource-before" {
				a.autonomy.mu.Lock()
				a.autonomy.doc.Policy.Enabled = false
				a.autonomy.mu.Unlock()
			}
			ctx, release, err := a.privateExclusiveOperation(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			observation := a.autonomyProbeRouteObservation(ctx, service, "direct", profile)
			log.SetOutput(previous)
			if observation.Verdict != "INCONCLUSIVE" || observation.Reason != tc.reason || observation.RetryAfterSeconds != 0 {
				t.Fatalf("%+v", observation)
			}
			if !strings.Contains(output.String(), "reason="+tc.reason) || strings.Contains(output.String(), private) {
				t.Fatal("missing bounded diagnostic or leaked provider detail", output.String())
			}
			if len(runner.Current()) != 0 || len(adapter.calls) != 0 || tc.scenario == "resource-before" && calls != 0 {
				t.Fatal("refusal published evidence or mutated route", calls)
			}
		})
	}
}

func TestAutonomyObservationContextDiagnosticDoesNotExposeErrorText(t *testing.T) {
	if got := autonomyObservationContextReason(context.Background(), "resource-after", context.DeadlineExceeded); got != "resource-after-deadline" {
		t.Fatal("leaf timeout was hidden", got)
	}
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := autonomyObservationContextReason(deadline, "network-after"); got != "network-after-deadline" {
		t.Fatal(got)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if got := autonomyObservationContextReason(canceled, "resource-before"); got != "resource-before-canceled" {
		t.Fatal(got)
	}
}
