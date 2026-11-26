package testlab

import (
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func TestRequiredScenarioHTTP429KeepsCooldownWithoutHidingFailure(t *testing.T) {
	row := func(id string, status int, retry string) Result {
		r := Result{ServiceID: "speedtest", Route: "nfqws2", ScenarioID: id, ScenarioNeeded: true, RouteConfirmed: true, HTTPStatus: status, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
		r.EvaluateHTTP(catalog.Service{}, probecheck.Observation{HTTPStatus: status, RetryAfter: retry})
		return r
	}
	rows := []Result{row("web", 200, ""), row("api", 429, "120")}
	got := AggregateScenarios(rows)
	if len(got) != 1 || got[0].Status != "partial" || got[0].Verdict != evidence.VerdictPartial || got[0].RetryAfterSeconds != 120 || got[0].ErrorCode != "http-429" {
		t.Fatal("rate limit lost or promoted", got)
	}
	rows = append(rows, row("blocked", 451, ""))
	got = AggregateScenarios(rows)
	if len(got) != 1 || got[0].Verdict != evidence.VerdictBlocked || got[0].RetryAfterSeconds != 0 {
		t.Fatal("rate limit hid a required failure", got)
	}
}
