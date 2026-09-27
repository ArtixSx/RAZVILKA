package autonomy

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestCandidateCooldownIsScopedBoundedAndExpires(t *testing.T) {
	now := time.Now().UTC()
	scope := ScopeFingerprint([]string{"192.168.1.2/32", "192.168.1.3/32"})
	if scope != ScopeFingerprint([]string{"192.168.1.3/32", "192.168.1.2/32"}) {
		t.Fatal("source order changed scope")
	}
	r := Runtime{}
	for i := 0; i < 10; i++ {
		r.RecordCandidateFailure(CandidateFailure{NodeID: fmt.Sprint(i), Network: "wan-a", Definition: "definition", Scope: scope, Code: "http-403", ObservedAt: now})
	}
	if len(r.CandidateFailures) != 4 || r.CandidateCoolingDown("0") || !r.CandidateCoolingDown("9") {
		t.Fatal("cooldown not bounded")
	}
	data, _ := json.Marshal(r)
	var restarted Runtime
	if err := json.Unmarshal(data, &restarted); err != nil {
		t.Fatal(err)
	}
	if !restarted.CandidateCoolingDown("9") {
		t.Fatal("restart lost negative observation")
	}
	for _, scenario := range []string{"network", "definition", "scope", "expired", "clock-backwards", "unbounded", "partial"} {
		t.Run(scenario, func(t *testing.T) {
			copy := r.Clone()
			network, definition, source, at := "wan-a", "definition", scope, now
			switch scenario {
			case "network":
				network = "wan-b"
			case "definition":
				definition = "other"
			case "scope":
				source = ScopeFingerprint([]string{"192.168.1.4/32"})
			case "expired":
				at = now.Add(5 * time.Minute)
			case "clock-backwards":
				at = now.Add(-time.Second)
			case "unbounded":
				for i := range copy.CandidateFailures {
					copy.CandidateFailures[i].Until = now.Add(time.Hour)
				}
			case "partial":
				for i := range copy.CandidateFailures {
					copy.CandidateFailures[i].Code = "http-429"
				}
			}
			copy.PruneCandidateFailures(network, definition, source, at)
			if len(copy.CandidateFailures) != 0 || len(r.CandidateFailures) != 4 {
				t.Fatal("stale cooldown or shallow clone")
			}
		})
	}
}
