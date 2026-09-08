package nodecleanup

import (
	"testing"
	"time"
)

func TestCleanupNeverTreatsApplicationFailuresAsDeadNodes(t *testing.T) {
	now := time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC)
	good := func() []Check {
		return []Check{{ServiceID: "s", Network: "wan", Route: "sing-box:n", Verdict: "ERROR", Level: "transport", Code: "node-transport-failed", At: now.Add(-time.Minute), Until: now.Add(time.Minute)}, {ServiceID: "s", Network: "wan", Route: "sing-box:n", Verdict: "ERROR", Level: "transport", Code: "node-transport-failed", At: now.Add(-30 * time.Second), Until: now.Add(time.Minute)}}
	}
	cases := []struct {
		name          string
		edit          func([]Check) []Check
		control, want bool
	}{
		{"two definite failures", func(c []Check) []Check { return c }, true, true},
		{"no control", func(c []Check) []Check { return c }, false, false},
		{"single failure", func(c []Check) []Check { return c[:1] }, true, false},
		{"duplicate time", func(c []Check) []Check { c[1].At = c[0].At; return c }, true, false},
		{"another network", func(c []Check) []Check { c[1].Network = "else"; return c }, true, false},
		{"another route", func(c []Check) []Check { c[1].Route = "sing-box:other"; return c }, true, false},
		{"another service", func(c []Check) []Check { c[1].ServiceID = "else"; return c }, true, false},
		{"future", func(c []Check) []Check { c[1].At = now.Add(time.Minute); return c }, true, false},
		{"stale", func(c []Check) []Check { c[0].Until = now; return c }, true, false},
		{"old", func(c []Check) []Check { c[0].At = now.Add(-time.Hour); return c }, true, false},
		{"inconclusive", func(c []Check) []Check { c[1].Verdict = "INCONCLUSIVE"; return c }, true, false},
		{"runtime unavailable", func(c []Check) []Check { c[1].Code = "node-protocol-start-failed"; return c }, true, false},
		{"DNS error", func(c []Check) []Check { c[1].Code = "node-dns-failed"; return c }, true, false},
		{"service blocked", func(c []Check) []Check { c[1].Code = "node-service-probe-failed"; c[1].Level = "service"; return c }, true, false},
		{"success another service", func(c []Check) []Check { x := c[1]; x.ServiceID = "another"; x.Verdict = "PASS"; return append(c, x) }, true, false},
		{"unknown code", func(c []Check) []Check { c[1].Code = "something-new"; return c }, true, false},
		{"egress", func(c []Check) []Check {
			for i := range c {
				c[i].Code = "node-egress-failed"
				c[i].Level = "protocol"
			}
			return c
		}, true, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := Eligible("n", "s", "wan", tt.edit(good()), now, tt.control); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
