package app

import (
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

func TestAutonomyImportWakesWorkerAcrossFirstEmptyRead(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	const id = "my-independent-site"
	now := time.Now()
	empty := &autonomy.Traversal{Exhausted: true}
	for _, tc := range []struct {
		name, source, state string
		search              *autonomy.Traversal
		wantWake            bool
	}{
		{"during first catalog read", "manual", "checking", nil, true},
		{"before empty outcome published", "manual", "checking", empty, true},
		{"after empty outcome published", "manual", "searching", empty, true},
		{"foreign source", "other", "checking", nil, false},
		{"paused", "manual", "paused", empty, false},
		{"halted", "manual", "checking", &autonomy.Traversal{Exhausted: true, Halted: true}, false},
		{"explicit retry", "manual", "checking", &autonomy.Traversal{Exhausted: true, RetryAt: now.Add(time.Hour)}, false},
		{"consumed candidate", "manual", "checking", &autonomy.Traversal{Ordered: []string{"old"}, Cursor: 1, Exhausted: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a.autonomy.doc.Runtime[id] = autonomy.Runtime{State: tc.state, Search: tc.search}
			a.reconciler.doc.Operations = []automationOperation{{Kind: "feeds", State: "running", NextRun: now.Add(time.Hour)}}
			a.reconciler.autonomyWakePending = false
			a.autonomySourceImported(tc.source)
			if got := a.reconciler.autonomyWakePending; got != tc.wantWake {
				t.Fatalf("pending wake = %v, want %v", got, tc.wantWake)
			}
		})
	}
}
