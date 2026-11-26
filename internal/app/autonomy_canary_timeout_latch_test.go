package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestAutonomyCanaryContinuationPublicationRestoresLatchOnClosingRefusal(t *testing.T) {
	for _, mode := range []string{"closed", "opening-review", "closing-review", "closing-cancel", "publication-cancel", "publication-io", "publication-revision"} {
		t.Run(mode, func(t *testing.T) {
			a, ids, _ := autonomousIntegrationFixture(t)
			r := autonomyTestState(a)
			r.Search = &autonomy.Traversal{Version: strings.Repeat("a", 64), Ordered: ids, Cursor: 1, Halted: true}
			revision := a.autonomyPolicy().Revision
			if err := a.persistAutonomySearch(context.Background(), revision, "my-independent-site", r); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			guard := func(context.Context) error {
				checks++
				if mode == "opening-review" || mode == "closing-review" && checks == 2 {
					return dataplane.ErrReviewChanged
				}
				if mode == "closing-cancel" && checks == 2 {
					cancel()
					return ctx.Err()
				}
				if mode == "publication-cancel" && checks == 1 {
					cancel()
				}
				if mode == "publication-revision" && checks == 1 {
					a.autonomy.mu.Lock()
					a.autonomy.doc.Policy.Revision++
					err := a.persistAutonomyLocked(context.Background())
					a.autonomy.mu.Unlock()
					if err != nil {
						t.Fatal(err)
					}
				}
				if mode == "publication-io" && checks == 1 {
					if err := os.Remove(a.autonomy.path); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(a.autonomy.path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			continued, err := a.resumeAutonomyAfterCanary(ctx, revision, "my-independent-site", &r, guard)
			if continued != (mode == "closed") || (err == nil) != continued || r.Search.Halted == continued {
				t.Fatal("wrong in-memory scheduling latch", mode, continued, err, r.Search)
			}
			if mode == "publication-io" {
				if release, gateErr := a.Operations.Enter(context.Background()); gateErr == nil {
					release()
					t.Fatal("unconfirmed relatch did not fence journal")
				} else if !errors.Is(gateErr, operationgate.ErrJournalRecovery) {
					t.Fatal(gateErr)
				}
				return
			}
			if mode == "publication-revision" {
				stored := autonomyTestState(a)
				if !errors.Is(err, dataplane.ErrReviewChanged) || stored.Search == nil || !stored.Search.Halted || checks != 1 {
					t.Fatal("stale attempt changed the new generation's latch", err, checks, stored.Search)
				}
			}
			// The worker may save its returned runtime again. It must retain the
			// restored latch and a reload must not resurrect permission.
			if err := a.persistAutonomySearch(context.Background(), a.autonomyPolicy().Revision, "my-independent-site", r); err != nil {
				t.Fatal(err)
			}
			d10Reopen(t, a)
			stored := autonomyTestState(a)
			if stored.Search == nil || stored.Search.Halted != !continued {
				t.Fatal("restart/status publication lost safety latch", mode, stored.Search)
			}
			if release, gateErr := a.Operations.Enter(context.Background()); gateErr != nil {
				t.Fatal("confirmed relatch unnecessarily fenced", gateErr)
			} else {
				release()
			}
		})
	}
}
