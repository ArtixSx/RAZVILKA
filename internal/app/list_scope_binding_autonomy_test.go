package app

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// The existing explicit physical/WAN model is the only modeled producer here.
// Store, approval, control, Gate, receipt and original ScopeReview are real.
// No Xray source/proof/process, new Review or native Apply is issued.
func TestListScopeAutonomyKeepsOriginalPhysicalReviewThroughActualCASAndUndo(t *testing.T) {
	a, b, model := listScopeFixture(t, "mac", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		before := a.Store.Get()
		facts, reference := model.snapshot(), b.reference
		checks := model.checks
		undo, receipt, err := a.Store.ApplyAutonomyRouteReviewedWithRollback("listed", "xray:node-"+strings.Repeat("a", 64), []string{"192.168.1.40"}, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.AcceptAutonomyCommitted(ctx, receipt); err != nil {
			t.Fatal("original scope refused actual single-service CAS", err)
		}
		if !reflect.DeepEqual(b.expected, a.Store.Get()) || !reflect.DeepEqual(model.snapshot(), facts) || b.reference != reference || model.closes != 0 || model.checks <= checks {
			t.Fatal("CAS reopened physics or renewed scope approval")
		}
		observed, err := b.Observe(ctx)
		if err != nil || observed.Paths != nil || observed.NodeGeneration != 0 || observed.ProfileGeneration != 0 {
			t.Fatal("scope receipt fabricated node/path evidence", err)
		}
		if err := undo(); err != nil {
			t.Fatal(err)
		}
		if err := b.AcceptAutonomyRestored(ctx, receipt); err != nil || !reflect.DeepEqual(b.expected, before) || !reflect.DeepEqual(a.Store.Get(), before) || !reflect.DeepEqual(model.snapshot(), facts) || b.reference != reference || model.closes != 0 {
			t.Fatal("actual undo renewed the original scope or lost its exact preimage", err)
		}
		if _, err := b.Observe(ctx); err != nil {
			t.Fatal("original physical review could not observe restored scope", err)
		}
	})
}

func TestListScopeAutonomyFailedTransitionCannotReopenOrRevive(t *testing.T) {
	for _, mode := range []string{"nil", "unissued", "undo-not-run", "physical", "foreign-draft", "control", "raw-context", "copy", "close", "repeat"} {
		t.Run(mode, func(t *testing.T) {
			a, b, model := listScopeFixture(t, "mac", false)
			listScopeOperation(t, a, func(ctx context.Context) {
				before := a.Store.Get()
				undo, receipt, err := a.Store.ApplyAutonomyRouteReviewedWithRollback("listed", "xray:node-"+strings.Repeat("a", 64), []string{"192.168.1.40"}, before.Revision)
				if err != nil {
					t.Fatal(err)
				}
				actual, original := receipt, b
				useCtx, restore := ctx, false
				switch mode {
				case "nil":
					receipt = nil
				case "unissued":
					receipt = &config.AutonomyRouteCommitReview{}
				case "undo-not-run":
					restore = true
				case "physical":
					model.verifyErr = physicalscope.ErrUnknown
				case "foreign-draft":
					if err := a.Store.UpdateService("foreign", config.ServiceState{Route: "direct"}); err != nil {
						t.Fatal(err)
					}
				case "control":
					if _, err := operationgate.RequestSelfUpdateStop(ctx, a.SelfUpdateFiles.ControlRoot, "0123456789abcdef0123456789abcdef", a.Store.Get().Revision); err != nil {
						t.Fatal(err)
					}
				case "raw-context":
					useCtx = context.Background()
				case "copy":
					b = &ListScopeBinding{self: original, app: a, store: a.Store}
				case "close":
					if err := b.Close(); err != nil {
						t.Fatal(err)
					}
				case "repeat":
					if err := b.AcceptAutonomyCommitted(ctx, receipt); err != nil {
						t.Fatal(err)
					}
				}
				accept := b.AcceptAutonomyCommitted
				if restore {
					accept = b.AcceptAutonomyRestored
				}
				if err := accept(useCtx, receipt); err == nil {
					t.Fatal("unowned transition renewed physical binding", mode)
				}
				if mode == "physical" {
					model.verifyErr = nil
					if err := undo(); err != nil {
						t.Fatal(err)
					}
					if err := b.AcceptAutonomyRestored(ctx, actual); err == nil {
						t.Fatal("actual undo revived failed physical review")
					}
				}
				if mode != "copy" && mode != "close" && (!b.invalid || b.AcceptAutonomyCommitted(ctx, actual) == nil) {
					t.Fatal("corrected receipt revived invalid original binding", mode)
				}
				if mode != "close" && model.closes != 0 {
					t.Fatal("refusal closed or reopened original physical Review", mode)
				}
			})
		})
	}
}

func TestListScopeAutonomyClosesReceiptPhaseAfterPhysicalAndWANCallbacks(t *testing.T) {
	a, b, model := listScopeFixture(t, "mac", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		before := a.Store.Get()
		undo, receipt, err := a.Store.ApplyAutonomyRouteReviewedWithRollback("listed", "xray:node-"+strings.Repeat("a", 64), []string{"192.168.1.40"}, before.Revision)
		if err != nil {
			t.Fatal(err)
		}
		after := a.Store.Get()
		b.network = func(c context.Context) (string, error) {
			if err := undo(); err != nil {
				t.Fatal(err)
			}
			// The explicit WAN callback model performs actual undo followed by a
			// genuine same-Store restore CAS of identical postimage bytes. Tuple
			// equality cannot recreate the first writer's committed phase.
			session, err := a.Store.BeginRestore(c)
			if err != nil {
				t.Fatal(err)
			}
			image, err := session.Read(c)
			if err != nil {
				_ = session.Close()
				t.Fatal(err)
			}
			next := image
			next.Data, err = json.Marshal(after)
			if err == nil {
				err = session.CompareAndSwap(c, image, next)
			}
			if err != nil {
				_ = session.Close()
				t.Fatal(err)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			return model.network, nil
		}
		if err := b.AcceptAutonomyCommitted(ctx, receipt); err == nil || !b.invalid || !reflect.DeepEqual(a.Store.Get(), after) {
			t.Fatal("identical postimage revived a receipt after its actual undo", err)
		}
		if model.closes != 0 {
			t.Fatal("closing phase refusal reacquired or closed original physics")
		}
	})
}
