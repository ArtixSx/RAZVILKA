package defaultconsent

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Genuine Store, approval, original control and same scope owner. The imported
// node supplies syntax only; this test creates no transport or service PASS.
func autonomyScopeFixture(t *testing.T) (*fixture, *ScopeReview) {
	t.Helper()
	f := consentFixture(t)
	if err := f.store.UpdateService("target", config.ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Approve(f.ctx, f.store.Get(), f.policy, nil); err != nil {
		t.Fatal(err)
	}
	r, err := f.owner.ReviewScope(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return f, r
}

func TestScopeConsumesActualAutonomyCommitAndExactOriginalUndo(t *testing.T) {
	f, r := autonomyScopeFixture(t)
	before, reference := f.store.Get(), r.Reference()
	undo, commit, err := f.store.ApplyAutonomyRouteReviewedWithRollback("target", f.grant.Resolved, before.Services["target"].Sources, before.Revision)
	if err != nil {
		t.Fatal(err)
	}
	after := f.store.Get()
	if r.Current(f.ctx) == nil || r.AcceptAutonomyCommitted(f.ctx, commit) != nil || r.Current(f.ctx) != nil || r.Reference() != reference {
		t.Fatal("same original scope did not consume actual single-service publication")
	}
	if !reflect.DeepEqual(before.DefaultRouteConsent, after.DefaultRouteConsent) {
		t.Fatal("single-service commit renewed approval")
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if err := r.AcceptAutonomyRestored(f.ctx, commit); err != nil || r.Current(f.ctx) != nil || r.Reference() != reference || !reflect.DeepEqual(f.store.Get(), before) {
		t.Fatal("actual undo did not restore original scope/revision/time", err)
	}
}

func TestScopeAutonomyFailedConsumptionCannotRenewOriginalReview(t *testing.T) {
	for _, mode := range []string{"nil", "unissued", "undo-not-run", "foreign-draft", "control", "raw-context", "copy", "closed", "repeat"} {
		t.Run(mode, func(t *testing.T) {
			f, r := autonomyScopeFixture(t)
			before := f.store.Get()
			_, commit, err := f.store.ApplyAutonomyRouteReviewedWithRollback("target", f.grant.Resolved, before.Services["target"].Sources, before.Revision)
			if err != nil {
				t.Fatal(err)
			}
			actual := commit
			ctx := f.ctx
			restored := false
			switch mode {
			case "nil":
				commit = nil
			case "unissued":
				commit = &config.AutonomyRouteCommitReview{}
			case "undo-not-run":
				restored = true
			case "foreign-draft":
				if err := f.store.UpdateService("foreign", config.ServiceState{Route: "direct"}); err != nil {
					t.Fatal(err)
				}
			case "control":
				if _, err := operationgate.RequestSelfUpdateStop(f.ctx, f.controlRoot, "0123456789abcdef0123456789abcdef", f.store.Get().Revision); err != nil {
					t.Fatal(err)
				}
			case "raw-context":
				ctx = context.Background()
			case "copy":
				r = &ScopeReview{self: r, review: r.review}
			case "closed":
				_ = r.Close()
			case "repeat":
				if err := r.AcceptAutonomyCommitted(f.ctx, commit); err != nil {
					t.Fatal(err)
				}
			}
			accept := r.AcceptAutonomyCommitted
			if restored {
				accept = r.AcceptAutonomyRestored
			}
			if err := accept(ctx, commit); err == nil {
				t.Fatal("unowned transition adopted current config", mode)
			}
			if mode == "nil" || mode == "unissued" || mode == "undo-not-run" || mode == "raw-context" {
				if err := r.AcceptAutonomyCommitted(f.ctx, actual); err == nil || r.Current(f.ctx) == nil {
					t.Fatal("corrected tuple revived failed transition scope", mode)
				}
			}
		})
	}
}
