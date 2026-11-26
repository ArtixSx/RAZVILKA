package defaultconsent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestScopeActualOwnerRevokesOldReviewAndAllowsFreshSameScope(t *testing.T) {
	f := consentFixture(t)
	if _, err := f.owner.Approve(f.ctx, f.store.Get(), f.policy, nil); err != nil {
		t.Fatal(err)
	}
	old, err := f.owner.ReviewScope(f.ctx)
	if err != nil || old.Current(f.ctx) != nil || !old.MatchesConfigStore(f.store) {
		t.Fatal("actual scope reader", err)
	}
	ref := old.Reference()
	if ref.Resolved != "" || ref.EngineID != "" || ref.NodeID != "" || ref.ConsentDigest == "" {
		t.Fatal("scope reader fabricated engine permission")
	}
	manual := []config.ResourceMatch{{Kind: "exact", Value: "excluded.example"}}
	if _, err := f.store.UpdateResourceExclusions(f.ctx, f.store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	if old.Current(f.ctx) == nil {
		t.Fatal("old scope review survived an exclusion edit")
	}
	fresh, err := f.owner.ReviewScope(f.ctx)
	if err != nil || fresh.Current(f.ctx) != nil {
		t.Fatal("unchanged explicitly approved scope needs a redundant approval", err)
	}
	if fresh.Reference().ConsentDigest != ref.ConsentDigest || fresh.Reference().ApprovalRevision != ref.ApprovalRevision || fresh.Reference().PolicyRevision != f.store.Get().NetworkPolicy.Revision {
		t.Fatal("fresh review renewed approval or used the old policy revision")
	}
	for _, remote := range []string{"usque", "warp-wg", "wireguard", f.grant.Resolved} {
		if _, err := f.owner.Review(f.ctx, remote); !errors.Is(err, ErrChanged) {
			t.Fatal("scope-only approval authorized remote provider", remote, err)
		}
	}
	if err := f.store.UpdateService("local", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if fresh.Current(f.ctx) == nil {
		t.Fatal("old review survived active list edit")
	}
	if _, err := f.owner.ReviewScope(f.ctx); err != nil {
		t.Fatal("fresh review refused active list edit within approved scope", err)
	}
}

func TestFreshProviderReviewStillChecksExactSourcesAndCurrentNegatives(t *testing.T) {
	f := consentFixture(t)
	old := f.approve(t)
	manual := []config.ResourceMatch{{Kind: "exact", Value: "excluded.example"}}
	if _, err := f.store.UpdateResourceExclusions(f.ctx, f.store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	if old.Current(f.ctx) == nil {
		t.Fatal("old provider review survived resource edit")
	}
	fresh, err := f.owner.Review(f.ctx, f.grant.Resolved)
	if err != nil {
		t.Fatal("exact approved provider cannot be reviewed again", err)
	}
	if err := fresh.CheckProbeTarget(f.ctx, "excluded.example", nil); !errors.Is(err, ErrProbeTargetExcluded) {
		t.Fatal("fresh provider review waived current negative", err)
	}
	_, _ = f.nodes.SetDisabled(f.ctx, f.grant.ProviderID, true, time.Now().UTC())
	if fresh.Current(f.ctx) == nil {
		t.Fatal("fresh provider review lost actual source fence")
	}
	if _, err := f.owner.Review(f.ctx, f.grant.Resolved); err == nil {
		t.Fatal("new review autoapproved changed source")
	}
}

func TestScopeCurrentRequiresOriginalOperationAndActualOwnerBookends(t *testing.T) {
	for _, change := range []string{"zero", "copy", "closed", "owner-closed", "slot", "control", "callback", "raw-context"} {
		t.Run(change, func(t *testing.T) {
			f := consentFixture(t)
			if _, err := f.owner.Approve(f.ctx, f.store.Get(), f.policy, nil); err != nil {
				t.Fatal(err)
			}
			r, err := f.owner.ReviewScope(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "zero":
				r = &ScopeReview{}
			case "copy":
				r = &ScopeReview{self: r.self, review: r.review}
			case "closed":
				_ = r.Close()
				if r.Reference() != (Reference{}) {
					t.Fatal("closed handle exposed current authority")
				}
			case "owner-closed":
				_ = f.owner.Close()
			case "slot":
				f.store = nil
			case "control":
				_, err = operationgate.RequestSelfUpdateStop(f.ctx, f.controlRoot, "0123456789abcdef0123456789abcdef", f.store.Get().Revision)
				if err != nil {
					t.Fatal(err)
				}
			case "callback":
				if err := r.WithCurrent(f.ctx, func() error { return f.store.UpdateService("new", config.ServiceState{Enabled: true, Route: "nfqws2"}) }); err == nil {
					t.Fatal("closing full config drift accepted")
				}
			case "raw-context":
				if err := r.Current(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
					t.Fatal("raw context granted", err)
				}
				return
			}
			if r.Current(f.ctx) == nil {
				t.Fatal("unowned or revoked scope accepted")
			}
		})
	}
}

func TestScopeExactCommitAfterOrdinaryEditDoesNotAdoptOtherChanges(t *testing.T) {
	f := consentFixture(t)
	if _, err := f.owner.Approve(f.ctx, f.store.Get(), f.policy, nil); err != nil {
		t.Fatal(err)
	}
	manual := []config.ResourceMatch{{Kind: "cidr", Value: "203.0.113.0/24"}}
	if _, err := f.store.UpdateResourceExclusions(f.ctx, f.store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	r, err := f.owner.ReviewScope(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref := r.Reference()
	before := f.store.Get()
	started := time.Now()
	undo, err := f.store.CommitNetworkPolicyWithRollback(before, before.NetworkPolicy, before.Services)
	finished := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	after := f.store.Get()
	if r.Current(f.ctx) == nil || r.AcceptCommitted(f.ctx, after, started, finished) != nil || r.Current(f.ctx) != nil {
		t.Fatal("exact sanctioned policy CAS was not consumed")
	}
	if r.Reference() != ref || !reflect.DeepEqual(after.DefaultRouteConsent, before.DefaultRouteConsent) {
		t.Fatal("commit renewed unchanged explicit scope approval")
	}
	if err := undo(); err != nil || r.Current(f.ctx) == nil {
		t.Fatal("undo still current", err)
	}
}
