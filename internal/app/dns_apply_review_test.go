package app

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

type dnsReviewAdapter struct {
	*nodeApplyAdapter
	dns    *dnscontrol.Manager
	review dnscontrol.ServiceSelectionReview
}

func (a *dnsReviewAdapter) ID() string                           { return "dns-scoped" }
func (a *dnsReviewAdapter) Deactivate(ctx context.Context) error { return ctx.Err() }
func (a *dnsReviewAdapter) Commit(ctx context.Context, p dataplane.Plan, root string) error {
	if err := a.dns.CommitServiceSelection(a.review); err != nil {
		return err
	}
	return a.nodeApplyAdapter.Commit(ctx, p, root)
}
func (a *dnsReviewAdapter) CommitRetirement(ctx context.Context, p dataplane.Plan, root string) error {
	return a.Commit(ctx, p, root)
}
func (a *dnsReviewAdapter) Rollback(ctx context.Context, p dataplane.Plan, root string) error {
	return errors.Join(a.dns.RestoreServiceSelection(a.review.Receipt()), a.nodeApplyAdapter.Rollback(ctx, p, root))
}
func (a *dnsReviewAdapter) VerifyRollback(context.Context, dataplane.Plan, string) (bool, error) {
	err := a.dns.VerifyServiceSelection(a.review.ServiceID, a.review.Applied)
	return err == nil, err
}

func TestDNSApplicationReviewAndJointSettingsCommit(t *testing.T) {
	for _, change := range []string{"none", "stage-draft", "health-draft", "config-write", "retire"} {
		t.Run(change, func(t *testing.T) {
			a := genericReviewFixture(t)
			a.DNS, _ = dnscontrol.New("")
			if err := a.DNS.SetServiceDraft("telegram", "private"); err != nil {
				t.Fatal(err)
			}
			a.Dataplane = dataplane.New(t.TempDir())
			a.Dataplane.FreshProfile = func(context.Context) (string, error) { return "wan-0123456789ab", nil }
			identity, _ := a.DNS.ScopedProfileIdentity("private")
			route := dataplane.Route{ServiceID: "telegram", ServiceName: "Telegram", Selected: "direct", Resolved: "direct", Domains: []string{"telegram.org"}, Sources: []string{"192.168.1.40/32"}, ProbeURL: "https://telegram.org/"}
			input := dataplane.Input{Revision: a.Store.Get().Revision, NetworkProfileID: "wan-0123456789ab", Routes: []dataplane.Route{route}, Engines: []dataplane.Engine{{ID: "dns-scoped", Installed: true, Configured: true, Activatable: true}}, DNS: &dataplane.ScopedDNSPlan{Listener: "192.168.1.1:10553", Ingress: "br0", Probe: catalog.Probe{ID: "web", Label: "Web", URL: route.ProbeURL, Required: true}, Bindings: []dataplane.ScopedDNSBinding{{ServiceID: "telegram", Client: "192.168.1.40", Domain: "telegram.org", ProfileID: "private", ProfileDigest: identity}}}}
			p, err := dataplane.Build(input)
			if err != nil || !p.Ready {
				t.Fatalf("plan: %v %+v", err, p.Blockers)
			}
			binding, err := a.bindApplyReview(context.Background(), a.Store.Get(), p, changeScopeServices, "")
			if err != nil {
				t.Fatal(err)
			}
			adapter := &dnsReviewAdapter{dns: a.DNS, review: binding.dnsSelections[0], nodeApplyAdapter: &nodeApplyAdapter{}}
			adapter.after = func(phase string) error {
				if change == "stage-draft" && phase == "stage" || change == "health-draft" && phase == "health" {
					return a.DNS.SetServiceDraft("telegram", "unfiltered")
				}
				return nil
			}
			if err := a.Dataplane.Register(adapter); err != nil {
				t.Fatal(err)
			}
			ctx := dataplane.WithReviewGuard(context.Background(), func(ctx context.Context) error { return binding.guard(a, ctx) })
			e, err := a.applyDataplane(ctx, p, func() (func() error, error) {
				if change == "config-write" {
					return nil, errors.New("injected config failure")
				}
				return binding.commit(a, ctx, changeScopeServices)
			})
			if change == "none" || change == "retire" {
				if err != nil || e.State != "committed" || a.DNS.VerifyServiceSelection("telegram", "private") != nil {
					t.Fatalf("joint commit failed: %v %+v", err, e)
				}
			} else {
				if err == nil || e.State == "committed" || a.DNS.VerifyServiceSelection("telegram", "") != nil {
					t.Fatalf("failed transaction left settings applied: %v %+v", err, e)
				}
				if change == "stage-draft" && slices.Contains(adapter.calls, "activate") {
					t.Fatal("changed draft reached activation")
				}
			}
			if change == "retire" {
				input.DNS = nil
				input.RetiringAdapters = []string{adapter.ID()}
				p, err = dataplane.Build(input)
				if err != nil {
					t.Fatal(err)
				}
				binding, err = a.bindApplyReview(context.Background(), a.Store.Get(), p, changeScopeServices, "")
				if err != nil {
					t.Fatal(err)
				}
				adapter.review = binding.dnsSelections[0]
				ctx = dataplane.WithReviewGuard(context.Background(), func(ctx context.Context) error { return binding.guard(a, ctx) })
				e, err = a.applyDataplane(ctx, p, func() (func() error, error) { return binding.commit(a, ctx, changeScopeServices) })
				if err != nil || e.State != "committed" || a.DNS.VerifyServiceSelection("telegram", "") != nil || a.DNS.Snapshot().ServiceDrafts["telegram"] != "private" {
					t.Fatalf("retirement lost review/draft: %v %+v", err, e)
				}
			}
		})
	}
}
