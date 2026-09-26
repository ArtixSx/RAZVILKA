package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

func TestScopedDNSSettingsJointConfigFailureAndRetirement(t *testing.T) {
	for _, retirement := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "retirement"}[retirement], func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			in.Revision++
			if err := a.DNS.SetServiceDraft("web", "unfiltered"); err != nil {
				t.Fatal(err)
			}
			if retirement {
				in.DNS = nil
				in.RetiringAdapters = []string{a.ID()}
			} else {
				in.DNS.Bindings[0].ProfileID = "unfiltered"
				in.DNS.Bindings[0].ProfileDigest, _ = a.DNS.ScopedProfileIdentity("unfiltered")
			}
			next, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			e, err := m.Apply(context.Background(), next, func() (func() error, error) {
				want := "unfiltered"
				if retirement {
					want = ""
				}
				if err := a.DNS.VerifyServiceSelection("web", want); err != nil {
					t.Fatal("DNS was not committed before route settings", err)
				}
				if err := a.DNS.SetServiceDraft("other", "security"); err != nil {
					t.Fatal(err)
				}
				return nil, errors.New("route configuration write failed")
			})
			if err == nil || e.State != "rolled-back" || !e.RollbackVerified || len(f.rules) != 2 || !dnsSessionAlive(a.live) {
				t.Fatalf("joint undo failed: %+v %v", e, err)
			}
			if a.DNS.VerifyServiceSelection("web", "private") != nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" || a.DNS.Snapshot().ServiceDrafts["other"] != "security" {
				t.Fatal("joint undo damaged settings")
			}
			in.Revision++
			next, _ = Build(in)
			if _, err = m.Apply(context.Background(), next, nil); err != nil {
				t.Fatal("retry failed", err)
			}
			if retirement && (a.DNS.VerifyServiceSelection("web", "") != nil || len(f.rules) != 0) {
				t.Fatal("retirement kept applied DNS")
			}
		})
	}
}

func TestScopedDNSSettingsRestoreFromJournalAfterProcessLoss(t *testing.T) {
	_, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), a.ID())
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate, a.Activate, a.Health, a.Commit} {
		if err := step(ctx, p, root); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate loss after the DNS settings write but before main config commit.
	a.live.cancel()
	<-a.live.done
	a.live = nil
	dns, err := dnscontrol.New(a.DNS.Path)
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewScopedDNSAdapter(ctx, dns, filepath.Dir(a.StateRoot))
	fresh.Runner, fresh.FreshProfile, fresh.ScopeCheck, fresh.HealthProbe, fresh.listen = f, a.FreshProfile, a.ScopeCheck, a.HealthProbe, a.listen
	if err := fresh.Rollback(ctx, p, root); err != nil {
		t.Fatal(err)
	}
	if ok, err := fresh.VerifyRollback(ctx, p, root); err != nil || !ok {
		t.Fatal("durable undo unverified", ok, err)
	}
	if len(f.rules) != 0 || dns.VerifyServiceSelection("web", "") != nil || dns.Snapshot().ServiceDrafts["web"] != "private" {
		t.Fatal("crash undo lost draft or left active DNS")
	}
}
