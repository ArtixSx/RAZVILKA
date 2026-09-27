package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestScopedDNSSuspendResumePreservesSavedPolicyAndPendingDraft(t *testing.T) {
	m, a, f, in := scopedAdapterFixture(t)
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.DNS.SetServiceDraft("web", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	routes := in.Routes
	in.Revision++
	in.DNS = nil
	in.Routes = nil
	in.RetiringAdapters = []string{a.ID()}
	in.SuspendDNS = true
	stop, err := Build(in)
	if err != nil || !stop.Ready || stop.Noop {
		t.Fatal("stop plan invalid", err, stop)
	}
	if _, err := m.Apply(context.Background(), stop, nil); err != nil {
		t.Fatal(err)
	}
	saved, _, _ := m.Committed()
	dns, err := m.SuspendedDNS(saved)
	if err != nil || dns.Bindings[0].ProfileID != "private" || len(f.rules) != 0 || a.live != nil {
		t.Fatal("suspend failed", dns, err)
	}
	if a.DNS.VerifyServiceSelection("web", "private") != nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
		t.Fatal("stop consumed pending settings")
	}
	in.Revision++
	in.DNS = dns
	in.Routes = routes
	in.RetiringAdapters = nil
	in.SuspendDNS = false
	in.NetworkProfileID = "wan-abcdef012345"
	a.FreshProfile = func(context.Context) (string, error) { return in.NetworkProfileID, nil }
	m.FreshProfile = a.FreshProfile
	resume, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(context.Background(), resume, nil); err != nil {
		t.Fatal("fresh resume failed", err)
	}
	if len(f.rules) != 2 || a.live == nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" || a.DNS.VerifyServiceSelection("web", "private") != nil {
		t.Fatal("resume applied pending profile")
	}
	if _, err := m.SuspendedDNS(saved); err == nil {
		t.Fatal("old stopped snapshot can replay after resume")
	}
}

func TestScopedDNSDiscardStoppedBindingWithoutStartingIt(t *testing.T) {
	for _, failCommit := range []bool{false, true} {
		t.Run(fmt.Sprint(failCommit), func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			in.Revision++
			in.DNS = nil
			in.Routes = nil
			in.SuspendDNS = true
			in.RetiringAdapters = []string{a.ID()}
			stop, _ := Build(in)
			if _, err := m.Apply(context.Background(), stop, nil); err != nil {
				t.Fatal(err)
			}
			saved, _, _ := m.Committed()
			if err := a.DNS.SetServiceDraft("web", "unfiltered"); err != nil {
				t.Fatal(err)
			}
			in.Revision++
			in.SuspendDNS = false
			in.DiscardDNS = true
			remove, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			var commit func() (func() error, error)
			if failCommit {
				commit = func() (func() error, error) { return nil, errors.New("injected removal failure") }
			}
			e, err := m.Apply(context.Background(), remove, commit)
			if len(f.rules) != 0 || a.live != nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
				t.Fatal("discard activated runtime or consumed draft")
			}
			if failCommit {
				if err == nil || !e.RollbackVerified || a.DNS.VerifyServiceSelection("web", "private") != nil {
					t.Fatal("failed removal lost saved choice", err)
				}
				if _, err := m.SuspendedDNS(saved); err != nil {
					t.Fatal("failed removal lost resumable snapshot", err)
				}
				return
			}
			if err != nil || a.DNS.VerifyServiceSelection("web", "") != nil {
				t.Fatal("discard failed", err)
			}
			if _, err := m.SuspendedDNS(saved); err == nil {
				t.Fatal("removed DNS can be replayed")
			}
			in.Revision++
			in.DiscardDNS = false
			in.RetiringAdapters = nil
			next, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Apply(context.Background(), next, nil); err != nil {
				t.Fatal("removed DNS still blocks later plans", err)
			}
		})
	}
}

func TestScopedDNSStopAfterRecoveryCleanupKeepsResumeAndRollbackIntent(t *testing.T) {
	for _, action := range []string{"stop-resume", "remove", "failed-stop"} {
		t.Run(action, func(t *testing.T) {
			m, a, f, in := scopedAdapterFixture(t)
			p, _ := Build(in)
			if _, err := m.Apply(context.Background(), p, nil); err != nil {
				t.Fatal(err)
			}
			old, _, _ := m.Committed()
			if err := m.PrepareDNSRecovery(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			if err := a.DNS.SetServiceDraft("web", "unfiltered"); err != nil {
				t.Fatal(err)
			}
			routes := in.Routes
			in.Revision++
			in.DNS = nil
			in.Routes = nil
			in.SuspendDNS = action != "remove"
			in.RetiringAdapters = []string{a.ID()}
			stop, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			var commit func() (func() error, error)
			if action == "failed-stop" {
				commit = func() (func() error, error) { return nil, errors.New("injected settings failure") }
			}
			e, err := m.Apply(context.Background(), stop, commit)
			if len(f.rules) != 0 || a.live != nil {
				t.Fatal("stop resurrected dead listener")
			}
			if action == "failed-stop" {
				if err == nil || e.State != "rolled-back" || !e.RollbackVerified || a.DNS.VerifyServiceSelection("web", "private") != nil {
					t.Fatal("failed Stop lost saved profile", err, e)
				}
				return
			}
			if err != nil {
				t.Fatal("Stop refused after recovery cleanup", err)
			}
			if action == "remove" {
				if a.DNS.VerifyServiceSelection("web", "") != nil {
					t.Fatal("removal left applied choice")
				}
				return
			}
			saved, _, _ := m.Committed()
			spec, err := m.SuspendedDNS(saved)
			if err != nil {
				t.Fatal(err)
			}
			in.Revision++
			in.DNS = spec
			in.Routes = routes
			in.SuspendDNS = false
			in.RetiringAdapters = nil
			resume, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Apply(context.Background(), resume, nil); err != nil {
				t.Fatal("resume after inactive Stop", err)
			}
			if len(f.rules) != 2 || a.live == nil || a.DNS.Snapshot().ServiceDrafts["web"] != "unfiltered" {
				t.Fatal("resume lost runtime or draft")
			}
		})
	}
}

func TestScopedDNSSuspensionRejectsMissingSnapshotAndInvalidScope(t *testing.T) {
	m, a, _, in := scopedAdapterFixture(t)
	in.SuspendDNS = true
	if _, err := Build(in); err == nil {
		t.Fatal("suspended active traffic accepted")
	}
	in.SuspendDNS = false
	p, _ := Build(in)
	if _, err := m.Apply(context.Background(), p, nil); err != nil {
		t.Fatal(err)
	}
	in.Revision++
	in.DNS = nil
	in.Routes = nil
	in.SuspendDNS = true
	in.RetiringAdapters = []string{a.ID()}
	stop, _ := Build(in)
	if _, err := m.Apply(context.Background(), stop, nil); err != nil {
		t.Fatal(err)
	}
	saved, _, _ := m.Committed()
	path := filepath.Join(m.StateRoot, "transactions", saved.PlanID, a.ID(), "snapshot.json")
	if err := os.WriteFile(path, []byte(`{"state":null,"active":false,"settings":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SuspendedDNS(saved); err == nil {
		t.Fatal("missing scope synthesized on resume")
	}
}
