package app

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// This exercises actual Store CAS, consent/control/scope/source owners and the
// registered factory. The shared fixture explicitly models physical/WAN/HTTP
// and recorded node health. No Apply, process or native traffic is exercised.
func xrayAssemblySourceCAS(t *testing.T, r *XrayListRuntimeSource) (func() error, time.Time, time.Time) {
	t.Helper()
	before := r.store.Get()
	started := time.Now()
	undo, err := r.store.CommitNetworkPolicyWithRollback(before, before.NetworkPolicy, before.Services)
	finished := time.Now()
	if err != nil {
		t.Fatal("actual policy CAS", err)
	}
	return undo, started, finished
}

func TestListXrayAssemblySourceAcceptsOnlyOriginalCommit(t *testing.T) {
	for _, failedRefresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "unchanged-LKG"}[failedRefresh], func(t *testing.T) {
			f := newListXraySourceFixture(t, "xray")
			listScopeOperation(t, f.a, func(ctx context.Context) {
				r := f.review(t, ctx)
				original, err := r.Observation(ctx)
				if err != nil {
					t.Fatal(err)
				}
				cache := filepath.Join(f.cache, "reviewed-networks.cache.json")
				bytes, err := os.ReadFile(cache)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(cache)
				if err != nil {
					t.Fatal(err)
				}
				if failedRefresh {
					f.a.Sources.SetHTTPClient(&http.Client{Transport: listXraySourceRejectedTransport{unavailable: true}})
					if err := f.a.Sources.Refresh(ctx, "reviewed-networks"); err == nil {
						t.Fatal("fixture refresh did not fail")
					}
				}
				before := f.a.Store.Get()
				_, started, finished := xrayAssemblySourceCAS(t, r)
				if err := r.acceptCommitted(ctx, started, finished); err != nil {
					t.Fatal("original CAS refused", err)
				}
				after := f.a.Store.Get()
				if after.Revision != before.Revision+1 || !reflect.DeepEqual(r.expected, after) || !reflect.DeepEqual(f.scope.expected, after) ||
					!defaultRouteCommittedConfig(before, after, before.NetworkPolicy, before.Services, started, finished) {
					t.Fatal("source/scope did not advance to exact sanctioned image")
				}
				observation, err := r.Observation(ctx)
				if err != nil || !reflect.DeepEqual(observation, original) {
					t.Fatal("CAS renewed or changed source/node/probe/WAN evidence", err)
				}
				if _, err := f.scope.Observe(ctx); err != nil {
					t.Fatal("original scope did not retain current consent", err)
				}
				current, err := os.ReadFile(cache)
				if err != nil || string(current) != string(bytes) {
					t.Fatal("commit changed accepted source bytes", err)
				}
				currentInfo, err := os.Stat(cache)
				if err != nil || !os.SameFile(info, currentInfo) || f.physical.closes != 0 {
					t.Fatal("commit replaced original source or retired physical owner", err)
				}
				if err := r.acceptCommitted(ctx, started, finished); err == nil {
					t.Fatal("same postimage was accepted twice")
				}
				if err := r.Current(ctx); err == nil {
					t.Fatal("refused replay revived source")
				}
			})
		})
	}
}

func TestListXrayAssemblySourceCommitRefusesChangedOwners(t *testing.T) {
	for _, change := range []string{"no-publication", "ordinary-edit", "bad-clock", "refresh", "node-generation", "predicate", "registry", "stop", "wan", "physical"} {
		t.Run(change, func(t *testing.T) {
			f := newListXraySourceFixture(t, "xray")
			listScopeOperation(t, f.a, func(ctx context.Context) {
				r := f.review(t, ctx)
				started, finished := time.Now(), time.Now()
				if change != "no-publication" && change != "ordinary-edit" {
					_, started, finished = xrayAssemblySourceCAS(t, r)
				}
				restore := func() {}
				switch change {
				case "ordinary-edit":
					if err := f.a.Store.UpdateService("listed", f.a.Store.Get().Services["listed"]); err != nil {
						t.Fatal(err)
					}
				case "bad-clock":
					started, finished = started.Add(time.Hour), finished.Add(time.Hour)
				case "refresh":
					if err := f.a.Sources.Refresh(ctx, "reviewed-networks"); err != nil {
						t.Fatal(err)
					}
				case "node-generation":
					f.record(t, "xray", "new-proof", time.Now().UTC())
				case "predicate":
					f.a.Catalog.Services[0].ProbeURL = "https://8.8.8.8/"
					restore = func() { f.a.Catalog.Services[0].ProbeURL = "https://1.1.1.1/" }
				case "registry":
					if err := f.a.Dataplane.Register(&dataplane.ProxyTunnelAdapter{EngineID: "sing-box", StateRoot: f.a.Dataplane.StateRoot}); err != nil {
						t.Fatal(err)
					}
				case "stop":
					if _, err := operationgate.RequestSelfUpdateStop(ctx, f.a.SelfUpdateFiles.ControlRoot, strings.Repeat("a", 32), 1); err != nil {
						t.Fatal(err)
					}
				case "wan":
					f.physical.network = "wan-fedcba987654"
					restore = func() { f.physical.network = "wan-0123456789ab" }
				case "physical":
					f.physical.verifyErr = errors.New("fixture incarnation changed")
					restore = func() { f.physical.verifyErr = nil }
				}
				image := f.a.Store.Get()
				if err := r.acceptCommitted(ctx, started, finished); err == nil {
					t.Fatal("changed owner or non-CAS image accepted")
				}
				if !reflect.DeepEqual(f.a.Store.Get(), image) {
					t.Fatal("source transition performed a Store write")
				}
				restore()
				if err := r.acceptCommitted(ctx, started, finished); err == nil {
					t.Fatal("restored tuple revived refused source")
				}
			})
		})
	}
}

func TestListXrayAssemblySourceCommitCannotBorrowNewOperation(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx, release, err := f.a.Operations.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	r := f.review(t, ctx)
	release()
	fresh, freshRelease, err := f.a.Operations.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer freshRelease()
	_, started, finished := xrayAssemblySourceCAS(t, r)
	if err := r.acceptCommitted(fresh, started, finished); err == nil {
		t.Fatal("new operation revived the released original source")
	}
}

func TestListXrayAssemblySourceRollbackCannotRenewEvidence(t *testing.T) {
	f := newListXraySourceFixture(t, "xray")
	listScopeOperation(t, f.a, func(ctx context.Context) {
		r := f.review(t, ctx)
		before := f.a.Store.Get()
		undo, started, finished := xrayAssemblySourceCAS(t, r)
		if err := r.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		if err := undo(); err != nil || !reflect.DeepEqual(f.a.Store.Get(), before) {
			t.Fatal("actual CAS compensation did not restore preimage", err)
		}
		if err := r.Current(ctx); err == nil {
			t.Fatal("restored preimage revived post-commit source")
		}
		if err := r.cidrs.Current(ctx); err != nil {
			t.Fatal("config compensation poisoned unchanged source cache", err)
		}
	})
}
