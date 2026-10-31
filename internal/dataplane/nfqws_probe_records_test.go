package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Original COMMON/receipt/kernel model, never a native process or source grant.
func retainedNFQWSProbeScopeFixture(t *testing.T) (*executionNFQWSFixture, *nfqwsProbeExecution) {
	t.Helper()
	f := executionNFQWSManagerFixture(t)
	e := &nfqwsProbeExecution{}
	e.self = e
	e.open.Store(true)
	ctx := context.WithValue(f.ctx, nfqwsProbeExecutionKey{}, e)
	err := f.m.WithExecutionResources(ctx, f.p, "nfqws2", func(c context.Context) error {
		c = f.bind(t, c)
		e.resource = f.r
		var err error
		e.records, err = newNFQWSProbeRecords(f.r.scope)
		if err != nil {
			return err
		}
		if err := f.r.scope.persist(); err != nil {
			return err
		}
		f.start(t, c)
		if err := f.r.Prepared(c, f.r.Binding()); err != nil {
			return err
		}
		if err := f.b.Apply(c, f.r.Plan(), f.r.Root()); err != nil {
			return err
		}
		return errors.New("modeled action failure; original known cleanup retained")
	})
	if err == nil || f.r == nil || !f.r.scope.open || !f.r.scope.pending || !f.r.scope.observationOpen.Load() {
		t.Fatal("original pending scope was closed", err)
	}
	t.Cleanup(func() { e.finishing.Store(true); _ = f.r.scope.close(); _ = e.records.close() })
	return f, e
}

func TestNFQWSProbePendingScopeRetainsOriginalCleanupAndAuthoredRecords(t *testing.T) {
	f, e := retainedNFQWSProbeScopeFixture(t)
	bounded, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	ctx := f.r.scope.contextWith(bounded)
	effects, _ := f.r.Plan().Effects()
	if f.r.Current(ctx, f.r.Binding()) == nil || f.r.ApplyGuard(ctx, f.r.Plan(), effects.Effects[0]) == nil {
		t.Fatal("retained scope resumed forward effects")
	}
	f.model.running, f.model.stopped = false, true
	if err := f.b.Remove(ctx, f.r.Plan(), f.r.Root()); err != nil {
		t.Fatal("original receipt cleanup could not retry", err)
	}
	if err := f.r.SettleRemoved(ctx); err != nil {
		t.Fatal("original COMMON could not settle", err)
	}
	if err := e.records.current(ctx, true); err != nil {
		t.Fatal("retry lost actual authored records", err)
	}
	e.finishing.Store(true)
	if err := f.r.scope.close(); err != nil {
		t.Fatal(err)
	}
	if f.r.scope.open || f.r.Current(ctx, f.r.Binding()) == nil {
		t.Fatal("terminal scope retained borrower")
	}
}

func TestNFQWSProbeRetryRefusesReplacedOriginalRecordAndRoot(t *testing.T) {
	for _, kind := range []string{"record", "root"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "root" && runtime.GOOS != "linux" {
				t.Skip("Linux descriptor rename semantics")
			}
			f, e := retainedNFQWSProbeScopeFixture(t)
			foreign := []byte("independently replaced journal\n")
			path := filepath.Join(f.m.StateRoot, "latest-execution.json")
			if kind == "root" {
				root := f.r.scope.root
				if err := os.Rename(root, root+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(root, "execution.json")
			}
			if err := os.WriteFile(path, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			if err := f.r.scope.persist(); err == nil {
				t.Fatal("retry adopted replaced original record/root")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(foreign) {
				t.Fatal("foreign journal overwritten", err)
			}
			if !f.r.scope.open || !e.open.Load() {
				t.Fatal("failed publication dropped original cleanup owner")
			}
		})
	}
}
