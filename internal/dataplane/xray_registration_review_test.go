package dataplane

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Actual registry with explicit process-free adapter model; no readiness.
func TestXrayRegistrationReviewRetainsOriginalAndRefusesReplacementCopyOrRevival(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m := New(t.TempDir())
	a := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: filepath.Join(m.StateRoot, "runtime", "xray")}
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	r, err := m.ReviewXrayRegistration(ctx, a)
	if err != nil || r.Current(ctx) != nil {
		t.Fatal("actual registry identity unavailable", err)
	}
	foreign := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: a.StateRoot}
	if copied, err := m.ReviewXrayRegistration(ctx, foreign); copied != nil || err == nil {
		t.Fatal("matching metadata replaced actual registered pointer")
	}
	var copied XrayRegistrationReview
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(r).Elem())
	if copied.Current(ctx) == nil || copied.Close() == nil || r.closed {
		t.Fatal("copied reader acted on original")
	}
	root := a.StateRoot
	a.StateRoot += "-changed"
	if r.Current(ctx) == nil {
		t.Fatal("changed registered adapter root accepted")
	}
	a.StateRoot = root
	if r.Current(ctx) == nil {
		t.Fatal("restoration revived invalid reader")
	}
	r, err = m.ReviewXrayRegistration(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(&fakeAdapter{id: "another"}); err != nil {
		t.Fatal(err)
	}
	if r.Current(ctx) == nil {
		t.Fatal("changed registry generation accepted")
	}
	if r.Close() != nil || r.Close() != nil || r.Current(ctx) == nil {
		t.Fatal("closed reader revived")
	}
}

func TestXrayRegistrationReviewRequiresFreshFiniteContextButNoConstructionLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	m := New(t.TempDir())
	a := &ProxyTunnelAdapter{EngineID: "xray", StateRoot: filepath.Join(m.StateRoot, "runtime", "xray")}
	if m.Register(a) != nil {
		t.Fatal("register")
	}
	r, err := m.ReviewXrayRegistration(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	fresh, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if r.Current(fresh) != nil {
		t.Fatal("read-only registry reader retained construction operation")
	}
	for _, supplied := range []context.Context{nil, context.Background(), ctx} {
		if r.Current(supplied) == nil {
			t.Fatal("unbounded/cancelled read accepted")
		}
		if owner, err := m.ReviewXrayRegistration(supplied, a); owner != nil || err == nil {
			t.Fatal("unbounded/cancelled construction accepted")
		}
	}
}
