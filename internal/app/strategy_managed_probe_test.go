package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestManagedStrategyProbeScopeUsesOnlyExactPublicHTTPSIPv4(t *testing.T) {
	for _, tc := range []struct {
		url, family string
		pass        bool
	}{
		{"https://8.8.8.8/", "ipv4", true},
		{"https://8.8.8.8/", "", true},
		{"https://8.8.8.8/", "ipv6", false},
		{"http://8.8.8.8/", "ipv4", false},
		{"https://8.8.8.8:8443/", "ipv4", false},
		{"https://127.0.0.1/", "ipv4", false},
		{"https://192.168.1.1/", "ipv4", false},
		{"https://user@8.8.8.8/", "ipv4", false},
		{"https://8.8.8.8/#fragment", "ipv4", false},
	} {
		scope, err := managedStrategyProbeScope(context.Background(), catalog.Service{ID: "service", ProbeURL: tc.url}, tc.family)
		if (err == nil) != tc.pass {
			t.Fatal(tc, err)
		}
		if err == nil && (scope.Address.String() != "8.8.8.8" || scope.Target.Protocol != "tcp" || scope.Target.IPFamily != "ipv4" || scope.CriteriaDigest == "") {
			t.Fatal(scope)
		}
	}
}

func TestManagedStrategyProbeClosingErrorCannotPublishEarlierPass(t *testing.T) {
	e := strategylab.Evidence{CandidateID: "candidate", Success: true, RouteConfirmed: true, Stages: []strategylab.StageEvidence{{Stage: "http", Status: "pass"}}}
	for _, err := range []error{context.Canceled, dataplane.ErrNFQWSManagedProcessUnknown, errors.New("original closing read failed")} {
		if managedStrategyProbeObservation("candidate", e, err) != nil {
			t.Fatal("known cleanup waived closing exception", err)
		}
	}
	if managedStrategyProbeObservation("candidate", e, nil) == nil {
		t.Fatal("unexceptional original observation discarded")
	}
	e.Success = false
	if managedStrategyProbeObservation("candidate", e, nil) == nil {
		t.Fatal("known negative observation discarded")
	}
}

func TestManagedStrategyProbeCannotBorrowLegacyExecutorOrUnboundRuntime(t *testing.T) {
	a := &App{Components: &components.Manager{}}
	w := httptest.NewRecorder()
	a.probeManagedStrategyCandidate(w, context.Background(), "candidate", catalog.Service{ID: "service", ProbeURL: "https://8.8.8.8/"}, "ipv4")
	if w.Code != http.StatusConflict || a.managedStrategyProbePending() {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestManagedStrategyProbeShutdownWaitsForOriginalAttemptAndRetainsUnknown(t *testing.T) {
	a := &App{}
	released := 0
	held := &strategyProbeRetention{done: make(chan struct{}), release: func() { released++ }, entered: true}
	a.strategyProbe.held = held
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(a.WaitManagedStrategyProbes(ctx), context.Canceled) || released != 0 || !a.managedStrategyProbePending() {
		t.Fatal("cancellation released original operation")
	}
	close(held.done)
	if !errors.Is(a.WaitManagedStrategyProbes(context.Background()), dataplane.ErrNFQWSManagedProcessUnknown) || released != 0 || !a.managedStrategyProbePending() {
		t.Fatal("unknown borrowed a replacement completion")
	}
	held.entered = false // Explicit pre-effect fixture; no native owner is claimed.
	if err := a.WaitManagedStrategyProbes(context.Background()); err != nil || released != 1 || a.managedStrategyProbePending() {
		t.Fatal(released, err)
	}
	if err := a.WaitManagedStrategyProbes(context.Background()); err != nil || released != 1 {
		t.Fatal("released twice", released, err)
	}
}
