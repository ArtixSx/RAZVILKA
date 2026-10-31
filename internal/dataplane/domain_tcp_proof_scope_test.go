package dataplane

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func domainTCPProofPlanModel(t *testing.T) Plan {
	t.Helper()
	transport, domain := syntheticTransportModelFixture(t)
	r := Route{ServiceID: "service", LogicalServiceID: "service", Selected: "xray:one", Resolved: "xray:one", Domains: []string{"service.example.com"}, Sources: []string{transport.Definition.Client.String() + "/32"}, Ingress: []string{transport.Definition.Ingress}}
	p, err := BuildAt(Input{Revision: 1, DomainPolicy: domain, SyntheticDNS: transport, NetworkProfileID: executionNetwork, Routes: []Route{r}, Engines: []Engine{{ID: "xray", Installed: true, Configured: true, Activatable: true}}, Host: HostState{IPCommand: true, IPTables: true, IP6Tables: true}}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDomainTCPProofPlanKeepsRealBlockersWithoutUnusedTUN(t *testing.T) {
	p := domainTCPProofPlanModel(t)
	if err := validateDomainTCPProofPlan(p); err != nil {
		t.Fatalf("exact blocked proof intent rejected: %v %+v", err, p.Blockers)
	}
	if p.Ready || p.Host.TUN || p.Host.SingBox || len(p.Blockers) != 2 {
		t.Fatal("proof intent fabricated capability", p.Ready, p.Host, p.Blockers)
	}
	for _, b := range p.Blockers {
		if b.Code == "TUN_MISSING" || b.Code == "TUN_SIDECAR_MISSING" {
			t.Fatal("unused sidecar blocks direct accepted TCP proof")
		}
	}
	if validateDomainTransportForExecution(p) == nil {
		t.Fatal("ordinary Apply gained authority")
	}
	for _, change := range []string{"ready", "missing-blocker", "extra-blocker", "duplicate-blocker", "broad-source", "extra-name", "other-adapter", "conflict", "retirement"} {
		t.Run(change, func(t *testing.T) {
			q := cloneExecutionResourcePlan(p)
			switch change {
			case "ready":
				q.Ready = true
			case "missing-blocker":
				q.Blockers = q.Blockers[:1]
			case "extra-blocker":
				q.Blockers = append(q.Blockers, Blocker{Code: "SAFE_MODE"})
			case "duplicate-blocker":
				q.Blockers[1] = q.Blockers[0]
			case "broad-source":
				q.Routes[0].Sources = []string{"192.168.1.0/24"}
			case "extra-name":
				q.Routes[0].Domains = append(q.Routes[0].Domains, "other.example.com")
			case "other-adapter":
				q.Adapters = append(q.Adapters, "sing-box")
			case "conflict":
				q.ResourceConflicts = append(q.ResourceConflicts, ResourceConflict{Kind: "table", Value: "31000"})
			case "retirement":
				q.RetiringAdapters = []string{"xray"}
			}
			if validateDomainTCPProofPlan(q) == nil {
				t.Fatal("nonexact proof accepted", change)
			}
		})
	}
	// The generic tunnel route remains subject to its original TUN checks.
	d := cloneExecutionResourcePlan(p)
	d.Routes[0].Sources = []string{"192.168.1.0/24"}
	input := Input{Revision: 1, DomainPolicy: d.DomainPolicy, SyntheticDNS: d.SyntheticDNS, NetworkProfileID: p.NetworkProfileID, Routes: d.Routes, Engines: []Engine{{ID: "xray", Installed: true, Configured: true, Activatable: true}}, Host: p.Host}
	other, err := BuildAt(input, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, b := range other.Blockers {
		codes = append(codes, b.Code)
	}
	if !slices.Contains(codes, "TUN_MISSING") || !slices.Contains(codes, "TUN_SIDECAR_MISSING") {
		t.Fatal("generic preflight weakened", codes)
	}
}

func TestDomainTCPProofNoHistoryRefusesBeforeAnyNewJournal(t *testing.T) {
	p := domainTCPProofPlanModel(t)
	m := New(filepath.Join(t.TempDir(), "dataplane"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	called := false
	if err := m.WithDomainTCPProofResources(ctx, p, nil, func(context.Context) error { called = true; return nil }); err == nil || called {
		t.Fatal("missing actual reader3 fleet owner admitted scope")
	}
	if matches, err := filepath.Glob(filepath.Join(m.StateRoot, "transactions", "*")); err != nil || len(matches) != 0 {
		t.Fatal("refusal created a journal", matches, err)
	}
}
