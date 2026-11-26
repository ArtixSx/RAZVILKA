package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Actual original atomic journal writers and their retained descriptors.
// The private pair is a protocol model only: no process, listener, physics,
// native check, COMMON or execution admission is supplied by these fixtures.
func replacementRecordsFixture(t *testing.T) (*xraySelectedTCPReplacement, context.Context) {
	t.Helper()
	m := &Manager{StateRoot: filepath.Join(t.TempDir(), "manager")}
	makeScope := func(letter string) *executionResourceScope {
		plan := Plan{PlanID: "dp-" + strings.Repeat(letter, 16), Digest: strings.Repeat(letter, 64)}
		root := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		return &executionResourceScope{manager: m, managerRoot: m.StateRoot, root: root, plan: plan,
			execution: &Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "planned"}}
	}
	a, c := makeScope("a"), makeScope("c")
	d, err := newXraySelectedTCPRecords(a)
	if err != nil {
		t.Fatal(err)
	}
	r := &XraySelectedTCPExecutionResource{scope: a, records: d}
	r.self = r
	a.xraySelectedTCP = map[string]*XraySelectedTCPExecutionResource{"original-A": r}
	if err := m.writeExecutionOwned(a.root, *a.execution, a); err != nil {
		t.Fatal(err)
	}
	e := &xraySelectedTCPExecution{plan: c.plan}
	e.self = e
	p := &xraySelectedTCPReplacement{manager: m, prior: &retainedXrayExecution{scope: a, records: d}, candidate: e}
	p.self = p
	m.replacementXray = p
	d.replacement.Store(p)
	if err := p.attachScope(c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.close(); _ = p.records.close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return p, ctx
}

func TestXraySelectedTCPReplacementAuthoredLatestHandoverPreservesOriginalA(t *testing.T) {
	for _, change := range []string{"unchanged", "candidate-latest-ABA", "candidate-transaction-ABA", "original-held-A-content", "copied-pair", "unissued-pair", "closed-pair"} {
		t.Run(change, func(t *testing.T) {
			p, ctx := replacementRecordsFixture(t)
			a := p.prior.records
			mutator, err := a.root.OpenFile("latest-execution.json", os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer mutator.Close()
			originalLatest, originalImage := a.files[1], append([]byte(nil), a.images[1]...)
			if err := p.manager.writeExecutionOwned(p.scope.root, *p.scope.execution, p.scope); err != nil {
				t.Fatal("actual C two-writer publication", err)
			}
			if !p.handedOver.Load() || a.files[1] != originalLatest || !reflect.DeepEqual(a.images[1], originalImage) {
				t.Fatal("C publication replaced or rewrote original A held writer")
			}
			if err := a.current(ctx, true); err != nil {
				t.Fatal("actual writer handover failed original A bookend", err)
			}
			switch change {
			case "candidate-latest-ABA", "candidate-transaction-ABA":
				root, name := p.records.recordPath(1)
				if change == "candidate-transaction-ABA" {
					root, name = p.records.recordPath(0)
				}
				data, err := root.ReadLimited(name, 16<<20)
				if err != nil || root.WriteAtomic(name, data, 0600) != nil {
					t.Fatal("fixture replacement", err)
				}
			case "original-held-A-content":
				if _, err := mutator.WriteAt([]byte("!"), 0); err != nil {
					t.Fatal(err)
				}
			case "copied-pair":
				copy := &xraySelectedTCPReplacement{self: p, manager: p.manager, prior: p.prior, candidate: p.candidate, scope: p.scope, records: p.records}
				copy.handedOver.Store(true)
				a.replacement.Store(copy)
			case "unissued-pair":
				unissued := &xraySelectedTCPReplacement{manager: p.manager, prior: p.prior, candidate: p.candidate, scope: p.scope, records: p.records}
				unissued.self = unissued
				unissued.handedOver.Store(true)
				a.replacement.Store(unissued)
			case "closed-pair":
				p.closed.Store(true)
			}
			if err := a.current(ctx, true); (err == nil) != (change == "unchanged") {
				t.Fatal("detached original A accepted unauthored C/changed original", change, err)
			}
			if change != "unchanged" && a.beforePublication() == nil {
				t.Fatal("next original writer adopted unknown handover")
			}
		})
	}
}

func TestXraySelectedTCPReplacementPriorRetirementWritesPrivateAliasWithoutTouchingC(t *testing.T) {
	p, ctx := replacementRecordsFixture(t)
	if err := p.manager.writeExecutionOwned(p.scope.root, *p.scope.execution, p.scope); err != nil {
		t.Fatal(err)
	}
	c := p.records
	latest, image := c.files[1], append([]byte(nil), c.images[1]...)
	p.prior.scope.execution.State = "rolled-back" // documentary model only
	if p.manager.writeExecutionOwned(p.prior.scope.root, *p.prior.scope.execution, p.prior.scope) == nil {
		t.Fatal("A retirement publication accepted before C committed")
	}
	p.committed.Store(true)
	if err := p.manager.writeExecutionOwned(p.prior.scope.root, *p.prior.scope.execution, p.prior.scope); err != nil {
		t.Fatal(err)
	}
	if !p.priorAlias.Load() || c.files[1] != latest || !reflect.DeepEqual(c.images[1], image) || c.current(ctx, true) != nil || p.prior.records.current(ctx, true) != nil {
		t.Fatal("A terminal writer damaged C or lost either original A ACK")
	}
	if p.publishPriorLatest() == nil {
		t.Fatal("postcommit A retirement regained restoration lane")
	}
}

func TestXraySelectedTCPReplacementOriginalRestoreWriterAndPartialACK(t *testing.T) {
	t.Run("restore-original", func(t *testing.T) {
		p, ctx := replacementRecordsFixture(t)
		if err := p.manager.writeExecutionOwned(p.scope.root, *p.scope.execution, p.scope); err != nil {
			t.Fatal(err)
		}
		if err := p.publishPriorLatest(); err != nil {
			t.Fatal(err)
		}
		if p.handedOver.Load() || p.prior.records.current(ctx, true) != nil {
			t.Fatal("actual A restore writer not independently acknowledged")
		}
		data, err := os.ReadFile(filepath.Join(p.manager.StateRoot, "latest-execution.json"))
		var restored Execution
		if err != nil || json.Unmarshal(data, &restored) != nil || !reflect.DeepEqual(restored, *p.prior.scope.execution) {
			t.Fatal("restore is not original complete A execution", err)
		}
	})
	for _, index := range []int{0, 1} {
		t.Run([]string{"first-ACK-fails", "second-ACK-fails"}[index], func(t *testing.T) {
			p, ctx := replacementRecordsFixture(t)
			data, err := json.Marshal(p.scope.execution)
			if err != nil {
				t.Fatal(err)
			}
			if index == 1 {
				if err := p.publishWriter(p.scope, p.records, data, 0); err != nil {
					t.Fatal("actual original first writer", err)
				}
			}
			path := filepath.Join(p.scope.root, "execution.json")
			if index == 1 {
				path = filepath.Join(p.manager.StateRoot, "latest-execution.json")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if p.publishWriter(p.scope, p.records, data, index) == nil {
				t.Fatal("actual failed publication reported both ACKs")
			}
			if p.records.current(ctx, true) == nil {
				t.Fatal("partial publication became complete owner")
			}
			if index == 1 && (p.records.files[0] == nil || p.records.files[1] != nil || p.handedOver.Load()) {
				t.Fatal("lost actual first ACK or invented second ACK")
			}
		})
	}
}

func TestXraySelectedTCPReplacementIntentIsSingleServiceAndExactNegativeScope(t *testing.T) {
	a := xraySelectedTCPFixtureSpec(t, "node-"+strings.Repeat("1", 64))
	c := a.Clone()
	c.NodeID, c.Generation, c.Listener = "node-"+strings.Repeat("2", 64), strings.Repeat("c", 64), netip.MustParseAddrPort("192.168.1.1:16444")
	c.LAN.Generation, c.LAN.Digest = c.Generation, ""
	c.LAN.Digest = lanPolicyDigest(c.LAN)
	if !xraySelectedTCPSameReplacementIntent(a, c) {
		t.Fatal("valid exact A/C comparison refused")
	}
	mutations := map[string]func(*XraySelectedTCPRedirectSpec){
		"service":              func(s *XraySelectedTCPRedirectSpec) { s.ServiceID = "other" },
		"listener-address":     func(s *XraySelectedTCPRedirectSpec) { s.Listener = netip.MustParseAddrPort("192.168.1.2:16444") },
		"listener-port":        func(s *XraySelectedTCPRedirectSpec) { s.Listener = netip.MustParseAddrPort("192.168.1.1:16445") },
		"destination":          func(s *XraySelectedTCPRedirectSpec) { s.Destinations[0] = "8.8.8.0/24" },
		"negative-destination": func(s *XraySelectedTCPRedirectSpec) { s.ExcludedDestinations = nil },
		"negative-source":      func(s *XraySelectedTCPRedirectSpec) { s.LAN.Ingress[0].ExcludedSources = nil },
		"negative-MAC":         func(s *XraySelectedTCPRedirectSpec) { s.LAN.Ingress[0].ExcludedMACs = nil },
		"source":               func(s *XraySelectedTCPRedirectSpec) { s.LAN.Ingress[0].Sources[0] = "192.168.1.40/32" },
		"port":                 func(s *XraySelectedTCPRedirectSpec) { s.Ports[0].First = 80 },
		"invalid-schema":       func(s *XraySelectedTCPRedirectSpec) { s.Schema = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			next := c.Clone()
			mutate(&next)
			next.LAN.Digest = lanPolicyDigest(next.LAN)
			if xraySelectedTCPSameReplacementIntent(a, next) {
				t.Fatal("changed intent entered replacement")
			}
		})
	}
}

func TestXraySelectedTCPReplacementUnenteredCancellationRetainsOnlyOriginalPair(t *testing.T) {
	m := &Manager{StateRoot: t.TempDir()}
	m.operationGate = make(chan struct{}, 1)
	m.operationGate <- struct{}{} // A competing Manager operation is still live.
	e := &xraySelectedTCPExecution{plan: Plan{PlanID: "dp-" + strings.Repeat("c", 16)}}
	e.self = e
	p := &xraySelectedTCPReplacement{manager: m, prior: &retainedXrayExecution{}, candidate: e}
	p.self = p
	m.replacementXray = p
	base := context.WithValue(context.WithValue(context.Background(), xraySelectedTCPReplacementKey{}, p), xraySelectedTCPExecutionKey{}, e)
	ctx, cancel := context.WithCancel(base)
	cancel()
	result, err := m.Apply(ctx, e.plan, nil)
	if !errors.Is(err, context.Canceled) || result.State != "replacement-pending" || !p.pending.Load() {
		t.Fatal("cancelled entry lost original association", result.State, err)
	}
	if m.pendingUnenteredXrayReplacement(context.Background(), e.plan) {
		t.Fatal("raw context retained foreign pair")
	}
	copy := &xraySelectedTCPReplacement{self: p, manager: m, prior: p.prior, candidate: e}
	if m.pendingUnenteredXrayReplacement(context.WithValue(base, xraySelectedTCPReplacementKey{}, copy), e.plan) {
		t.Fatal("copied pair regained association")
	}

	// A free select may accept its channel even with an already cancelled
	// context. The subsequent finite-context refusal must retain the same
	// association too; neither scheduler outcome may lose original cleanup.
	for range 16 {
		m.operationGate = make(chan struct{}, 1)
		p.pending.Store(false)
		result, err := m.Apply(ctx, e.plan, nil)
		if err == nil || result.State != "replacement-pending" || !p.pending.Load() {
			t.Fatal("cancelled free entry lost original association", result.State, err)
		}
	}
}
