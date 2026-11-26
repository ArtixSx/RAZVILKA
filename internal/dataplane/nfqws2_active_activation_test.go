package dataplane

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestNFQWSPreparedIntentChecksExactTuplesWithoutNativeCommand(t *testing.T) {
	plan, spec := nfqwsScopedSelectedFixture(t) // Explicit immutable intent model.
	spec.SessionID, spec.CommandSHA256 = "", ""
	checked, err := validateNFQWSScopedIntent(plan, spec)
	if err != nil || checked.SessionID != "" || checked.CommandSHA256 != "" {
		t.Fatal("preparation requires or creates a native command", err)
	}
	if p, err := CompileNFQWSScopedPlan(plan, checked); p != nil || err == nil {
		t.Fatal("untimed intent compiled an executable scoped plan")
	}
	for _, kind := range []string{"lost-tuple", "port", "source", "private-destination", "ingress", "origin", "family"} {
		t.Run(kind, func(t *testing.T) {
			changed := checked.Clone()
			switch kind {
			case "lost-tuple":
				changed.Matches = changed.Matches[:1]
			case "port":
				changed.Matches[0].LastPort++
			case "source":
				changed.Matches[0].Source = netip.MustParsePrefix("192.168.2.0/24")
			case "private-destination":
				changed.Matches[0].Destination = netip.MustParsePrefix("10.0.0.1/32")
			case "ingress":
				changed.Matches[0].Ingress = "br9"
			case "origin":
				changed.Matches[0].Origin = "default"
			case "family":
				changed.Candidate.IPFamily = "ipv6"
			}
			if _, err := validateNFQWSScopedIntent(plan, changed); err == nil {
				t.Fatal("prepared tuple widened or detached")
			}
		})
	}
}

func TestNFQWSOriginalActivationDeadlineIsFifteenSecondsOrEarlierParent(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancel()
	deadline, err := nfqws2OriginalActivationDeadline(ctx, now)
	if err != nil || deadline != now.Add(15*time.Second).UTC() {
		t.Fatal("native deadline changed", deadline, err)
	}
	short, stop := context.WithDeadline(ctx, now.Add(2*time.Second))
	defer stop()
	deadline, err = nfqws2OriginalActivationDeadline(short, now)
	if err != nil || deadline != now.Add(2*time.Second).UTC() {
		t.Fatal("original parent bound lost", deadline, err)
	}
	stop()
	for _, supplied := range []context.Context{nil, context.Background(), short} {
		if deadline, err := nfqws2OriginalActivationDeadline(supplied, now); err == nil || !deadline.IsZero() {
			t.Fatal("unbounded or cancelled activation issued")
		}
	}
}

// Private seal identity model only. No source/physical/native permission or
// actual command/resource issuance can be obtained from this fixture.
func TestNFQWSActivationSealModelCannotCopyReuseRenewOrEscapeOriginalScope(t *testing.T) {
	command, spec, _ := nfqws2ActiveCommandFixture(t)
	material := &NFQWSActiveMaterial{command: command, intent: nfqws2ActiveIntentFromCommand(command)}
	material.self = material
	selection := &NFQWSScopedSelection{spec: spec}
	selection.self = selection
	e := &nfqws2ActiveExecution{material: material, selection: selection, spec: spec}
	e.self = e
	scope := &executionResourceScope{}
	seal := &nfqws2ActiveActivationSeal{execution: e, scope: scope, selection: selection, command: command.clone(), spec: spec.Clone()}
	seal.self, e.activationSeal = seal, seal
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := context.WithValue(parent, nfqws2ActiveActivationRegistrarKey{}, scope)
	var copied nfqws2ActiveActivationSeal
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(seal).Elem())
	if copied.consume(ctx, e) == nil || seal.consumed || seal.consume(parent, e) == nil || seal.consumed {
		t.Fatal("copy or escaped context consumed original seal")
	}
	if err := seal.consume(ctx, e); err != nil || !seal.consumed || seal.consume(ctx, e) == nil {
		t.Fatal("original seal was not one-use", err)
	}
	expiry := material.command.ActivationDeadline
	material.command.ActivationDeadline = expiry.Add(time.Second)
	if seal.current(e) == nil {
		t.Fatal("command deadline renewal retained original seal")
	}
	material.command.ActivationDeadline = expiry
	if err := seal.current(e); err != nil {
		t.Fatal("original consumed seal lost immutable identity", err)
	}
	if _, err := e.issueOriginalActivation(ctx); err == nil || e.resource != nil {
		t.Fatal("seal model reconstructed original native issuer")
	}
}
