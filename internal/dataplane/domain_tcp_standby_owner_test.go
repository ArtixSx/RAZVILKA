package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDomainTCPStandbyCannotBeIssuedFromMetadataOrCopiedOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, original := range []*DomainTCPOriginalScope{nil, {}, {standbyReady: true, closed: true}} {
		if original != nil {
			original.self = original
		}
		if err := original.standbyCurrent(ctx); err == nil {
			t.Fatal("missing original native/COMMON owner admitted")
		}
		if err := original.RetainStandby(ctx, nil); err == nil {
			t.Fatal("missing original fleet owner admitted")
		}
	}
	original := &DomainTCPOriginalScope{}
	original.self = original
	copy := DomainTCPOriginalScope{self: original}
	if err := copy.standbyCurrent(ctx); err == nil {
		t.Fatal("copied original owner admitted")
	}
	owner := &domainTCPStandbyOwner{original: original}
	owner.self = owner
	if err := owner.current(); err == nil {
		t.Fatal("retained status without actual handoff")
	}
}

// Real original journal writers/FD handoff, isolated from native authority.
// This protocol fixture intentionally issues no original standby owner.
func TestDomainTCPStandbyAliasRetainsOriginalGlobalWriter(t *testing.T) {
	root := t.TempDir()
	transaction := filepath.Join(root, "transactions", "dp-aaaaaaaaaaaaaaaa")
	if err := os.MkdirAll(transaction, 0700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{StateRoot: root}
	s := &executionResourceScope{manager: m, managerRoot: root, root: transaction, execution: &Execution{PlanID: "dp-aaaaaaaaaaaaaaaa", Digest: strings.Repeat("a", 64), State: "planned"}}
	var err error
	s.owned, s.anchor, err = openNetworkPolicyObservationRoot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	defer s.owned.Close()
	d := &xraySelectedTCPExecutionRecords{scope: s}
	d.root, d.anchor, err = openNetworkPolicyObservationRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	d.transactionRoot, d.transactionAnchor, err = openNetworkPolicyObservationRoot(transaction)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	p := &XrayDomainTCPExecutionResource{scope: s, records: d}
	p.self = p
	s.xrayDomainTCP = map[string]*XrayDomainTCPExecutionResource{"original": p}
	if err := m.writeExecutionOwned(transaction, *s.execution, s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owner := &domainTCPStandbyOwner{process: p}
	owner.self = owner
	if err := d.detachStandbyAlias(ctx, owner); err != nil {
		t.Fatal(err)
	}
	defer owner.latest.Close()
	before, err := owner.latest.Stat()
	if err != nil || !os.SameFile(before, owner.latestInfo) {
		t.Fatal("original global FD lost", err)
	}
	if err := d.root.WriteAtomic("latest-execution.json", []byte(`{"foreign":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := d.root.Stat("latest-execution.json")
	if err != nil || os.SameFile(before, after) {
		t.Fatal("global original inode not pinned", err)
	}
	if err := d.current(ctx, true); err != nil {
		t.Fatal("new global writer revoked original alias", err)
	}
	raw, err := d.transactionRoot.ReadLimited("standby-execution.json", 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.transactionRoot.WriteAtomic("standby-execution.json", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.current(ctx, true); err == nil {
		t.Fatal("equal-byte foreign alias adopted")
	}
	if err := m.checkKnownDomainStandbyRecord(*s.execution); err == nil {
		t.Fatal("journal protocol fixture fabricated native standby owner")
	}
}

func TestDomainTCPStandbyPendingCloseRevokesForwardAndRetainsUnknown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := &executionResourceScope{ctx: ctx, cancel: cancel, open: true, retained: true}
	owner := &retainedXrayExecution{scope: scope, standby: &domainTCPStandbyOwner{}, pending: true}
	owner.self = owner
	scope.retainedXrayOwner = owner
	scope.observationOpen.Store(true)
	if err := scope.close(); !errors.Is(err, ErrPolicyAdditionUnknown) || ctx.Err() == nil || scope.observationOpen.Load() {
		t.Fatal("pending handoff retained forward permission or lost its fence", err)
	}
	if scope.retainedXrayOwner != owner || !scope.open || !owner.pending {
		t.Fatal("pending original custody discarded")
	}
}
