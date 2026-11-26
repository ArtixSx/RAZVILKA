package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Actual files, modeled static associations only. This deliberately cannot
// pass the original live witness/manager producer and cannot issue a Current.
func domainSuccessorReadModel(t *testing.T, use func(*domainTCPSuccessorRead, *XrayDomainTCPExecutionResource) error) error {
	t.Helper()
	process, ctx := domainFileObservationModel(t)
	return domainPreAddFileLoan(t, ctx, process, func(root context.Context, baseline *syntheticBaselineExecutionResource, loan *domainTCPPreAddLoan) error {
		manager := &Manager{}
		scope := &executionResourceScope{manager: manager}
		process.scope = scope
		binding := &SyntheticDNSExecutionBinding{scope: scope}
		process.material = &XrayDomainTCPOperationMaterial{binding: binding}
		owner := &DomainTCPOriginalScope{process: process, binding: binding, baseline: baseline}
		owner.self = owner
		capture := &DomainPolicyTCPCapture{owner: owner}
		owner.capture = capture
		baseline.self, baseline.binding, baseline.capture = baseline, binding, capture
		loan.read.owner = owner
		pool := &domainTCPStandbyPool{manager: manager}
		cursor := &domainTCPGlobalSuccessor{scope: scope, pool: pool}
		cursor.self, scope.domainSuccessor = cursor, cursor
		cursor.records = &xraySelectedTCPExecutionRecords{scope: scope}
		pool.self, pool.successor = pool, cursor
		witness := &domainTCPPoolListenerWitness{cursor: cursor, resource: process}
		witness.self = witness
		cursor.listener.Store(witness)
		read := &domainTCPSuccessorRead{cursor: cursor, loan: loan, files: loan.files, owner: owner, baseline: baseline, process: process, witness: witness, rootCtx: root, ctx: root}
		read.self = read
		old := &XrayDomainTCPExecutionResource{scope: &executionResourceScope{manager: manager}}
		old.self = old
		if err := read.rootCurrent(root); err != nil {
			t.Fatal("model file association", err)
		}
		return use(read, old)
	})
}

func TestDomainSuccessorReadRejectsForeignAndCopiedCarriers(t *testing.T) {
	err := domainSuccessorReadModel(t, func(read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource) error {
		copied := *read
		if copied.rootCurrent(read.rootCtx) == nil {
			t.Fatal("copied carrier accepted")
		}
		foreign := context.WithValue(read.rootCtx, struct{}{}, true)
		if read.rootCurrent(foreign) == nil {
			t.Fatal("foreign root context accepted")
		}
		if _, _, err := read.forPriorContext(foreign, old); err == nil {
			t.Fatal("foreign parent accepted")
		}
		if _, _, err := read.forPriorContext(read.rootCtx, read.process); err == nil {
			t.Fatal("successor used as prior")
		}
		prior, derived, err := read.forPriorContext(read.rootCtx, old)
		if err != nil {
			return err
		}
		if prior.Value(syntheticExecutionRegistrarKey{}) != old.scope {
			t.Fatal("original old scope context not retained")
		}
		if err := derived.current(prior, read.witness, old); err != nil {
			return err
		}
		if derived.current(foreign, read.witness, old) == nil || derived.current(prior, &domainTCPPoolListenerWitness{}, old) == nil || derived.current(prior, read.witness, read.process) == nil {
			t.Fatal("foreign association accepted")
		}
		if _, _, err := derived.forPriorContext(prior, old); err == nil {
			t.Fatal("unbounded derivation accepted")
		}
		// Static byte association is not original process/manager authority.
		if read.witness.currentWithSuccessorRead(prior, old, derived) == nil {
			t.Fatal("modeled witness minted native Current")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainSuccessorReadRejectsChangedOwnerAndExpiredLoan(t *testing.T) {
	var escaped *domainTCPSuccessorRead
	err := domainSuccessorReadModel(t, func(read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource) error {
		escaped = read
		process := read.witness.resource
		read.witness.resource = old
		if read.rootCurrent(read.rootCtx) == nil {
			t.Fatal("changed successor accepted")
		}
		read.witness.resource = process
		original := read.cursor.scope.domainSuccessor
		read.cursor.scope.domainSuccessor = &domainTCPGlobalSuccessor{}
		if read.rootCurrent(read.rootCtx) == nil {
			t.Fatal("foreign cursor accepted")
		}
		read.cursor.scope.domainSuccessor = original
		read.owner.closed = true
		if read.rootCurrent(read.rootCtx) == nil {
			t.Fatal("closed owner accepted")
		}
		read.owner.closed = false
		read.loan.open.Store(false)
		if read.rootCurrent(read.rootCtx) == nil {
			t.Fatal("revoked original loan accepted")
		}
		read.loan.open.Store(true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if escaped.rootCurrent(escaped.rootCtx) == nil {
		t.Fatal("escaped byte view accepted")
	}
}

func TestDomainSuccessorReadCanceledAndInvalidMarkers(t *testing.T) {
	var cursor *domainTCPGlobalSuccessor
	if read, err := cursor.originalSuccessorRead(context.Background()); read != nil || err != nil {
		t.Fatal("unmarked path changed", err)
	}
	for _, value := range []any{true, (*domainTCPPreAddLoan)(nil), &domainTCPPreAddLoan{}} {
		if read, err := cursor.originalSuccessorRead(context.WithValue(context.Background(), domainTCPPreAddKey{}, value)); read != nil || err == nil {
			t.Fatal("invalid marker fell back")
		}
	}
	err := domainSuccessorReadModel(t, func(read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource) error {
		prior, derived, err := read.forPriorContext(read.rootCtx, old)
		if err != nil {
			return err
		}
		canceled, cancel := context.WithCancel(prior)
		cancel()
		if err := derived.current(canceled, read.witness, old); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation cause lost", err)
		}
		if nested, revoke, err := derived.derive(canceled, canceled, read.witness, old); nested != nil || revoke != nil || err == nil {
			t.Fatal("invalid derivation issued view")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainSuccessorReadNoWitnessCannotHideInvalidLoan(t *testing.T) {
	err := domainSuccessorReadModel(t, func(read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource) error {
		c := read.cursor
		c.records = &xraySelectedTCPExecutionRecords{scope: c.scope}
		c.pool.self, c.pool.successor = c.pool, c
		c.listener.Store(nil)
		if got, err := c.originalSuccessorRead(read.rootCtx); got != nil || err != nil {
			t.Fatal("valid no-witness fallback changed", err)
		}
		read.owner.closed = true
		if got, err := c.originalSuccessorRead(read.rootCtx); got != nil || err == nil {
			t.Fatal("missing witness hid invalid original owner")
		}
		read.owner.closed = false
		read.loan.open.Store(false)
		if got, err := c.originalSuccessorRead(read.rootCtx); got != nil || err == nil {
			t.Fatal("missing witness hid revoked loan")
		}
		read.loan.open.Store(true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDomainSuccessorReadRetainsOuterActualByteClosing(t *testing.T) {
	err := domainSuccessorReadModel(t, func(read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource) error {
		path := read.process.executable.path
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		body[0] ^= 1
		if err := os.WriteFile(path, body, 0700); err != nil {
			return err
		}
		// The original full-byte closer must refuse even with the original length
		// and restored modification time; this model cannot mint a live witness.
		return os.Chtimes(path, read.process.executable.info.ModTime(), read.process.executable.info.ModTime())
	})
	if !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("outer source mutation escaped closing", err)
	}
}
