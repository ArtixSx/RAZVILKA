package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func nfqNeverIssuedWriterFixture(t *testing.T) (*policyEffectFixture, *nfqwsPolicyRecovery, context.Context) {
	t.Helper()
	f := newPolicyEffectFixture(t)
	cut := errors.New("original pre-Run cut")
	f.options.fault = func(point string, index int) error {
		if point == "intent" && index == 3 {
			return cut
		}
		return nil
	}
	c := &nfqwsPolicyRecovery{index: -1}
	c.self = c
	ctx := context.Background()
	if err := applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c); !errors.Is(err, cut) || !c.retained || c.entered || len(f.calls) != 3 {
		t.Fatal("original prefix/never-issued witness missing", err, c.retained, c.entered, f.calls)
	}
	t.Cleanup(c.close)
	c.session.options.fault = nil
	return f, c, context.WithValue(ctx, policyEffectReceiptBorrowKey{}, c.session.borrow)
}

// This proves original writer custody and COMMON transitions with the existing
// command model. Native process/queue/inventory proof is a separate fixture.
func TestNFQWSNeverIssuedOriginalWriterSettlesOnlyIntentAndRemovesACKPrefix(t *testing.T) {
	f, c, ctx := nfqNeverIssuedWriterFixture(t)
	if err := c.session.removeKnownEffects(ctx, f.runtime); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != 3 {
		t.Fatal("ordinary unknown guard weakened", err, f.calls)
	}
	verified := 0
	if err := c.settleNeverIssued(ctx, func() error { verified++; return nil }); err != nil {
		t.Fatal(err)
	}
	if verified != 1 || !c.settled || c.session.doc.Steps[3].State != "removed" || len(f.calls) != 3 {
		t.Fatal("settlement issued an effect or lost its proof", verified, f.calls)
	}
	for i, step := range c.session.doc.Steps {
		if i < 3 && step.State != "added" || i > 3 && step.State != "planned" {
			t.Fatal("changed unrelated original state", i, step.State)
		}
	}
	if err := c.session.removeKnownEffects(ctx, f.runtime); err != nil || !c.session.status().Removed || len(f.calls) != 6 {
		t.Fatal("strict original prefix cleanup failed", err, f.calls)
	}
	for i, call := range f.calls[3:] {
		if call.add || call.index != 2-i {
			t.Fatal("never-issued or unrelated effect received a delete grant", call)
		}
	}
	c.close()
	if err := f.remove(); err != nil || len(f.calls) != 6 {
		t.Fatal("cold observer replayed terminal prefix", err)
	}
	if err := f.apply(); !errors.Is(err, ErrPolicyAdditionExists) {
		t.Fatal("old generation replayed instead of fresh generation", err)
	}
}

func TestNFQWSNeverIssuedSettlementPublicationCutsRetrySameAuthoredFD(t *testing.T) {
	for _, point := range []string{"nfq-original-publication", "nfq-original-before-sync", "nfq-original-after-sync"} {
		t.Run(point, func(t *testing.T) {
			f, c, ctx := nfqNeverIssuedWriterFixture(t)
			cut := errors.New(point)
			c.session.options.fault = func(got string, _ int) error {
				if got == point {
					return cut
				}
				return nil
			}
			before := c.publication
			if err := c.settleNeverIssued(ctx, func() error { return nil }); !errors.Is(err, cut) || !c.settled || !c.needsSync || c.publication != before+1 || len(f.calls) != 3 {
				t.Fatal("publication cut lost exact custody", err, c.settled, c.needsSync)
			}
			file := c.pending
			if file == nil {
				file = c.session.borrow.published
			}
			original, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			c.session.options.fault = nil
			if err := c.settleNeverIssued(ctx, func() error { return nil }); err != nil || c.needsSync || c.publication != before+1 {
				t.Fatal("retry rewrote/adopted instead of closing original publication", err)
			}
			retained, err := c.session.borrow.published.Stat()
			if err != nil || !os.SameFile(original, retained) {
				t.Fatal("original inode lost", err)
			}
			if err := c.session.removeKnownEffects(ctx, f.runtime); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNFQWSNeverIssuedRecoveryRefusesChangedCustodyAndExpiredForward(t *testing.T) {
	for _, name := range []string{"copy", "receipt-inode", "receipt-bytes", "marker", "boot", "proof-refusal", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f, original, ctx := nfqNeverIssuedWriterFixture(t)
			c := original
			proof := func() error { return nil }
			switch name {
			case "copy":
				c = &nfqwsPolicyRecovery{self: original, session: original.session, index: original.index, retained: true}
			case "receipt-inode":
				raw, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
				if err != nil {
					t.Fatal(err)
				}
				if err := c.session.root.WriteAtomic(policyAdditionFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-bytes":
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionFile), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "marker":
				if err := os.WriteFile(filepath.Join(f.root, policyAdditionLock), []byte("changed-marker"), 0600); err != nil {
					t.Fatal(err)
				}
			case "boot":
				c.session.options.boot = func() (string, error) { return "new-boot", nil }
			case "proof-refusal":
				proof = func() error { return errors.New("foreign target or changed complete inventory") }
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := c.settleNeverIssued(ctx, proof); err == nil || len(f.calls) != 3 || original.session.doc.Steps[3].State != "intent" {
				t.Fatal("refusal acquired a cleanup grant", err, f.calls)
			}
			if name == "canceled" {
				fresh := context.WithValue(context.Background(), policyEffectReceiptBorrowKey{}, original.session.borrow)
				if err := original.settleNeverIssued(fresh, proof); err != nil {
					t.Fatal("expired forward destroyed original cleanup custody", err)
				}
			}
		})
	}
}

func TestNFQWSNeverIssuedCustodyNeverSurvivesRunEntryOrLostACK(t *testing.T) {
	for _, cut := range []string{"runner-refusal", "lost-ACK", "after-ACK"} {
		t.Run(cut, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			failure := errors.New(cut)
			switch cut {
			case "runner-refusal":
				f.runtime.Runner = policyEffectInvocationTestRunner(func(context.Context, string, ...string) ([]byte, error) { return nil, failure })
			case "lost-ACK":
				f.lostAdd = 0
			case "after-ACK":
				f.options.fault = func(point string, _ int) error {
					if point == "add" {
						return failure
					}
					return nil
				}
			}
			c := &nfqwsPolicyRecovery{index: -1}
			c.self = c
			if err := applyPolicyEffectsWithOriginalRecovery(context.Background(), f.runtime, f.plan, f.root, f.options, nil, c); err == nil || c.retained || !c.entered {
				t.Fatal("Run entry was classified never-issued", err, c.retained, c.entered)
			}
			if err := f.remove(); !errors.Is(err, ErrPolicyAdditionUnknown) {
				t.Fatal("unknown command outcome lost its fence", err)
			}
		})
	}
}

func TestNFQWSRecoveryReceiptScopeRevocationAndForeignCopy(t *testing.T) {
	f, c, ctx := nfqNeverIssuedWriterFixture(t)
	e := &nfqws2ActiveExecution{partialRecovery: c}
	e.self, c.execution = e, e
	scope := &nfqwsRecoveryScope{owner: c}
	scope.self = scope
	c.scope.Store(scope)
	ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, e)
	ctx = context.WithValue(ctx, nfqwsPolicyRecoveryKey{}, scope)
	status, present, err := inspectNFQWSRecoveryReceipt(ctx, f.plan, f.root)
	if err != nil || !present || !status.Unknown || status.Added != 3 {
		t.Fatal("original readonly scope lost its actual unknown receipt", status, present, err)
	}
	copyScope := &nfqwsRecoveryScope{self: scope, owner: c}
	foreign := context.WithValue(ctx, nfqwsPolicyRecoveryKey{}, copyScope)
	if _, _, err := inspectNFQWSRecoveryReceipt(foreign, f.plan, f.root); err == nil {
		t.Fatal("copied scope acquired original writer access")
	}
	scope.closed.Store(true)
	// An escaped old context must refuse while a later original rollback
	// publishes/revokes its own scope, before reading mutable owner fields.
	finished := make(chan error, 1)
	go func() {
		for range 100 {
			if _, _, err := inspectNFQWSRecoveryReceipt(ctx, f.plan, f.root); err == nil {
				finished <- errors.New("revoked scope accepted")
				return
			}
		}
		finished <- nil
	}()
	for range 100 {
		next := &nfqwsRecoveryScope{owner: c}
		next.self = next
		c.scope.Store(next)
		next.closed.Store(true)
		c.scope.Store(nil)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestNFQWSRecoveryLateForeignTargetCannotConsumeACKPrefix(t *testing.T) {
	f, c, ctx := nfqNeverIssuedWriterFixture(t)
	if err := c.settleNeverIssued(ctx, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// A third-party identical target appearing after settlement remains unowned.
	f.present[3] = 1
	if err := c.session.removeKnownEffects(ctx, f.runtime); !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != 3 {
		t.Fatal("late target let cleanup strip original prerequisites", err, f.calls)
	}
	if !c.session.status().Unknown {
		t.Fatal("failed cleanup scan lost its durable fence")
	}
}

func TestNFQWSRecoveryTerminalCloseUnregistersSourceShutdown(t *testing.T) {
	_, c, _ := nfqNeverIssuedWriterFixture(t)
	panel, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{}, 1)
	stop := context.AfterFunc(panel, func() { called <- struct{}{} })
	unregistered := false
	c.shutdownStop = func() bool { unregistered = stop(); return unregistered }
	c.close()
	if !unregistered || c.shutdownStop != nil || !c.closed {
		t.Fatal("terminal recovery retained its execution through source shutdown callback")
	}
	c.close()
	cancel()
	select {
	case <-called:
		t.Fatal("revoked source shutdown callback ran")
	default:
	}
}

func TestNFQWSRecoveryConcurrentReaderUsesOnlyPublishedImage(t *testing.T) {
	f, c, ctx := nfqNeverIssuedWriterFixture(t)
	e := &nfqws2ActiveExecution{partialRecovery: c}
	e.self, c.execution = e, e
	scope := &nfqwsRecoveryScope{owner: c}
	scope.self = scope
	c.scope.Store(scope)
	ctx = context.WithValue(ctx, nfqws2ActiveExecutionKey{}, e)
	ctx = context.WithValue(ctx, nfqwsPolicyRecoveryKey{}, scope)
	started, stop, joined := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		for {
			select {
			case <-stop:
				joined <- nil
				return
			default:
			}
			status, present, err := inspectNFQWSRecoveryReceipt(ctx, f.plan, f.root)
			// Atomic rename may temporarily disagree with the old publication:
			// refusal is correct, synthesized complete authority is never correct.
			if err == nil && (!present || status.Complete || status.Added != 3 || status.Cleaned > 1) {
				joined <- errors.New("reader exposed mutable or fabricated writer state")
				return
			}
		}
	}()
	<-started
	err := c.settleNeverIssued(ctx, func() error { return nil })
	close(stop)
	readErr := <-joined
	if err != nil || readErr != nil {
		t.Fatal("original concurrent receipt boundary", err, readErr)
	}
}

func TestNFQWSUnpublishedIntentPreservesKnownPrefixCleanup(t *testing.T) {
	for _, failure := range []string{"prewrite", "canceled", "permission"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "permission" && (runtime.GOOS != "linux" || os.Geteuid() == 0) {
				t.Skip("actual pre-rename permission failure requires non-root Linux")
			}
			f := newPolicyEffectFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cut := errors.New("before actual intent write")
			beforeWrite := false
			f.options.fault = func(point string, index int) error {
				if failure == "permission" && point == "added" && index == 2 {
					return os.Chmod(f.root, 0500)
				}
				if point == "nfq-original-before-write" && index == 3 {
					beforeWrite = true
					if failure == "canceled" {
						cancel()
						return ctx.Err()
					}
					if failure == "prewrite" {
						return cut
					}
				}
				return nil
			}
			c := &nfqwsPolicyRecovery{index: -1}
			c.self = c
			err := applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c)
			if failure == "permission" {
				if restore := os.Chmod(f.root, 0700); restore != nil {
					t.Fatal(restore)
				}
			}
			if err == nil || !beforeWrite || c.retained || c.fenced || c.renameAttempted || c.session.doc.Steps[3].State != "planned" || len(f.calls) != 3 {
				t.Fatal("unpublished intent stranded formerly known prefix", err, c.retained, c.fenced, c.renameAttempted, f.calls)
			}
			if failure == "permission" && !errors.Is(err, os.ErrPermission) {
				t.Fatal("did not exercise actual pre-rename permission error", err)
			}
			if failure == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause was lost", err)
			}
			f.options.fault = nil
			if err := f.remove(); err != nil || len(f.calls) != 6 {
				t.Fatal("fresh strict Remove cannot clean original ACKs", err, f.calls)
			}
			for _, call := range f.calls[3:] {
				if call.add || call.index >= 3 {
					t.Fatal("unpublished intent gained Delete", call)
				}
			}
		})
	}
}

func TestNFQWSUnpublishedIntentCannotAdoptReplacedPriorInode(t *testing.T) {
	f := newPolicyEffectFixture(t)
	cut := errors.New("prior authored inode replaced")
	f.options.fault = func(point string, index int) error {
		if point != "nfq-original-before-write" || index != 3 {
			return nil
		}
		raw, err := os.ReadFile(filepath.Join(f.root, policyAdditionFile))
		if err != nil {
			return err
		}
		root, err := nfqwsScopedOpenReceiptRoot(f.root)
		if err != nil {
			return err
		}
		defer root.Close()
		if err := root.WriteAtomic(policyAdditionFile, raw, 0600); err != nil {
			return err
		}
		return cut
	}
	c := &nfqwsPolicyRecovery{index: -1}
	c.self = c
	err := applyPolicyEffectsWithOriginalRecovery(context.Background(), f.runtime, f.plan, f.root, f.options, nil, c)
	defer c.close()
	if !errors.Is(err, cut) || !c.retained || !c.fenced || len(f.calls) != 3 {
		t.Fatal("same-byte replacement manufactured known prefix release", err, c.retained, c.fenced)
	}
}

func TestNFQWSRecoveryWriterPreservesForeignPublicationFences(t *testing.T) {
	for _, owner := range []string{"xray", "wireguard"} {
		t.Run(owner, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			ctx := context.Background()
			if owner == "xray" {
				ctx = context.WithValue(ctx, xrayOperationOwnerKey{}, struct{}{})
			} else {
				ctx = context.WithValue(ctx, wgOperationOwnerKey{}, struct{}{})
				ctx = context.WithValue(ctx, wgCommonWriterKey{}, struct{}{})
			}
			c := &nfqwsPolicyRecovery{index: -1}
			c.self = c
			if err := applyPolicyEffectsWithOriginalRecovery(ctx, f.runtime, f.plan, f.root, f.options, nil, c); err == nil || len(f.calls) != 0 || c.retained {
				t.Fatal("foreign publication fence bypassed", err, f.calls, c.retained)
			}
		})
	}
}
