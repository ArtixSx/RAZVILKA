package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

// These tests exercise the actual COMMON file writer and held descriptors.
// Their existing kernel model does not grant native Xray/process admission.
func TestXraySelectedTCPCommonWriterRetainsActualPublication(t *testing.T) {
	f := newPolicyEffectFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	publications := 0
	f.runtime.Guard = func(c context.Context, _ int) error {
		b := c.Value(policyEffectReceiptBorrowKey{}).(*policyEffectReceiptBorrow)
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.absent {
			return nil
		}
		if b.published == nil {
			t.Fatal("actual writer lost its published FD")
		}
		held, err := b.published.Stat()
		named, namedErr := b.session.root.Stat(policyAdditionFile)
		if err != nil || namedErr != nil || !os.SameFile(held, named) || !os.SameFile(held, b.publishedInfo) {
			t.Fatal("actual save did not retain its own publication", err, namedErr)
		}
		publications++
		return nil
	}
	if err := applyPolicyEffects(ctx, f.runtime, f.plan, f.root, f.options); err != nil || publications == 0 {
		t.Fatal("actual COMMON save coverage missing", err, publications)
	}
}

func TestXraySelectedTCPCommonWriterRefusesSameBytesABABeforeACK(t *testing.T) {
	f := newPolicyEffectFixture(t)
	if err := f.apply(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := openPolicyEffectSession(ctx, f.plan, f.root, f.options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.load(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := newPolicyEffectReceiptBorrow(s)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	data, err := json.Marshal(s.doc)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := s.root.WriteAtomicRetained(policyAdditionFile, data, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer actual.Close()
	if err := s.root.WriteAtomic(policyAdditionFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := b.savedOriginal(actual); !errors.Is(err, ErrPolicyAdditionReceipt) || b.published != nil {
		t.Fatal("same-byte replacement manufactured publisher ACK", err)
	}
	if _, err := actual.Stat(); err != nil {
		t.Fatal("failed ACK took ownership of caller's FD", err)
	}
	if err := (&policyEffectReceiptBorrow{self: b, session: s}).savedOriginal(actual); !errors.Is(err, ErrPolicyAdditionReceipt) {
		t.Fatal("copied writer acquired publication", err)
	}
}
