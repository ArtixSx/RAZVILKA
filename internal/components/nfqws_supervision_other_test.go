//go:build !linux

package components

import (
	"context"
	"errors"
	"testing"
)

func TestNFQWSSupervisionUnavailable(t *testing.T) {
	if _, err := ReadNFQWSSupervisionIdentity(); !errors.Is(err, ErrNFQWSSupervisionUnavailable) {
		t.Fatal(err)
	}
	if _, err := ReadNFQWSSupervisionProcessIdentity(42); !errors.Is(err, ErrNFQWSSupervisionUnavailable) {
		t.Fatal(err)
	}
	if receipt, err := RunNFQWSSupervision(context.Background(), nfqwsTestCommand(t), nfqwsTestHooks()); !errors.Is(err, ErrNFQWSSupervisionUnavailable) || receipt.Started {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}
