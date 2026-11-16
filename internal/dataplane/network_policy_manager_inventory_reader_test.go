package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNetworkPolicyInventoryReaderTypedDispatch(t *testing.T) {
	c, s, ctx := networkPolicyNFQReadSourcesFixture(t)
	original, err := c.manager.BindNetworkPolicyChecks(c.gate, &s.execution.inventory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = original.Close() })
	reader, ok := original.readSource.(*networkPolicyOriginalInventoryReader)
	if !ok || reader == nil || reader.inventory != original.inventory || reader.inventory == &s.execution.inventory {
		t.Fatal("public bind did not freeze one exact original dispatcher")
	}
	sentinel := errors.New("custom read")
	calls := 0
	custom := networkPolicyInventoryCallback(func(got context.Context, id netidentity.Identity) (BackendInventorySnapshot, error) {
		calls++
		if got != ctx || id != s.identity.value {
			t.Fatal("custom arguments changed")
		}
		return BackendInventorySnapshot{}, sentinel
	})
	before := original.readSource
	original.readSource = custom
	if _, err := original.read(ctx, s.identity.value); !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal("custom dispatch changed", err, calls)
	}
	if _, ok := original.readSource.(*networkPolicyOriginalInventoryReader); ok {
		t.Fatal("custom callback acquired original type")
	}
	original.readSource = before
	if original.readSource != reader {
		t.Fatal("original source restoration changed")
	}
}

func TestNetworkPolicyInventoryReaderMissing(t *testing.T) {
	for _, reader := range []networkPolicyInventoryReader{nil, networkPolicyInventoryCallback(nil), (*networkPolicyOriginalInventoryReader)(nil), &networkPolicyOriginalInventoryReader{}} {
		c := &NetworkPolicyChecks{readSource: reader}
		if _, err := c.read(context.Background(), netidentity.Identity{}); err == nil {
			t.Fatal("missing source accepted")
		}
	}
}
