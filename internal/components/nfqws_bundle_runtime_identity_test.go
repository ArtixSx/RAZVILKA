package components

import (
	"context"
	"errors"
	"testing"
)

func TestManagedNFQWSRuntimeCopyCannotUseOrReleaseOriginalWriter(t *testing.T) {
	manifest, input, _ := bundleFixtureManifest(t, "original-runtime")
	m := bundleFixtureManager(t, input)
	if _, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority()); err != nil {
		t.Fatal(err)
	}
	lease, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	// Clone every capability-bearing field without copying sync.Mutex. The
	// ordinary public value-copy carries this same original self pointer.
	copy := &ManagedNFQWSRuntimeLease{self: lease.self, manager: lease.manager, tx: lease.tx, receipt: lease.receipt, descriptor: lease.descriptor}
	for _, invalid := range []*ManagedNFQWSRuntimeLease{{}, copy} {
		if invalid.Descriptor().ReceiptID != "" || !errors.Is(invalid.Check(context.Background()), ErrManagedNFQWSBundle) || !errors.Is(invalid.Close(), ErrManagedNFQWSBundle) {
			t.Fatal("copied/zero runtime retained source or writer authority")
		}
		if err := lease.Check(context.Background()); err != nil {
			t.Fatal("invalid Close released the original runtime", err)
		}
		if other, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background()); err == nil || other != nil {
			t.Fatal("invalid Close released the existing writer lease")
		}
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if copy.Check(context.Background()) == nil || lease.Check(context.Background()) == nil {
		t.Fatal("closed original admitted copied runtime")
	}
	next, err := m.AcquireCurrentManagedNFQWSRuntime(context.Background())
	if err != nil {
		t.Fatal("original Close did not release the actual writer", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
