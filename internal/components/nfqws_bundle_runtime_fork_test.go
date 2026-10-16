package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func runtimeForkFixture(t *testing.T) (*Manager, *ManagedNFQWSRuntimeLease) {
	t.Helper()
	manifest, input, _ := bundleFixtureManifest(t, "validation-fork")
	m := bundleFixtureManager(t, input)
	if _, err := m.InstallManagedBundle(t.Context(), manifest, 7, bundleFixtureAuthority()); err != nil {
		t.Fatal(err)
	}
	l, err := m.AcquireCurrentManagedNFQWSRuntime(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return m, l
}

func requireRuntimeWriterHeld(t *testing.T, m *Manager) {
	t.Helper()
	if other, err := m.AcquireCurrentManagedNFQWSRuntime(t.Context()); err == nil || other != nil {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("independent acquisition crossed original exclusive writer")
	}
}

func TestManagedNFQWSRuntimeValidationForkLifecycle(t *testing.T) {
	m, source := runtimeForkFixture(t)
	child, err := source.ForkValidation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Close() })
	if child == source || child.owner != source.owner || !reflect.DeepEqual(child.Descriptor(), source.Descriptor()) {
		t.Fatal("fork was not issued by the same immutable owner")
	}
	if err := source.Close(); !errors.Is(err, ErrManagedNFQWSValidationPending) {
		t.Fatal("source did not retain pending validation", err)
	}
	if source.Check(t.Context()) != nil || child.Check(t.Context()) != nil {
		t.Fatal("refused source Close revoked an original owner")
	}
	for _, issuer := range []*ManagedNFQWSRuntimeLease{source, child} {
		if other, err := issuer.ForkValidation(t.Context()); err == nil || other != nil {
			t.Fatal("nested/duplicate validation fork admitted")
		}
	}
	requireRuntimeWriterHeld(t, m)
	d := child.Descriptor()
	d.Lua[0].SHA256 = "mutated"
	d.AllowedFeatures = append(d.AllowedFeatures, "foreign")
	if !reflect.DeepEqual(child.Descriptor(), source.Descriptor()) {
		t.Fatal("descriptor mutation reached original owner")
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Close(); err != nil {
		t.Fatal("double Close", err)
	}
	if child.Check(t.Context()) == nil || child.Descriptor().ReceiptID != "" {
		t.Fatal("closed validation retained access")
	}
	if source.Check(t.Context()) != nil {
		t.Fatal("validation Close revoked source")
	}
	requireRuntimeWriterHeld(t, m)
	// A completed validation may be replaced, never resurrected.
	nextChild, err := source.ForkValidation(t.Context())
	if err != nil || nextChild == child {
		t.Fatal("new lifecycle", err)
	}
	if err := nextChild.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if child, err := source.ForkValidation(t.Context()); err == nil || child != nil {
		t.Fatal("closed source issued validation")
	}
	next, err := m.AcquireCurrentManagedNFQWSRuntime(t.Context())
	if err != nil {
		t.Fatal("final original Close did not release writer", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedNFQWSRuntimeValidationForkRejectsCopiesAndCancellation(t *testing.T) {
	m, source := runtimeForkFixture(t)
	copy := &ManagedNFQWSRuntimeLease{owner: source.owner}
	copy.self = copy // Even a self-consistent unregistered object has no grant.
	for _, invalid := range []*ManagedNFQWSRuntimeLease{nil, {}, copy} {
		if child, err := invalid.ForkValidation(t.Context()); err == nil || child != nil {
			t.Fatal("unissued object forked writer")
		}
	}
	if copy.Check(t.Context()) == nil || copy.Descriptor().ReceiptID != "" || copy.Close() == nil {
		t.Fatal("unregistered copy acquired membership")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if child, err := source.ForkValidation(ctx); !errors.Is(err, context.Canceled) || child != nil {
		t.Fatal("canceled fork", err)
	}
	if source.Check(t.Context()) != nil {
		t.Fatal("failed fork changed original source")
	}
	requireRuntimeWriterHeld(t, m)
}

func TestManagedNFQWSRuntimeValidationForkFreshChecksAndErrorClose(t *testing.T) {
	for _, damage := range []string{"generation", "unknown-journal"} {
		t.Run(damage, func(t *testing.T) {
			m, source := runtimeForkFixture(t)
			child, err := source.ForkValidation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			path := source.Descriptor().Executable.Path
			if damage == "unknown-journal" {
				path = filepath.Join(m.updateJournalDir(), "current.json")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("tampered generation"), 0600); err != nil {
				t.Fatal(err)
			}
			if source.Check(t.Context()) == nil || child.Check(t.Context()) == nil {
				t.Fatal("fork skipped original full generation check")
			}
			if err := source.Close(); !errors.Is(err, ErrManagedNFQWSValidationPending) {
				t.Fatal("tamper released pending writer", err)
			}
			requireRuntimeWriterHeld(t, m)
			if child.Close() == nil {
				t.Fatal("changed child Close reported acceptance")
			}
			if fork, err := source.ForkValidation(t.Context()); err == nil || fork != nil {
				t.Fatal("changed generation forked after child Close")
			}
			requireRuntimeWriterHeld(t, m)
			if source.Close() == nil {
				t.Fatal("changed source Close reported acceptance")
			}
			// Inspect the real writer directly: generation verification must still fail,
			// but both lifecycle Close calls must have released the one original flock.
			tx, err := m.lockUpdateJournal()
			if err != nil {
				t.Fatal("error Close leaked writer", err)
			}
			tx.close()
		})
	}
}

func TestManagedNFQWSRuntimeValidationForkConcurrentLifecycle(t *testing.T) {
	m, source := runtimeForkFixture(t)
	var wg sync.WaitGroup
	children := make(chan *ManagedNFQWSRuntimeLease, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			child, _ := source.ForkValidation(context.Background())
			if child != nil {
				children <- child
			}
		}()
	}
	wg.Wait()
	close(children)
	var child *ManagedNFQWSRuntimeLease
	for issued := range children {
		if child != nil {
			t.Fatal("two simultaneous validation children")
		}
		child = issued
	}
	if child == nil {
		t.Fatal("no validation issued")
	}
	requireRuntimeWriterHeld(t, m)
	var parentErr, childErr error
	wg.Add(2)
	go func() { defer wg.Done(); parentErr = source.Close() }()
	go func() { defer wg.Done(); childErr = child.Close() }()
	wg.Wait()
	if childErr != nil || parentErr != nil && !errors.Is(parentErr, ErrManagedNFQWSValidationPending) {
		t.Fatal(parentErr, childErr)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := m.AcquireCurrentManagedNFQWSRuntime(t.Context())
	if err != nil {
		t.Fatal("concurrent lifecycle leaked writer", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
