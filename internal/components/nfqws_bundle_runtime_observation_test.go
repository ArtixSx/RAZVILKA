package components

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func TestManagedNFQWSObservationDoesNotBorrowOrReleaseRuntimeWriter(t *testing.T) {
	m, lease := runtimeForkFixture(t)
	descriptor := lease.Descriptor()
	observed, err := m.ObserveCurrentManagedNFQWSRuntime(context.Background())
	if err != nil || !reflect.DeepEqual(observed, descriptor) {
		t.Fatal("same-generation observation conflicts with legitimate writer", err)
	}
	requireRuntimeWriterHeld(t, m)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	observed, err = m.ObserveCurrentManagedNFQWSRuntime(context.Background())
	if err != nil || !reflect.DeepEqual(observed, descriptor) {
		t.Fatal("read-only observation requires old runtime lease", err)
	}
	if err := os.Chmod(descriptor.Executable.Path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descriptor.Executable.Path, []byte("modified immutable executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ObserveCurrentManagedNFQWSRuntime(context.Background()); err == nil {
		t.Fatal("modified generation remained eligible")
	}
}
