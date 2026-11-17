//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package app

import (
	"context"
	"testing"
)

type releaseForeignPhysicalSource struct{}

func (releaseForeignPhysicalSource) original(*ManagedNFQWSListRuntime) bool { return true }
func (releaseForeignPhysicalSource) acquire(context.Context, *managedNFQWSListExecution, bool) error {
	panic("release comparison must not acquire physical scope")
}

func TestManagedNFQReleaseNativeExceptionRequiresOriginalActor(t *testing.T) {
	a, r := managedNFQReleaseFixture(t)
	if managedNFQExperimentalRuntime(r) {
		t.Fatal("tag alone enabled production owner")
	}
	if err := installNativeFixtureNFQListPhysicalSource(r); err != nil {
		t.Fatal(err)
	}
	s := r.physicalSource.(*nativeFixtureNFQListPhysicalSource)
	if !managedNFQExperimentalRuntime(r) || a.managedNFQNewApplyRefusal("chat") != nil {
		t.Fatal("original explicit fixture no longer reaches experimental scenario")
	}
	for _, source := range []managedNFQListPhysicalSource{
		nil, (*nativeFixtureNFQListPhysicalSource)(nil), releaseForeignPhysicalSource{},
		&nativeFixtureNFQListPhysicalSource{self: s, runtime: r, app: a, provider: r.provider},
	} {
		r.physicalSource = source
		if managedNFQExperimentalRuntime(r) {
			t.Fatal("foreign/copied source enabled experimental scenario")
		}
	}
	r.physicalSource = s
	a.managedNFQList = nil
	if managedNFQExperimentalRuntime(r) {
		t.Fatal("detached actor enabled experimental scenario")
	}
	a.managedNFQList = r
	r.tools = nil
	if managedNFQExperimentalRuntime(r) {
		t.Fatal("incomplete owner enabled experimental scenario")
	}
}
