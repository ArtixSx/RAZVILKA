//go:build linux

package dataplane

import (
	"os"
	"testing"
)

// Actual Linux file ownership/modes, with the explicitly modeled original
// process/kernel source. This does not claim native network acceptance.
func TestNFQWS2RebootStopPackageOwnedListFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing only temporary fixture ownership requires root")
	}
	f := newNFQWS2RebootStopFixture(t)
	platform, err := nfqws2InactiveSystemPlatform()
	if err != nil {
		t.Fatal(err)
	}
	f.proof.protected, f.proof.foreignList = platform.protected, platform.foreignList
	f.source.platform = f.proof
	lists := f.a.ownedListPaths()
	for _, path := range lists[2:] {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal("private fixture stock-owner setup", err)
		}
	}
	ctx := nfqws2InactiveTestContext(t)
	if err := f.admit(ctx); err != nil {
		t.Fatal("actual stock list UID blocked original Stop", err)
	}
	if err := os.Chmod(lists[2], 0664); err != nil {
		t.Fatal(err)
	}
	if err := f.admit(ctx); err == nil {
		t.Fatal("stock owner allowance admitted group-writable list")
	}
}
