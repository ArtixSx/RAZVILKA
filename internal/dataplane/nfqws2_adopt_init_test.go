package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func adoptInitFixture(t *testing.T) (*NFQWS2Adapter, string, string) {
	t.Helper()
	a, _, root := newOwnedNFQWS2(t)
	transaction := stageOwnedNFQWS2(t, a, root, "owned.example")
	if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.InitPath, 0o755); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(root, "nfqws2-keenetic.list")
	if err := os.WriteFile(list, []byte("/opt/usr/bin/nfqws2\n"+a.InitPath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return a, list, transaction
}

func TestNFQWS2AdoptsPackageInitAndOnlyInit(t *testing.T) {
	a, list, _ := adoptInitFixture(t)
	if err := os.WriteFile(a.InitPath, []byte("#!/bin/sh\n# upgraded package\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyOwnedRuntime(mustLease(t, a), false); err == nil {
		t.Fatal("fixture did not reproduce the stale init hash")
	}
	previous, adopted, err := a.AdoptPackageInit(list)
	if err != nil || previous == adopted || adopted == "" {
		t.Fatalf("adopt: %q -> %q, %v", previous, adopted, err)
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		t.Fatal("ownership still refuses after adoption:", err)
	}
	if again, same, err := a.AdoptPackageInit(list); err != nil || again != adopted || same != adopted {
		t.Fatal("repeated adoption is not a no-op", again, same, err)
	}
}

func TestNFQWS2AdoptRefusesAnyOtherDrift(t *testing.T) {
	for _, mode := range []string{"config", "list", "unlisted", "missing-list", "no-lease"} {
		t.Run(mode, func(t *testing.T) {
			a, list, _ := adoptInitFixture(t)
			if err := os.WriteFile(a.InitPath, []byte("#!/bin/sh\n# upgraded package\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "config":
				if err := os.WriteFile(a.ConfigPath, []byte("foreign-config\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "list":
				if err := os.WriteFile(a.IPSetListPath, []byte(managedBegin+"\n# RAZVILKA INSTANCE foreign\n198.51.100.0/24\n"+managedEnd+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unlisted":
				if err := os.WriteFile(list, []byte("/opt/usr/bin/nfqws2\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "missing-list":
				list = filepath.Join(filepath.Dir(list), "absent.list")
			case "no-lease":
				if err := os.Remove(filepath.Join(a.StateRoot, nfqws2LeaseFile)); err != nil {
					t.Fatal(err)
				}
			}
			before := mustLeaseOrNil(t, a)
			if _, _, err := a.AdoptPackageInit(list); err == nil {
				t.Fatal("adoption accepted", mode)
			}
			if after := mustLeaseOrNil(t, a); before != nil && after.InitHash != before.InitHash {
				t.Fatal("refused adoption changed the lease")
			}
		})
	}
}

func mustLease(t *testing.T, a *NFQWS2Adapter) *nfqws2Lease {
	t.Helper()
	lease := mustLeaseOrNil(t, a)
	if lease == nil {
		t.Fatal("NFQWS2 lease is missing")
	}
	return lease
}

func mustLeaseOrNil(t *testing.T, a *NFQWS2Adapter) *nfqws2Lease {
	t.Helper()
	lease, err := a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	return lease
}
