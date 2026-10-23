package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNFQWS2CurrentProfileRequiresRunningReceiptAndReadback(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	if f.m.NFQWS2CurrentDomainOnlyProfile(firstStartContext(t)) {
		t.Fatal("stock readiness was classified as a current profile")
	}
	f.apply(t)
	if !f.m.NFQWS2CurrentDomainOnlyProfile(firstStartContext(t)) {
		t.Fatal("confirmed running profile not classified")
	}
	lease, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	before := readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))
	for _, which := range []string{"process", "config", "list", "receipt", "cancel"} {
		t.Run(which, func(t *testing.T) {
			identity := f.identity
			config := readBytes(t, f.a.ConfigPath)
			list := readBytes(t, f.a.ownedListPaths()[0])
			ctx := firstStartContext(t)
			switch which {
			case "process":
				f.identity.Start = "99999"
			case "config":
				writeStockText(t, f.a.ConfigPath, string(config)+"\n# changed\n")
			case "list":
				writeStockText(t, f.a.ownedListPaths()[0], "changed")
			case "receipt":
				changed := *lease
				changed.FirstStart = nil
				if err := f.a.writeLease(&changed); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if f.m.NFQWS2CurrentDomainOnlyProfile(ctx) {
				t.Fatal("changed/external profile acquired closed classification")
			}
			f.identity = identity
			if err := os.WriteFile(f.a.ConfigPath, config, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.a.ownedListPaths()[0], list, 0644); err != nil {
				t.Fatal(err)
			}
			if err := f.a.writeLease(lease); err != nil {
				t.Fatal(err)
			}
		})
	}
	if !reflect.DeepEqual(before, readBytes(t, filepath.Join(f.a.StateRoot, nfqws2LeaseFile))) {
		t.Fatal("profile observation rewrote receipt")
	}
	if err := f.a.Deactivate(firstStartContext(t)); err != nil {
		t.Fatal(err)
	}
	if f.m.NFQWS2CurrentDomainOnlyProfile(firstStartContext(t)) {
		t.Fatal("stopped receipt invented current running profile")
	}
}
