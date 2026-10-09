package app

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

func TestManagedNFQRouteChoiceRequiresOriginalInstalledReceipt(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	option := routecatalog.Option{ID: "nfqws2"}
	before := option
	a.prepareManagedNFQRouteOption(context.Background(), &option)
	if !reflect.DeepEqual(option, before) {
		t.Fatal("missing installed source enabled route", option)
	}
	journal := filepath.Join(a.Components.StateDir, "update-journal")
	if err := os.MkdirAll(journal, 0700); err != nil {
		t.Fatal(err)
	}
	// Decoded installed/ready/native flags do not create a genuine receipt.
	if err := os.WriteFile(filepath.Join(journal, "current.json"), []byte(`{"installed":true,"ready":true,"native":true,"generation_path":"request supplied"}`), 0600); err != nil {
		t.Fatal(err)
	}
	a.prepareManagedNFQRouteOption(context.Background(), &option)
	if !reflect.DeepEqual(option, before) || a.managedNFQList != nil || a.Operations.Snapshot().Active != 0 {
		t.Fatal("decoded flags supplied availability or runtime", option)
	}
}

func TestManagedNFQRouteChoiceDoesNotReplaceOtherEngineOrCanceledSource(t *testing.T) {
	a := managedNFQInitialControlFixture(t)
	for _, original := range []routecatalog.Option{{ID: "direct", Installed: true, Selectable: true, Ready: true}, {ID: "wireguard:profile", Installed: true, Selectable: true}, {ID: "nfqws2"}} {
		option := original
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a.prepareManagedNFQRouteOption(ctx, &option)
		if !reflect.DeepEqual(option, original) {
			t.Fatal("foreign/canceled source replaced route", option)
		}
	}
}
