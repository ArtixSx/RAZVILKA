package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestNFQWSOwnedPackageMutationRefusesBeforeCommands(t *testing.T) {
	for _, variant := range []string{"owned", "malformed"} {
		for _, action := range []string{"install", "update", "remove", "recommended", "late-command", "journal-rollback"} {
			t.Run(variant+"/"+action, func(t *testing.T) {
				m, runner, _, _ := stockNativeFixture(t)
				path := filepath.Join(m.InitDir, "S51nfqws2")
				stock, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data, err := engineconfig.NFQWSFirstStartInit(stock, "0123456789abcdef01234567")
				if err != nil {
					t.Fatal(err)
				}
				want := ErrNFQWSOwnedPackageMutation
				if variant == "malformed" {
					data = append(data, []byte("echo foreign\n")...)
					want = ErrNFQWSPackageOwnershipUnknown
				}
				if err := os.WriteFile(path, data, 0755); err != nil {
					t.Fatal(err)
				}
				switch action {
				case "install":
					_, err = m.Apply(context.Background(), "nfqws2")
				case "update":
					_, err = m.ManagedUpdateGuarded(context.Background(), "nfqws2", func(context.Context) error { t.Fatal("candidate ran"); return nil }, nil)
				case "remove":
					_, err = m.Remove(context.Background(), "nfqws2")
				case "recommended":
					// Cancel unrelated recommendations. NFQ must still report the
					// ownership refusal on the actual CLI batch entry point.
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					report := m.InstallRecommended(ctx)
					if report.OK || !strings.Contains(strings.Join(report.Errors, "\n"), want.Error()) {
						t.Fatalf("batch=%+v", report)
					}
					return
				case "late-command":
					_, err = m.run(context.Background(), "install", "nfqws2-keenetic")
				case "journal-rollback":
					tx := &updateTransaction{manager: m}
					tx.doc.Component = "nfqws2"
					_, err = tx.runPackage(context.Background(), "rollback", "install", "--force-reinstall", "old.ipk")
				}
				if !errors.Is(err, want) {
					t.Fatal("wrong refusal", err)
				}
				if runner.calls != 0 {
					t.Fatalf("refused operation executed %d commands", runner.calls)
				}
			})
		}
	}
}

func TestNFQWSUnownedPackageStillRemovable(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"list-installed": "nfqws2-keenetic - 1.3.1\n", "remove": "removed"}}
	m := &Manager{Opkg: "opkg", Runner: r, InitDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(m.InitDir, "S51nfqws2"), []byte("#!/bin/sh\necho ordinary package\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if result, err := m.Remove(context.Background(), "nfqws2"); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	found := false
	for _, call := range r.calls {
		if len(call) > 1 && call[1] == "remove" {
			found = true
		}
	}
	if !found {
		t.Fatal("ordinary package removal never reached runner")
	}
}
