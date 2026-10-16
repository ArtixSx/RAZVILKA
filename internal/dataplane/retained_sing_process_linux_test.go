//go:build linux

package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Local child process only: no engines, ports, routing, namespaces, packages or
// router access. This checks the actual /proc observer, not a native dataplane.
func TestRetainedSingActualProcessIdentityAndLegacySidecarWithoutReceipt(t *testing.T) {
	for _, launchReceipt := range []bool{false, true} {
		name := "legacy-sidecar"
		if launchReceipt {
			name = "engine-launch-receipt"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			config := filepath.Join(root, "engine.json")
			if err := os.WriteFile(config, []byte(`{"test":true}`), 0600); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			spec := ProcessSpec{ID: "retained-sing-test", Binary: binary,
				Args: []string{"-test.run=^TestManagedIdentityHelper$", "--", "--identity-helper", config}, Dir: root,
				PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: launchReceipt}
			controller := OSProcessController{}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := controller.Start(ctx, spec); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				if err := controller.Stop(cleanup, spec); err != nil {
					t.Error(err)
				}
			})
			first, err := retainedSingProcessIdentity(spec)
			if err != nil || first.identity.PID <= 1 || first.executable == nil {
				t.Fatal("actual child refused", err)
			}
			if namespace, err := retainedSingNamespace(spec); err != nil || namespace == "" {
				t.Fatal("actual namespace refused", err)
			}
			second, err := retainedSingProcessIdentity(spec)
			if err != nil || first.identity != second.identity || !os.SameFile(first.executable, second.executable) {
				t.Fatal("unchanged child drifted", err)
			}
			if !launchReceipt {
				if _, err := os.Lstat(spec.PIDPath + routeidentity.ReceiptSuffix); !os.IsNotExist(err) {
					t.Fatal("reader invented a legacy sidecar launch receipt", err)
				}
				strict := spec
				strict.RouteProof = true
				if _, err := retainedSingProcessIdentity(strict); err == nil {
					t.Fatal("missing engine launch receipt accepted")
				}
			}
			wrong := spec
			wrong.Args = append(append([]string{}, spec.Args...), "unbound")
			if _, err := retainedSingProcessIdentity(wrong); err == nil {
				t.Fatal("unknown argv accepted")
			}
			if err := os.WriteFile(config, []byte(`{"test":"changed"}`), 0600); err != nil {
				t.Fatal(err)
			}
			changed, err := retainedSingProcessIdentity(spec)
			if launchReceipt && err == nil || !launchReceipt && (err != nil || changed.identity.ConfigHash == first.identity.ConfigHash) {
				t.Fatal("config drift was invisible", err)
			}
			if err := os.WriteFile(config, make([]byte, (8<<20)+1), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := retainedSingProcessIdentity(spec); err == nil {
				t.Fatal("oversized config accepted")
			}
			if err := os.WriteFile(config, []byte(`{"test":true}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := controller.Stop(ctx, spec); err != nil {
				t.Fatal(err)
			}
			if _, err := retainedSingProcessIdentity(spec); err == nil {
				t.Fatal("dead original process accepted")
			}
		})
	}
}
