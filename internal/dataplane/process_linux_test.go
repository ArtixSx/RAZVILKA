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

// A separate test process sleeps without network/filesystem mutations. Its
// config argument lets the normal controller identify only this child.
func TestManagedIdentityHelper(t *testing.T) {
	args := os.Args
	if len(args) < 2 || args[len(args)-2] != "--identity-helper" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestManagedProcessCreatesAndInvalidatesReceipt(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "engine.json")
	if err := os.WriteFile(config, []byte(`{"test":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	spec := ProcessSpec{ID: "identity-test", Binary: binary, Args: []string{"-test.run=^TestManagedIdentityHelper$", "--", "--identity-helper", config}, Dir: root, PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: true}
	controller := OSProcessController{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controller.Start(ctx, spec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 6*time.Second)
		defer stop()
		_ = controller.Stop(cleanup, spec)
	})
	if info, err := os.Stat(spec.PIDPath + routeidentity.ReceiptSuffix); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt permissions: %v %v", info, err)
	}
	if !controller.Running(spec) {
		t.Fatal("managed child not running")
	}
	if err := controller.Stop(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(spec.PIDPath + routeidentity.ReceiptSuffix); !os.IsNotExist(err) {
		t.Fatalf("stopped receipt remained: %v", err)
	}
}
