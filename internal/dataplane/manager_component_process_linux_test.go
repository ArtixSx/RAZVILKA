package dataplane

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComponentProcessHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_COMPONENT_PROCESS_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

// Local Linux process test for the coordinator. No ports, network namespaces,
// routes, packages, downloads or engine runtimes are involved.
func TestComponentInstalledExecutableAcceptanceUsesKernelIdentity(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, filepath.Base(executable))
	copyBinary := func() {
		source, err := os.Open(executable)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		dest, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if err != nil {
			t.Fatal(err)
		}
		_, copyErr := io.Copy(dest, source)
		closeErr := dest.Close()
		if copyErr != nil {
			t.Fatal(copyErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	copyBinary()
	config := filepath.Join(root, "config.json")
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAZVILKA_COMPONENT_PROCESS_HELPER", "1")
	spec := ProcessSpec{ID: "component-receipt-test", Binary: binary, Args: []string{"-test.run=^TestComponentProcessHelper$", "--", config}, Dir: root, PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: config, RouteProof: true}
	controller := OSProcessController{}
	if err := controller.Start(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		if err := controller.Stop(ctx, spec); err != nil {
			t.Error(err)
		}
	}()
	if err := verifyInstalledManagedProcess(spec); err != nil {
		t.Fatal("owned current executable rejected", err)
	}
	if err := os.WriteFile(config, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledManagedProcess(spec); err == nil {
		t.Fatal("changed runtime configuration accepted")
	}
	if err := os.WriteFile(config, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(binary, binary+".old"); err != nil {
		t.Fatal(err)
	}
	copyBinary() // Same version text/bytes, a different installed inode.
	if err := verifyInstalledManagedProcess(spec); err == nil {
		t.Fatal("old live executable accepted after package replacement")
	}
}
