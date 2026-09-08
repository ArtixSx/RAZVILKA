package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNodeStoreFollowsConfigAndDoesNotCreateNodeFile(t *testing.T) {
	root := t.TempDir()
	store, err := openNodeStore(filepath.Join(root, "candidate.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "nodes-private")
	markers, err := filepath.Glob(filepath.Join(directory, ".state-*.lock"))
	if err != nil || len(markers) != 1 {
		t.Fatal("node writer protocol marker missing")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "nodes.private.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup created an empty private node document")
	}
	if _, err := os.Stat(markers[0]); err != nil {
		t.Fatal("node writer protocol marker was removed")
	}
}

func TestNodeStoreRefusesUnsafeRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openNodeStore(filepath.Join(root, "config.json"), file); err == nil {
		t.Fatal("file accepted as node store directory")
	}
	if runtime.GOOS != "windows" {
		public := filepath.Join(root, "public")
		if err := os.Mkdir(public, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := openNodeStore(filepath.Join(root, "config.json"), public); err == nil {
			t.Fatal("public node store directory accepted")
		}
	}
}

func TestDualRecoveryUsesIndependentLifetimeLeases(t *testing.T) {
	root := t.TempDir()
	args := []string{filepath.Join(root, "config"), filepath.Join(root, "custom"), filepath.Join(root, "devices"), filepath.Join(root, "stage"), filepath.Join(root, "provider"), filepath.Join(root, "nodes")}
	legacy, current, _, _, err := preparePrivateRecoveries(args[0], args[1], args[2], args[3], args[4], args[5])
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	defer current.Close()
	if competing, _, err := preparePrivateRecovery(args[0], args[1], args[2], args[3], args[4]); err == nil {
		competing.Close()
		t.Fatal("legacy recovery lease was released")
	}
	if competing, _, err := prepareNodePrivateRecovery(args[0], args[1], args[2], args[3], args[4], args[5]); err == nil {
		competing.Close()
		t.Fatal("node recovery lease was released")
	}
}

func TestNativeRecoveryKeepsBothPreviousProtocolLeases(t *testing.T) {
	root := t.TempDir()
	args := []string{filepath.Join(root, "config"), filepath.Join(root, "custom"), filepath.Join(root, "devices"), filepath.Join(root, "stage"), filepath.Join(root, "provider"), filepath.Join(root, "nodes"), filepath.Join(root, "warp")}
	older, current, _, _, err := preparePrivateRecoveries(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
	if err != nil {
		t.Fatal(err)
	}
	defer older.Close()
	defer current.Close()
	if next, _, err := preparePrivateRecovery(args[0], args[1], args[2], args[3], args[4]); err == nil {
		next.Close()
		t.Fatal("legacy protocol lease released")
	}
	if next, _, err := prepareNodePrivateRecovery(args[0], args[1], args[2], args[3], args[4], args[5]); err == nil {
		next.Close()
		t.Fatal("node protocol lease released")
	}
	if _, err := os.Stat(args[6]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("clean native recovery created enrollment store")
	}
}
