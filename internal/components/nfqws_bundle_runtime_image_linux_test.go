//go:build linux && (amd64 || arm64)

package components

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// Actual file descriptors, journal publication, modes and Linux metadata;
// payload/authority are explicitly the existing bundle MODEL, not a native
// runtime, validation grant or stock-router acceptance.
func runtimeImageFilesystemModel(t *testing.T) (*Manager, ManagedNFQWSManifest, ManagedNFQWSBundleReceipt) {
	t.Helper()
	manifest, input, _ := bundleFixtureManifest(t, "runtime-image-model")
	m := bundleFixtureManager(t, input)
	receipt, err := m.InstallManagedBundle(context.Background(), manifest, 7, bundleFixtureAuthority())
	if err != nil {
		t.Fatal(err)
	}
	return m, manifest, receipt
}

func TestManagedNFQWSRuntimeImageSecondReadPreservesByteAndEOFFences(t *testing.T) {
	for _, kind := range []string{"unchanged", "changed-byte-restored-mtime", "extra-byte", "truncated", "closed-fd", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "original-payload")
			expected := bytes.Repeat([]byte("actual original bounded payload\n"), 3500)
			if err := os.WriteFile(path, expected, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "changed-byte-restored-mtime":
				changed := bytes.Clone(expected)
				changed[(32<<10)+1] ^= 1
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "extra-byte":
				appendFile, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := appendFile.Write([]byte{0})
				if err := errors.Join(writeErr, appendFile.Close()); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(path, int64(len(expected)-1)); err != nil {
					t.Fatal(err)
				}
			case "closed-fd":
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			count, err := managedRuntimeImageCompare(ctx, file, expected, make([]byte, 32<<10))
			if kind == "unchanged" {
				if err != nil || count != int64(len(expected)) {
					t.Fatal("full second read or EOF changed", count, err)
				}
			} else if kind == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("original cancellation lost", err)
				}
			} else if !errors.Is(err, ErrManagedNFQWSBundle) {
				t.Fatal("changed bytes accepted independent of metadata", kind, count, err)
			}
		})
	}
}

func runtimeImageClosingModel(t *testing.T, manifest ManagedNFQWSManifest, path string) (*os.Root, os.FileInfo, []*managedRuntimeImageNode) {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	anchor, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{".", "bin", "lua", "blobs", "manifest.json", "source-notices.json"}
	for _, member := range manifest.Members {
		names = append(names, filepath.FromSlash(member.Destination))
	}
	var nodes []*managedRuntimeImageNode
	for _, name := range names {
		file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		node := &managedRuntimeImageNode{name: name, file: file, info: info}
		if info.IsDir() {
			node.entries, err = managedRuntimeImageEntries(file)
			if err != nil {
				t.Fatal(err)
			}
		}
		nodes = append(nodes, node)
	}
	return root, anchor, nodes
}

func TestManagedNFQWSRuntimeImagePreservesOriginalLeaseAndDefaultVerifier(t *testing.T) {
	m, expected, receipt := runtimeImageFilesystemModel(t)
	lease, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := m.verifyManagedNFQWSRuntimeImage(context.Background(), receipt.GenerationPath, receipt.ManifestSHA256)
	if err != nil || !reflect.DeepEqual(current, expected) {
		t.Fatal("runtime image changed", current, err)
	}
	legacy, err := m.verifyManagedNFQWSTerminal(context.Background(), receipt)
	if err != nil || !reflect.DeepEqual(legacy, current) {
		t.Fatal("default installer/recovery verifier diverged", err)
	}
	if _, err := m.UpdateManagedBundle(context.Background(), expected, 7, bundleFixtureAuthority()); err == nil {
		t.Fatal("read observation released original writer lease")
	}
}

func TestManagedNFQWSRuntimeImageClosingRefusesActualSourceDrift(t *testing.T) {
	for _, kind := range []string{"same-bytes-restored-mtime", "same-bytes-replaced-inode", "extra-member", "named-root-replaced", "closed-original-fd", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			m, manifest, receipt := runtimeImageFilesystemModel(t)
			root, anchor, nodes := runtimeImageClosingModel(t, manifest, receipt.GenerationPath)
			if err := m.managedRuntimeImageClosing(context.Background(), root, receipt.GenerationPath, anchor, nodes); err != nil {
				t.Fatal("original graph not current", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			binary := filepath.Join(receipt.GenerationPath, "bin", "rzv-nfqws2")
			switch kind {
			case "same-bytes-restored-mtime":
				info, err := os.Stat(binary)
				if err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(binary, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(binary, data, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(binary, 0555); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(binary, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "same-bytes-replaced-inode":
				data, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Dir(binary), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(binary, filepath.Join(filepath.Dir(receipt.GenerationPath), "model-original-binary")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(binary, data, 0555); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Dir(binary), 0555); err != nil {
					t.Fatal(err)
				}
			case "extra-member":
				dir := filepath.Join(receipt.GenerationPath, "lua")
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "foreign.lua"), []byte("not an accepted member"), 0444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dir, 0555); err != nil {
					t.Fatal(err)
				}
			case "named-root-replaced":
				if err := os.Rename(receipt.GenerationPath, receipt.GenerationPath+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(receipt.GenerationPath, 0555); err != nil {
					t.Fatal(err)
				}
			case "closed-original-fd":
				if err := nodes[len(nodes)-1].file.Close(); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			if err := m.managedRuntimeImageClosing(ctx, root, receipt.GenerationPath, anchor, nodes); err == nil {
				t.Fatal("changed original graph accepted")
			}
		})
	}
}

func TestManagedNFQWSRuntimeImageRefusesFIFOAndSymlinkWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			m, _, receipt := runtimeImageFilesystemModel(t)
			path := filepath.Join(receipt.GenerationPath, "lua", "zapret-auto.lua")
			if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "fifo" {
				err = syscall.Mkfifo(path, 0444)
			} else {
				err = os.Symlink("zapret-lib.lua", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(path), 0555); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				_, err := m.verifyManagedNFQWSRuntimeImage(ctx, receipt.GenerationPath, receipt.ManifestSHA256)
				finished <- err
			}()
			select {
			case err := <-finished:
				if !errors.Is(err, ErrManagedNFQWSBundle) {
					t.Fatal("nonregular source not refused", err)
				}
			case <-ctx.Done():
				t.Fatal("nonregular open blocked instead of refusing")
			}
		})
	}
}
