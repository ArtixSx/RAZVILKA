//go:build linux && (amd64 || arm64)

package components

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func runtimeReadFrameFixture(t *testing.T) (*Manager, *ManagedNFQWSRuntimeLease, ManagedNFQWSBundleReceipt) {
	t.Helper()
	m, _, receipt := runtimeImageFilesystemModel(t)
	lease, err := m.AcquireManagedNFQWSRuntime(context.Background(), receipt.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	return m, lease, receipt
}

func TestManagedRuntimeReadFrameCustodyAndRevocation(t *testing.T) {
	m, lease, receipt := runtimeReadFrameFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var late *ManagedNFQWSRuntimeRead
	var lateCtx context.Context
	var files []*os.File
	var payloads [][]byte
	callbackErr := errors.New("pure reader error")
	began, err := lease.WithReadObservation(ctx, func(c context.Context, v *ManagedNFQWSRuntimeRead) error {
		late, lateCtx = v, c
		image := v.image.(*managedNFQWSHeldReadImage)
		for _, node := range image.nodes {
			files = append(files, node.file)
			payloads = append(payloads, node.content)
		}
		if !v.BoundTo(lease) || v.CompareCurrent(c) != nil {
			t.Fatal("original comparison refused")
		}
		if _, ok := any(v).(interface{ Check(context.Context) error }); ok {
			t.Fatal("view became runtime authority")
		}
		if _, ok := any(v).(interface{ Descriptor() NFQWSRuntimeDescriptor }); ok {
			t.Fatal("view became descriptor authority")
		}
		if v.CompareCurrent(ctx) == nil || v.CompareCurrent(context.WithValue(c, struct{}{}, 1)) == nil {
			t.Fatal("foreign context accepted")
		}
		copyView := &ManagedNFQWSRuntimeRead{self: v, open: true}
		if copyView.CompareCurrent(c) == nil || copyView.BoundTo(lease) {
			t.Fatal("copied comparison accepted")
		}
		if err := lease.Close(); !errors.Is(err, ErrManagedNFQWSReadPending) {
			t.Fatal("read released writer", err)
		}
		if _, err := lease.ForkValidation(c); !errors.Is(err, ErrManagedNFQWSReadPending) {
			t.Fatal("read admitted lifecycle fork", err)
		}
		if next, err := m.AcquireManagedNFQWSRuntime(c, receipt.TransactionID); err == nil {
			next.Close()
			t.Fatal("read lost original writer exclusion")
		}
		called := false
		if nested, err := lease.WithReadObservation(c, func(context.Context, *ManagedNFQWSRuntimeRead) error { called = true; return nil }); nested || err != nil || called {
			t.Fatal("busy frame entered callback", nested, err)
		}
		if err := lease.Check(c); err != nil {
			t.Fatal("busy old full Check path unavailable", err)
		}
		return callbackErr
	})
	if !began || !errors.Is(err, callbackErr) {
		t.Fatal(began, err)
	}
	if late.CompareCurrent(lateCtx) == nil || late.BoundTo(lease) {
		t.Fatal("late view escaped")
	}
	for _, file := range files {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("held FD escaped", err)
		}
	}
	for _, data := range payloads {
		if !bytes.Equal(data, make([]byte, len(data))) {
			t.Fatal("read bytes escaped clearing")
		}
	}
	if lease.owner.readFrame != nil {
		t.Fatal("read token escaped")
	}
	if err := lease.Close(); err != nil {
		t.Fatal("original Close retry refused", err)
	}
}

func TestManagedRuntimeReadFrameRefusesChangedGraphAndOwner(t *testing.T) {
	for _, kind := range []string{"byte-restored-mtime", "replaced-member", "extra-hardlink", "canceled", "owner-receipt"} {
		t.Run(kind, func(t *testing.T) {
			_, lease, receipt := runtimeReadFrameFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := filepath.Join(receipt.GenerationPath, "lua", "zapret-auto.lua")
			oldReceipt := lease.owner.receipt
			began, err := lease.WithReadObservation(ctx, func(c context.Context, v *ManagedNFQWSRuntimeRead) error {
				if err := v.CompareCurrent(c); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "canceled":
					cancel()
				case "owner-receipt":
					lease.owner.mu.Lock()
					lease.owner.receipt.TransactionID = "foreign"
					lease.owner.mu.Unlock()
				case "extra-hardlink":
					if err := os.Link(path, filepath.Join(t.TempDir(), "alias")); err != nil {
						t.Fatal(err)
					}
				case "replaced-member":
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path, path+".prior"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0444); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path + ".prior"); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(filepath.Dir(path), 0555); err != nil {
						t.Fatal(err)
					}
				case "byte-restored-mtime":
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					data[len(data)-1] ^= 1
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0444); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, info.Mode().Perm()); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
				if v.CompareCurrent(c) == nil {
					t.Fatal("changed metadata/owner accepted", kind)
				}
				return nil
			})
			lease.owner.mu.Lock()
			lease.owner.receipt = oldReceipt
			lease.owner.mu.Unlock()
			if !began || err == nil {
				t.Fatal("changed frame succeeded", began, err)
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			if lease.owner.readFrame != nil {
				t.Fatal("failed frame retained token")
			}
		})
	}
}

// Lifecycle-only blocking seam around the real image comparator. The actual
// opening/closing streams and files are unchanged; this models an admitted
// comparison still in flight when its enclosing pure callback returns.
type runtimeReadJoiningImage struct {
	original managedNFQWSRuntimeReadImage
	entered  chan struct{}
	release  chan struct{}
}

func (i *runtimeReadJoiningImage) compare(ctx context.Context) error {
	close(i.entered)
	select {
	case <-i.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return i.original.compare(ctx)
}

func TestManagedRuntimeReadFrameJoinsBeforeClosingDescriptors(t *testing.T) {
	_, lease, _ := runtimeReadFrameFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, release, bodyReturned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	readDone, frameDone := make(chan error, 1), make(chan error, 1)
	var late *ManagedNFQWSRuntimeRead
	var lateCtx context.Context
	go func() {
		_, err := lease.WithReadObservation(ctx, func(c context.Context, v *ManagedNFQWSRuntimeRead) error {
			late, lateCtx = v, c
			v.mu.Lock()
			v.image = &runtimeReadJoiningImage{v.image, entered, release}
			v.mu.Unlock()
			go func() { readDone <- v.CompareCurrent(c) }()
			<-entered
			close(bodyReturned)
			return nil
		})
		frameDone <- err
	}()
	select {
	case <-bodyReturned:
	case <-ctx.Done():
		t.Fatal("comparison did not begin")
	}
	select {
	case err := <-frameDone:
		t.Fatal("unjoined comparison escaped", err)
	default:
	}
	close(release)
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if err := <-frameDone; err != nil {
		t.Fatal(err)
	}
	if late.CompareCurrent(lateCtx) == nil || lease.owner.readFrame != nil {
		t.Fatal("joined view escaped")
	}
}
