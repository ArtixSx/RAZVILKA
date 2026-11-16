//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package components

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

// Actual original descriptor streams; only file payloads/install authority are
// the existing explicit model. No process or native route proof is claimed.
func TestManagedRuntimeReadFrameOriginalStreamsAndAbnormalExit(t *testing.T) {
	for _, kind := range []string{"success", "error", "panic", "goexit", "full-check"} {
		t.Run(kind, func(t *testing.T) {
			manager, lease, receipt := runtimeReadFrameFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			before, bytesBefore := NativeFixtureManagedNFQWSPayloadReads(manager)
			framesBefore := NativeFixtureManagedNFQWSRuntimeFrames(manager)
			cut := errors.New("read callback cut")
			var result error
			var caught any
			var began, returned bool
			var files []*os.File
			var payloads [][]byte
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { caught = recover() }()
				began, result = lease.WithReadObservation(ctx, func(c context.Context, v *ManagedNFQWSRuntimeRead) error {
					for _, node := range v.image.(*managedNFQWSHeldReadImage).nodes {
						files = append(files, node.file)
						payloads = append(payloads, node.content)
					}
					if err := lease.Close(); !errors.Is(err, ErrManagedNFQWSReadPending) {
						t.Error("borrow failed to retain original writer", err)
					}
					count, _ := NativeFixtureManagedNFQWSPayloadReads(manager)
					if count-before != 6 {
						t.Errorf("opening complete six-member stream missing: %d", count-before)
					}
					for i := 0; i < 2; i++ {
						if err := v.CompareCurrent(c); err != nil {
							return err
						}
					}
					afterCompare, _ := NativeFixtureManagedNFQWSPayloadReads(manager)
					if afterCompare != count {
						t.Error("comparison reopened payloads")
					}
					switch kind {
					case "error":
						return cut
					case "panic":
						panic(cut)
					case "goexit":
						runtime.Goexit()
					case "full-check":
						return lease.Check(c)
					}
					return nil
				})
				returned = true
			}()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("original read did not unwind")
			}
			after, bytesAfter := NativeFixtureManagedNFQWSPayloadReads(manager)
			wanted := uint64(12)
			if kind == "full-check" {
				wanted = 24
			}
			if after-before != wanted || bytesAfter <= bytesBefore {
				t.Fatal("original closing stream omitted", kind, after-before, wanted)
			}
			if kind == "panic" {
				if caught != cut || returned {
					t.Fatal("panic changed", caught, returned)
				}
			} else if kind == "goexit" {
				if returned || caught != nil {
					t.Fatal("Goexit changed")
				}
			} else if !began || !returned {
				t.Fatal("read never began")
			}
			if kind == "error" {
				if !errors.Is(result, cut) {
					t.Fatal(result)
				}
			} else if returned && result != nil {
				t.Fatal(result)
			}
			if lease.owner.readFrame != nil {
				t.Fatal("abnormal exit retained writer borrow")
			}
			for _, file := range files {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("abnormal exit retained FD", err)
				}
			}
			for _, data := range payloads {
				if !bytes.Equal(data, make([]byte, len(data))) {
					t.Fatal("abnormal exit retained bytes")
				}
			}
			framesAfter := NativeFixtureManagedNFQWSRuntimeFrames(manager)
			wantedFrames := [3]uint64{1, 0, 1}
			if kind == "success" || kind == "full-check" {
				wantedFrames = [3]uint64{1, 1, 0}
			}
			for i := range framesAfter {
				if framesAfter[i] < framesBefore[i] || framesAfter[i]-framesBefore[i] != wantedFrames[i] {
					t.Fatal("invalid native frame outcomes", framesBefore, framesAfter)
				}
			}
			if err := lease.Close(); err != nil {
				t.Fatal("same original writer could not retire", err)
			}
			next, err := manager.AcquireManagedNFQWSRuntime(ctx, receipt.TransactionID)
			if err != nil {
				t.Fatal("closed reader blocked next original writer", err)
			}
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
