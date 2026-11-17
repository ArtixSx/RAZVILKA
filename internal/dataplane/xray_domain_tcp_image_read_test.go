package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestXrayImageScopeScratchExclusiveFixedAndCleared(t *testing.T) {
	var scratch xrayDomainTCPImageScratch
	if scratch.borrow(0) != nil || scratch.borrow(xrayDomainTCPImageScratchLimit+1) != nil {
		t.Fatal("invalid memory budget admitted")
	}
	first := scratch.borrow(41)
	if first == nil || scratch.borrow(1) != nil {
		t.Fatal("exclusive nonwaiting slot not enforced")
	}
	copy(first.data, bytes.Repeat([]byte{0x7f}, len(first.data)))
	copied := &xrayDomainTCPImageLease{self: first, scratch: first.scratch, data: first.data}
	first.release()
	if scratch.borrow(42) != nil || scratch.busy.Load() {
		t.Fatal("first allocation resized or oversize refusal held slot")
	}
	second := scratch.borrow(17)
	if second == nil || !bytes.Equal(scratch.data, make([]byte, 41)) {
		t.Fatal("released backing bytes survived")
	}
	first.release()
	copy(second.data, bytes.Repeat([]byte{0x3a}, len(second.data)))
	copied.release()
	if !scratch.busy.Load() {
		t.Fatal("stale release revoked a newer borrower")
	}
	if !bytes.Equal(second.data, bytes.Repeat([]byte{0x3a}, len(second.data))) {
		t.Fatal("copied lease cleared a newer borrower")
	}
	second.release()
}

func TestXrayImageScopeConcurrentScratchHasOneBorrower(t *testing.T) {
	var scratch xrayDomainTCPImageScratch
	start, release := make(chan struct{}), make(chan struct{})
	results := make(chan bool, 16)
	var joined sync.WaitGroup
	for range 16 {
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-start
			lease := scratch.borrow(31)
			results <- lease != nil
			if lease != nil {
				copy(lease.data, bytes.Repeat([]byte{0x7f}, len(lease.data)))
				<-release
				lease.release()
			}
		}()
	}
	close(start)
	winners := 0
	for range 16 {
		if <-results {
			winners++
		}
	}
	close(release)
	joined.Wait()
	if winners != 1 || scratch.busy.Load() || !bytes.Equal(scratch.data, make([]byte, 31)) {
		t.Fatal("concurrent storage ownership/clearing failed", winners)
	}
}

func xrayImageScopeReleased(t *testing.T, size int64) {
	t.Helper()
	if domainTCPImageScratch.busy.Load() {
		t.Fatal("image slot retained after joined scope")
	}
	lease := domainTCPImageScratch.borrow(size)
	if lease == nil {
		t.Fatal("test image no longer fits first fixed capacity")
	}
	defer lease.release()
	if !bytes.Equal(lease.data, make([]byte, len(lease.data))) {
		t.Fatal("private bytes escaped clear")
	}
}

func TestXrayImageScopeOriginalClosingAndEscapes(t *testing.T) {
	for _, mode := range []string{"clean", "mutation", "replacement", "panic", "cancel", "capture-failure", "contention"} {
		t.Run(mode, func(t *testing.T) {
			r, ctx := domainFileObservationModel(t)
			active, cancel := context.WithCancel(ctx)
			defer cancel()
			var held *xrayDomainTCPImageLease
			if mode == "contention" {
				held = domainTCPImageScratch.borrow(r.executable.info.Size())
				if held == nil {
					t.Fatal("could not occupy private slot")
				}
			}
			if mode == "capture-failure" {
				r.executable.sha256 = "invalid expected SHA"
			}
			var view *xrayDomainTCPFileObservation
			called := false
			var result error
			panicked := false
			func() {
				defer func() { panicked = recover() != nil }()
				result = r.withFileObservation(active, func(v *xrayDomainTCPFileObservation) error {
					called, view = true, v
					if !domainTCPImageScratch.busy.Load() {
						t.Fatal("actual outer image slot not entered")
					}
					switch mode {
					case "mutation":
						file, err := os.OpenFile(r.executable.path, os.O_WRONLY, 0)
						if err != nil {
							return err
						}
						_, writeErr := file.WriteAt([]byte{0xff}, 0)
						return errors.Join(writeErr, file.Close(), os.Chtimes(r.executable.path, r.executable.info.ModTime(), r.executable.info.ModTime()))
					case "replacement":
						if err := os.WriteFile(r.executable.path+".new", []byte("replacement"), 0700); err != nil {
							return err
						}
						return os.Rename(r.executable.path+".new", r.executable.path)
					case "panic":
						panic("private observation test")
					case "cancel":
						cancel()
					}
					return r.filesCurrentForObservation(active, v)
				})
			}()
			if held != nil {
				if !domainTCPImageScratch.busy.Load() {
					t.Fatal("fallback released another borrower's slot")
				}
				held.release()
			}
			if called != (mode != "capture-failure") || panicked != (mode == "panic") {
				t.Fatal("attempted capture failure fell back or panic changed", called, panicked)
			}
			if (mode == "clean" || mode == "contention") != (result == nil) && mode != "panic" {
				t.Fatal("source refusal changed", mode, result)
			}
			if mode == "cancel" && !errors.Is(result, context.Canceled) {
				t.Fatal("cancellation cause lost", result)
			}
			if view != nil && (view.open.Load() || view.current(active, r) == nil) {
				t.Fatal("escaped file view accepted after image release")
			}
			xrayImageScopeReleased(t, r.executable.info.Size())
		})
	}
}

func TestXrayImageScopeForeignStaleAndConsumedOpening(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	image := r.borrowFileObservationImage(ctx)
	if image == nil {
		t.Fatal("image borrow missing")
	}
	t.Cleanup(image.release)
	copied := &xrayDomainTCPImageRead{self: image, lease: image.lease}
	copied.release()
	if image.lease.closed.Load() {
		t.Fatal("copied image released original storage")
	}
	if err := r.filesCurrentForImageRead(ctx, nil, image); err != nil {
		image.release()
		t.Fatal(err)
	}
	foreign := &XrayDomainTCPExecutionResource{executable: r.executable}
	foreign.self = foreign
	if image.belongsTo(foreign) || foreign.filesCurrentForImageRead(ctx, nil, image) == nil {
		t.Fatal("image crossed original resource")
	}
	derived := context.WithValue(ctx, struct{}{}, true)
	called := false
	if err := r.withFileObservationAfterOpeningImage(derived, nil, func(*xrayDomainTCPFileObservation) error { called = true; return nil }, image); err == nil || called {
		t.Fatal("foreign captured context reached callback", err)
	}
	if image.current(derived) == nil {
		t.Fatal("image crossed original context")
	}
	if err := r.filesCurrentForImageRead(ctx, nil, image); err != nil {
		t.Fatal("original closing refused", err)
	}
	if image.current(ctx) == nil {
		t.Fatal("completed closing reused")
	}
	image.release()
	if image.current(ctx) == nil || image.belongsTo(r) {
		t.Fatal("released image reused")
	}
	// Existing already-opened/handoff path has no image, even if storage is free.
	if err := r.filesCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.withFileObservationAfterOpening(ctx, nil, func(v *xrayDomainTCPFileObservation) error {
		if domainTCPImageScratch.busy.Load() {
			t.Fatal("existing opening handoff acquired new image")
		}
		return v.current(ctx, r)
	}); err != nil {
		t.Fatal(err)
	}
	xrayImageScopeReleased(t, r.executable.info.Size())
}

type xrayImageScopeReadTicks struct {
	context.Context
	ticks, cancelAt int
}

func (c *xrayImageScopeReadTicks) Err() error {
	c.ticks++
	if c.cancelAt > 0 && c.ticks >= c.cancelAt {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestXrayImageScopeProductionClosingReadsPastMismatch(t *testing.T) {
	for _, cancelLater := range []bool{false, true} {
		r, parent := domainFileObservationModel(t)
		ctx := &xrayImageScopeReadTicks{Context: parent}
		data := bytes.Repeat([]byte{0x5a}, (96<<10)+1)
		path := r.rootPath + "/larger-image"
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { file.Close() })
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		p := &xrayDomainTCPExecutable{file: file, info: info, path: path, sha256: nodeDefaultSourceMaterialHash(data)}
		r.executable = p
		var scratch xrayDomainTCPImageScratch
		lease := scratch.borrow(info.Size())
		if lease == nil {
			t.Fatal("local production storage unavailable")
		}
		deadline, _ := ctx.Deadline()
		// Actual held file protocol only: this fixture issues no native child or
		// execution authority. Local scratch avoids priming the process singleton.
		image := &xrayDomainTCPImageRead{resource: r, executable: p, file: file, info: info, path: path, hash: p.sha256, ctx: ctx, deadline: deadline, lease: lease}
		image.self = image
		t.Cleanup(image.release)
		if err := image.current(ctx); err != nil {
			t.Fatal("production fresh capture", err)
		}
		if _, err := file.WriteAt([]byte{0xff}, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
		ctx.ticks = 0
		if cancelLater {
			ctx.cancelAt = 7 // Entry + two metadata ticks + two actual reads.
		}
		err = image.current(ctx)
		if err == nil || image.phase.Load() != 4 {
			t.Fatal("same-size changed bytes accepted or capture retained", err)
		}
		if cancelLater {
			if ctx.ticks < ctx.cancelAt || !errors.Is(err, context.Canceled) {
				t.Fatal("first-byte mismatch skipped the later read/cancel boundary", ctx.ticks, err)
			}
		} else {
			// One entry + two opening metadata + two per32KiB actual read +
			// two closing metadata + one final context tick. This is the actual
			// production loop, not the independent measurement implementation.
			if want := 6 + 2*int((info.Size()+(32<<10)-1)/(32<<10)); ctx.ticks != want {
				t.Fatal("mismatch did not complete every original read/closing check", ctx.ticks, want)
			}
		}
		image.release()
		if scratch.busy.Load() || !bytes.Equal(scratch.data, make([]byte, len(data))) {
			t.Fatal("production read failure retained private image")
		}
	}
}

type xrayImageScopeAfterClearContext struct {
	context.Context
	after bool
}

func (c *xrayImageScopeAfterClearContext) Err() error {
	if c.after && !domainTCPImageScratch.busy.Load() {
		return context.Canceled
	}
	return c.Context.Err()
}

type xrayImageScopeAbsoluteContext struct {
	context.Context
	deadline time.Time
}

func (c *xrayImageScopeAbsoluteContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestXrayImageScopePostClearCancellationAndAbsoluteDeadline(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	after := &xrayImageScopeAfterClearContext{Context: ctx}
	if err := r.withFileObservation(after, func(*xrayDomainTCPFileObservation) error { after.after = true; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation after clear accepted", err)
	}
	xrayImageScopeReleased(t, r.executable.info.Size())
	absolute := &xrayImageScopeAbsoluteContext{Context: context.Background(), deadline: time.Now().Add(20 * time.Millisecond)}
	if err := r.withFileObservation(absolute, func(*xrayDomainTCPFileObservation) error {
		time.Sleep(time.Until(absolute.deadline) + time.Millisecond)
		return nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired absolute deadline accepted despite nil Err", err)
	}
	xrayImageScopeReleased(t, r.executable.info.Size())
}
