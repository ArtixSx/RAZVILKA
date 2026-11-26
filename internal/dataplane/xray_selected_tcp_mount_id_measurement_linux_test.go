//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestXraySelectedTCPMountIDMeasurement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	proc, err := openXraySelectedTCPProc(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer proc.close()
	var actual unix.Statx_t
	if err := unix.Statx(proc.root, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &actual); err != nil || actual.Mask&unix.STATX_MNT_ID == 0 {
		t.Fatal("native statx observation unavailable", err)
	}
	const samples = 1000
	measure := func(read func() (uint64, error)) time.Duration {
		start := time.Now()
		for range samples {
			id, err := read()
			if err != nil || id != proc.mount {
				t.Fatal("held descriptor identity drift", id, proc.mount, err)
			}
		}
		return time.Since(start)
	}
	before := measure(func() (uint64, error) { return proc.mountIDFromFDInfo(ctx, proc.root) })
	after := measure(func() (uint64, error) { return proc.mountID(ctx, proc.root) })
	fallback := measure(func() (uint64, error) { return proc.mountIDAfterStatx(ctx, proc.root, unix.Statx_t{}, unix.ENOSYS) })
	if err := proc.current(ctx); err != nil {
		t.Fatal("closing owner", err)
	}
	t.Logf("same held proc FD mount ID samples=%d fdinfo=%s statx=%s forced-ENOSYS-fdinfo=%s; forced fallback excludes failed syscall overhead; no router or full-workflow latency claim", samples, before, after, fallback)
}
