//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package netidentity

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProcMountIDNativeMeasurement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a := mountIDAuditFixture(t, ctx)
	var stat unix.Statx_t
	if err := unix.Statx(a.root.fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat); err != nil || stat.Mask&unix.STATX_MNT_ID == 0 {
		t.Fatal("native statx unavailable", err)
	}
	const samples = 1000
	measure := func(read func() (uint64, bool)) time.Duration {
		start := time.Now()
		for range samples {
			if id, ok := read(); !ok || id != stat.Mnt_id {
				t.Fatal("held mount changed", id, ok)
			}
		}
		return time.Since(start)
	}
	before := measure(func() (uint64, bool) { return a.mountIDFromFDInfo(a.root.fd) })
	after := measure(func() (uint64, bool) { return a.mountID(a.root.fd) })
	fallback := measure(func() (uint64, bool) { return a.mountIDAfterStatx(a.root.fd, unix.Statx_t{}, unix.ENOSYS) })
	if !a.stable() || !a.mountsMatch(stat.Mnt_id) {
		t.Fatal("closing audit")
	}
	t.Logf("netidentity same held proc FD mount ID samples=%d fdinfo=%s statx=%s forced-ENOSYS-fdinfo=%s; forced fallback excludes failed syscall overhead; no router or full-workflow latency claim", samples, before, after, fallback)
}
