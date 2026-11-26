//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func inactiveMountFixture(t testing.TB) *linuxInactiveProcPass {
	t.Helper()
	pass, err := openLinuxInactiveProc(context.Background(), "/proc", os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	p := pass.(*linuxInactiveProcPass)
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestInactiveProcMountIDActualParityAndFallback(t *testing.T) {
	p := inactiveMountFixture(t)
	exe, err := unix.Openat(p.selfDir, "exe", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(exe); err != nil {
			t.Error(err)
		}
	})
	for _, fd := range []int{p.root, p.selfDir, p.fdinfo, p.nsDir, p.nsLink, p.namespace, exe} {
		want, err := p.mountIDFromFDInfo(fd)
		if err != nil || want == "" {
			t.Fatal("original fdinfo", fd, err)
		}
		got, err := p.mountID(fd)
		if err != nil || got != want {
			t.Fatal("actual held descriptor parity", fd, want, got, err)
		}
		for _, cause := range []error{unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL, unix.EPERM, unix.EACCES} {
			got, err := p.mountIDAfterStatx(fd, unix.Statx_t{}, cause)
			if err != nil || got != want {
				t.Fatal("protected fallback", cause, want, got, err)
			}
		}
		got, err = p.mountIDAfterStatx(fd, unix.Statx_t{Mnt_id: 999999}, nil)
		if err != nil || got != want {
			t.Fatal("missing mask bypassed original fdinfo", got, err)
		}
	}
	if err := p.currentRoot(); err != nil {
		t.Fatal("final original root proof", err)
	}
}

func TestInactiveProcMountIDRefusesInvalidAndLostCustody(t *testing.T) {
	p := inactiveMountFixture(t)
	for _, cause := range []error{unix.EIO, unix.EBADF, unix.ENOENT, unix.EFAULT, context.Canceled} {
		if got, err := p.mountIDAfterStatx(p.root, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 7}, cause); err == nil || got != "" {
			t.Fatal("error promoted", cause, got, err)
		}
	}
	if got, err := p.mountIDAfterStatx(p.root, unix.Statx_t{Mask: unix.STATX_MNT_ID}, nil); err == nil || got != "" {
		t.Fatal("zero mount admitted", got, err)
	}
	wide := uint64(1)<<63 | 7
	if got, err := p.mountIDAfterStatx(p.root, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: wide}, nil); err != nil || got != strconv.FormatUint(wide, 10) {
		t.Fatal("mount ID narrowed", got, err)
	}
	copyPass := *p
	if got, err := copyPass.mountID(p.root); err == nil || got != "" {
		t.Fatal("copied owner admitted", got, err)
	}
	if got, err := p.mountID(-1); err == nil || got != "" {
		t.Fatal("negative FD admitted", got, err)
	}
	foreign, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := p.fdinfo
	p.fdinfo = foreign
	for _, cause := range []error{nil, unix.ENOSYS} {
		if got, err := p.mountIDAfterStatx(p.root, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 7}, cause); err == nil || got != "" {
			t.Error("foreign fdinfo custody admitted", got, err)
		}
	}
	p.fdinfo = original
	if err := unix.Close(foreign); err != nil {
		t.Fatal(err)
	}
	p.fdinfo = -1
	for _, cause := range []error{nil, unix.ENOSYS} {
		if got, err := p.mountIDAfterStatx(p.root, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 7}, cause); err == nil || got != "" {
			t.Error("closed fdinfo custody admitted", got, err)
		}
	}
	p.fdinfo = original
	ctx, cancel := context.WithCancel(p.ctx)
	previous := p.ctx
	p.ctx = ctx
	cancel()
	for _, cause := range []error{nil, unix.ENOSYS} {
		if got, err := p.mountIDAfterStatx(p.root, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 7}, cause); !errors.Is(err, context.Canceled) || got != "" {
			t.Error("canceled result", got, err)
		}
	}
	p.ctx = previous
}

func BenchmarkInactiveProcMountIDPair(b *testing.B) {
	p := inactiveMountFixture(b)
	var actual unix.Statx_t
	if err := unix.Statx(p.selfDir, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &actual); err != nil || actual.Mask&unix.STATX_MNT_ID == 0 {
		b.Fatal("this benchmark requires actual STATX_MNT_ID support", err)
	}
	want, err := p.mountIDFromFDInfo(p.selfDir)
	if err != nil {
		b.Fatal(err)
	}
	for _, side := range []struct {
		name string
		read func(int) (string, error)
	}{
		{"original-fdinfo", p.mountIDFromFDInfo}, {"fresh-statx", p.mountID},
		{"fallback-handler-only", func(fd int) (string, error) { return p.mountIDAfterStatx(fd, unix.Statx_t{}, unix.ENOSYS) }},
	} {
		b.Run(side.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got, err := side.read(p.selfDir); err != nil || got != want {
					b.Fatal("fresh ID changed", got, want, err)
				}
			}
		})
	}
	if err := p.currentRoot(); err != nil {
		b.Fatal(err)
	}
}

// Reuse the exact descriptor number for a different held filesystem. Both
// readers must observe its fresh mount; an FD-number cache would fail here.
func TestInactiveProcMountIDDescriptorReuse(t *testing.T) {
	p := inactiveMountFixture(t)
	fd, err := unix.Dup(p.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Error(err)
		}
	})
	first, err := p.mountID(fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup3(p.namespace, fd, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	second, err := p.mountID(fd)
	if err != nil || second == first {
		t.Fatal("reused FD retained old mount", first, second, err)
	}
	fallback, err := p.mountIDAfterStatx(fd, unix.Statx_t{}, unix.ENOSYS)
	if err != nil || fallback != second {
		t.Fatal("reused FD fallback", fallback, second, err)
	}
	if err := unix.Dup3(p.root, fd, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	restored, err := p.mountID(fd)
	if err != nil || restored != first {
		t.Fatal("restored descriptor", first, restored, err)
	}
}
