//go:build linux && (amd64 || arm64)

package netidentity

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func mountIDAuditFixture(t *testing.T, ctx context.Context) *audit {
	t.Helper()
	a := &audit{ctx: ctx, fdinfo: -1}
	t.Cleanup(a.close)
	fd, err := syscall.Open("/proc", dirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := a.take(fd, true, false)
	if !ok || root.stat.Ino != 1 {
		t.Fatal("original proc root unavailable")
	}
	a.root = root
	pid, ok := a.openDir(root.fd, strconv.Itoa(os.Getpid()))
	if !ok {
		t.Fatal("original process directory unavailable")
	}
	a.fdinfo, ok = a.openDir(pid, "fdinfo")
	if !ok {
		t.Fatal("original fdinfo directory unavailable")
	}
	return a
}

func TestProcMountIDActualParityAndFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := mountIDAuditFixture(t, ctx)
	for _, held := range a.fds {
		want, ok := a.mountIDFromFDInfo(held.fd)
		if !ok || want == 0 {
			t.Fatal("original fdinfo unavailable")
		}
		if got, ok := a.mountID(held.fd); !ok || got != want {
			t.Fatal("same held mount changed", got, want, ok)
		}
		for _, unsupported := range []error{unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL, unix.EPERM, unix.EACCES} {
			if got, ok := a.mountIDAfterStatx(held.fd, unix.Statx_t{}, unsupported); !ok || got != want {
				t.Fatal("fallback did not observe original", unsupported, got, want, ok)
			}
		}
		if got, ok := a.mountIDAfterStatx(held.fd, unix.Statx_t{Mnt_id: want + 1}, nil); !ok || got != want {
			t.Fatal("unsupported field used dummy mount ID")
		}
	}
	root, ok := a.mountID(a.root.fd)
	if !ok || !a.stable() || !a.mountsMatch(root) {
		t.Fatal("actual original audit bookends failed")
	}
	original := a.fdinfo
	a.fdinfo = -1
	if got, ok := a.mountIDAfterStatx(a.root.fd, unix.Statx_t{}, unix.ENOSYS); ok || got != 0 {
		t.Fatal("failed original reader produced success")
	}
	a.fdinfo = original
}

func TestProcMountIDRejectsMalformedResultAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a := &audit{ctx: ctx, fdinfo: -1}
	for _, cause := range []error{unix.EBADF, unix.EIO, unix.EFAULT, unix.ENOENT} {
		if got, ok := a.mountIDAfterStatx(3, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 73}, cause); ok || got != 0 {
			t.Fatal("error adopted ID", cause)
		}
	}
	if got, ok := a.mountIDAfterStatx(3, unix.Statx_t{Mask: unix.STATX_MNT_ID}, nil); ok || got != 0 {
		t.Fatal("zero ID adopted")
	}
	const wide = uint64(1)<<40 | 73
	if got, ok := a.mountIDAfterStatx(3, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: wide}, nil); !ok || got != wide {
		t.Fatal("ID truncated")
	}
	if got, ok := a.mountID(-1); ok || got != 0 {
		t.Fatal("invalid descriptor adopted")
	}
	cancel()
	if got, ok := a.mountID(3); ok || got != 0 {
		t.Fatal("cancel before syscall accepted")
	}
	if got, ok := a.mountIDAfterStatx(3, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: wide}, nil); ok || got != 0 {
		t.Fatal("cancel after syscall accepted")
	}
}

func TestProcMountIDNativeClosingRejectsSameInodeBind(t *testing.T) {
	if os.Getenv("RAZVILKA_NETIDENTITY_MOUNT_ID_NATIVE") != "1" {
		t.Skip("opt-in disposable mount namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if os.Getenv("RAZVILKA_NETIDENTITY_MOUNT_ID_CHILD") != "1" {
		command := exec.CommandContext(ctx, "unshare", "--mount", "--fork", os.Args[0], "-test.run=^TestProcMountIDNativeClosingRejectsSameInodeBind$", "-test.v")
		command.Env = append(os.Environ(), "RAZVILKA_NETIDENTITY_MOUNT_ID_CHILD=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("disposable proc mount fixture: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	provider := NewProcProvider()
	var original Identity
	if err := provider.WithCurrent(ctx, func(_ context.Context, id Identity) error { original = id; return nil }); err != nil {
		t.Fatal("opening provider", err)
	}
	a := mountIDAuditFixture(t, ctx)
	rootID, ok := a.mountID(a.root.fd)
	if !ok {
		t.Fatal("original mount ID")
	}
	var stat unix.Statx_t
	if err := unix.Statx(a.root.fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat); err != nil || stat.Mask&unix.STATX_MNT_ID == 0 {
		t.Fatal("native statx unavailable", err)
	}
	target := "/proc/" + strconv.Itoa(os.Getpid()) + "/fdinfo"
	mounted := false
	defer func() {
		if mounted {
			_ = unix.Unmount(target, 0)
		}
	}()
	entered := false
	err := provider.WithCurrent(ctx, func(_ context.Context, id Identity) error {
		if id != original {
			t.Fatal("opening identity changed")
		}
		if err := unix.Mount(target, target, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		mounted = true
		entered = true
		fd, err := syscall.Open(target, dirFlags, 0)
		if err != nil {
			return err
		}
		defer syscall.Close(fd)
		var before, after syscall.Stat_t
		if syscall.Fstat(a.fdinfo, &before) != nil || syscall.Fstat(fd, &after) != nil || before.Ino != after.Ino || before.Dev != after.Dev {
			t.Fatal("bind changed inode")
		}
		bound, ok := a.mountID(fd)
		old, oldOK := a.mountIDFromFDInfo(fd)
		if !ok || !oldOK || bound == rootID || bound != old {
			t.Fatal("same-inode bind mount lost identity", bound, rootID, old)
		}
		if got, ok := a.mountIDAfterStatx(fd, unix.Statx_t{}, unix.ENOSYS); !ok || got != bound {
			t.Fatal("legacy fallback missed bind")
		}
		return nil
	})
	if !entered || err == nil {
		t.Fatal("closing provider adopted late bind mount", entered, err)
	}
	if err := unix.Unmount(target, 0); err != nil {
		t.Fatal(err)
	}
	mounted = false
	if err := provider.WithCurrent(ctx, func(_ context.Context, id Identity) error {
		if id != original {
			t.Fatal("restored identity drift")
		}
		return nil
	}); err != nil {
		t.Fatal("fresh provider after actual unmount", err)
	}
	if !a.stable() || !a.mountsMatch(rootID) {
		t.Fatal("held original audit changed")
	}
}
