//go:build linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestXraySelectedTCPMountIDActualParityAndFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proc, err := openXraySelectedTCPProc(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer proc.close()
	for _, fd := range []int{proc.root, proc.child, proc.fdinfo} {
		want, err := proc.mountIDFromFDInfo(ctx, fd)
		if err != nil || want == 0 {
			t.Fatal("original fdinfo", want, err)
		}
		got, err := proc.mountID(ctx, fd)
		if err != nil || got != want {
			t.Fatal("same held FD mount identity changed", got, want, err)
		}
		for _, unsupported := range []error{unix.ENOSYS, unix.EOPNOTSUPP, unix.EINVAL, unix.EPERM, unix.EACCES} {
			got, err := proc.mountIDAfterStatx(ctx, fd, unix.Statx_t{}, unsupported)
			if err != nil || got != want {
				t.Fatal("compatibility path changed", unsupported, got, want, err)
			}
		}
		// A dummy field with no supporting mask is never a valid mount proof.
		got, err = proc.mountIDAfterStatx(ctx, fd, unix.Statx_t{Mnt_id: want + 1}, nil)
		if err != nil || got != want {
			t.Fatal("missing mask used dummy field", got, want, err)
		}
	}
	if err := proc.current(ctx); err != nil {
		t.Fatal("original proc owner bookends", err)
	}
	original := proc.fdinfo
	proc.fdinfo = -1
	if got, err := proc.mountIDAfterStatx(ctx, proc.root, unix.Statx_t{}, unix.ENOSYS); err == nil || got != 0 {
		t.Fatal("failed original fallback became success", got, err)
	}
	proc.fdinfo = original
}

func TestXraySelectedTCPMountIDRefusesMalformedErrorsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	proc := &xraySelectedTCPProc{fdinfo: -1}
	for _, cause := range []error{unix.EBADF, unix.EIO, unix.EFAULT, unix.ENOENT} {
		got, err := proc.mountIDAfterStatx(ctx, 3, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: 99}, cause)
		if got != 0 || !errors.Is(err, cause) {
			t.Fatal("syscall failure fell back or became identity", cause, got, err)
		}
	}
	if got, err := proc.mountIDAfterStatx(ctx, 3, unix.Statx_t{Mask: unix.STATX_MNT_ID}, nil); got != 0 || err == nil {
		t.Fatal("zero identity accepted", got, err)
	}
	const wide = uint64(1)<<40 | 73
	if got, err := proc.mountIDAfterStatx(ctx, 3, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: wide}, nil); got != wide || err != nil {
		t.Fatal("mount ID truncated", got, err)
	}
	if got, err := proc.mountID(ctx, -1); got != 0 || err == nil {
		t.Fatal("invalid descriptor observed", got, err)
	}
	closed, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(closed); err != nil {
		t.Fatal(err)
	}
	if got, err := proc.mountID(ctx, closed); got != 0 || err == nil {
		t.Fatal("closed descriptor supplied identity", got, err)
	}
	cancel()
	if got, err := proc.mountID(ctx, 3); got != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancel before syscall lost", got, err)
	}
	if got, err := proc.mountIDAfterStatx(ctx, 3, unix.Statx_t{Mask: unix.STATX_MNT_ID, Mnt_id: wide}, nil); got != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancel after syscall lost", got, err)
	}
}

func TestXraySelectedTCPMountIDBindBoundary(t *testing.T) {
	if os.Getenv("RAZVILKA_DOMAIN_MOUNT_ID_NATIVE") != "1" {
		t.Skip("opt-in disposable mount namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if os.Getenv("RAZVILKA_DOMAIN_MOUNT_ID_CHILD") != "1" {
		command := exec.CommandContext(ctx, "unshare", "--mount", "--fork", os.Args[0], "-test.run=^TestXraySelectedTCPMountIDBindBoundary$", "-test.v")
		command.Env = append(os.Environ(), "RAZVILKA_DOMAIN_MOUNT_ID_CHILD=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("disposable mount fixture: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	proc, err := openXraySelectedTCPProc(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer proc.close()
	target := t.TempDir()
	if err := unix.Mount("/proc", target, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(target, 0)
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	// The inode and procfs filesystem are identical, but this is another mount.
	var boundInfo unix.Stat_t
	if err := unix.Fstat(fd, &boundInfo); err != nil || boundInfo.Ino != proc.rootStat.Ino || boundInfo.Dev != proc.rootStat.Dev {
		t.Fatal("bind fixture changed inode", err)
	}
	if !proc.procFile(fd, unix.S_IFDIR) {
		t.Fatal("fixture changed filesystem instead of mount")
	}
	var stat unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat); err != nil || stat.Mask&unix.STATX_MNT_ID == 0 {
		t.Fatal("native statx mount ID unavailable", err)
	}
	old, err := proc.mountIDFromFDInfo(ctx, fd)
	if err != nil || old == proc.mount || old != stat.Mnt_id {
		t.Fatal("bind mount parity", old, proc.mount, stat.Mnt_id, err)
	}
	if proc.sameMount(ctx, fd) {
		t.Fatal("bind mount with identical inode adopted")
	}
	if got, err := proc.mountIDAfterStatx(ctx, fd, unix.Statx_t{}, unix.ENOSYS); err != nil || got != old {
		t.Fatal("forced fallback missed bind mount", got, old, err)
	}
	// Reuse the same descriptor number for the different mount: a cached ID
	// would incorrectly preserve the first success despite the actual change.
	probe, err := unix.Dup(proc.root)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(probe)
	if !proc.sameMount(ctx, probe) {
		t.Fatal("original duplicate refused")
	}
	if err := unix.Dup3(fd, probe, unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if proc.sameMount(ctx, probe) {
		t.Fatal("descriptor number reused stale mount identity")
	}
	if got, err := proc.mountIDAfterStatx(ctx, probe, unix.Statx_t{}, unix.ENOSYS); err != nil || got != old {
		t.Fatal("fallback reused stale descriptor identity", got, old, err)
	}
	if err := proc.current(ctx); err != nil {
		t.Fatal("unrelated bind disturbed original held owner", err)
	}
}
